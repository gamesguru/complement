//go:build !dendrite_blacklist && !venator_blacklist

package msc4521

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wombat-Foundation/gomatrixcrypto/reconcile"
	"github.com/tidwall/gjson"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/must"
)

// Limits the homeserver initiator is expected to enforce. They are parameters
// of the implementation under test, not protocol constants; adjust them to the
// configured limits of the build being tested.
const (
	maxFetchesPerRound = 100              // upper bound on /event fetches in one exchange with one peer
	sampleFetchBound   = 40               // upper bound on fetches before a partly fake claim is abandoned
	settle             = 20 * time.Second // upper bound on any wait for the homeserver
	noActivityGrace    = 3 * time.Second  // give up early if the homeserver sends nothing at all
	quietPeriod        = 2 * time.Second  // activity counts as finished after this much silence
	// roundQuiet ends a wait whose bound is per exchange. Fetches within one
	// exchange arrive milliseconds apart, so this much silence means the
	// exchange is over; it does not wait for any retry.
	roundQuiet = 500 * time.Millisecond
	// laterRoundWait bounds the wait for another exchange to start after a
	// trigger. Exceeding it weakens a check but is not a failure: whether and
	// when the homeserver starts another exchange is its own policy.
	laterRoundWait = 5 * time.Second
)

const msc4521Prefix = "/_matrix/federation/unstable/tk.nutra.msc0501/"

// scriptedPeer is a federation server that joins a room and answers the
// reconciliation endpoints however a test tells it to, recording every
// request it receives.
type scriptedPeer struct {
	// anchors are the homeserver's own frame event IDs. The peer reports them as
	// its frame so the homeserver compares sets instead of falling back to an
	// extremity transfer.
	anchors   []string
	srv       *federation.Server
	room      *federation.ServerRoom
	userID    string
	advertise bool // false: room_digest/room_diff answer 404
	frameID   string

	mu      sync.Mutex
	reqs    []string
	claimed []string // event IDs the peer claims to hold (digest)
	offered []string // full IDs returned as missing from the requester
}

func (p *scriptedPeer) count(substr string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, r := range p.reqs {
		if strings.Contains(r, substr) {
			n++
		}
	}
	return n
}

func (p *scriptedPeer) claim(claimed, offered []string) {
	p.mu.Lock()
	p.claimed, p.offered = claimed, offered
	p.mu.Unlock()
}

// encodeStrata is the wire form of a kernel's strata: one unpadded base64url
// string per stratum, each the stratum's coordinates as little-endian u64s.
func encodeStrata(strata *[reconcile.StrataCount][reconcile.StratumCapacity]uint64) []string {
	out := make([]string, 0, len(strata))
	for _, stratum := range strata {
		raw := make([]byte, 0, len(stratum)*8)
		for _, coordinate := range stratum {
			raw = binary.LittleEndian.AppendUint64(raw, coordinate)
		}
		out = append(out, base64.RawURLEncoding.EncodeToString(raw))
	}
	return out
}

// declineReconciliation makes a mock federation server answer room_digest the
// way a homeserver without MSC4521 does. The homeserver under test now starts
// reconciliations itself, so a mock that says nothing about the endpoint would
// have every such request counted as an unexpected one and fail its test.
func declineReconciliation(srv *federation.Server) {
	decline := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errcode":"M_UNRECOGNIZED","error":"Unrecognized request"}`))
	}
	srv.Mux().HandleFunc(msc4521Prefix+"room_digest/{roomID}", decline).Methods("GET")
	srv.Mux().HandleFunc(msc4521Prefix+"room_digest/{roomID}/strata", decline).Methods("GET")
}

// declineEventRelationships answers the /event_relationships fallback that a
// homeserver tries on every joined server once get_missing_events came back
// empty, as it does for a prober that holds no history.
func declineEventRelationships(srv *federation.Server) {
	srv.Mux().HandleFunc("/_matrix/federation/unstable/event_relationships", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errcode":"M_UNRECOGNIZED","error":"Unrecognized request"}`))
	}).Methods("POST")
}

func (p *scriptedPeer) digestJSON(withStrata bool) map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	k := reconcile.NewResidentKernel()
	for _, id := range p.claimed {
		if h, err := reconcile.FromMatrixEventID(id, reconcile.V4Plus); err == nil {
			_ = k.Insert(h)
		}
	}
	out := map[string]interface{}{
		"digest_type": "algebraic_v1.0.0", "digest": k.Accumulator().EncodeDigest(),
		"frame_id": p.frameID, "known_event_count": k.Accumulator().Count,
		"frame_event_ids": p.anchors, "extremity_event_ids": p.anchors,
		"depth_range": []int{0, 0}, "origin_server_ts_range": []int{0, 0},
	}
	if withStrata {
		out["strata"] = encodeStrata(k.Strata())
	}
	return out
}

// newPeer creates a scripted federation server and joins it to roomID via hs1.
func newPeer(t *testing.T, deployment complement.Deployment, roomID string, join, advertise bool) *scriptedPeer {
	t.Helper()
	p := &scriptedPeer{advertise: advertise}
	p.srv = federation.NewServer(t, deployment,
		federation.HandleKeyRequests(),
		federation.HandleTransactionRequests(nil, nil),
		federation.HandleEventRequests(),
	)
	m := p.srv.Mux()
	m.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.mu.Lock()
			p.reqs = append(p.reqs, r.Method+" "+r.URL.Path)
			p.mu.Unlock()
			next.ServeHTTP(w, r)
		})
	})
	reply := func(w http.ResponseWriter, code int, v interface{}) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	m.HandleFunc("/_matrix/federation/v1/version", func(w http.ResponseWriter, _ *http.Request) {
		features := map[string]bool{}
		if p.advertise {
			features["tk.nutra.msc4521.digest.algebraic_v1.0.0"] = true
			features["tk.nutra.msc4521.binding.event_id_v1"] = true
			features["tk.nutra.msc0501.strata"] = true
			features["tk.nutra.msc0501.reconciliation"] = true
		}
		reply(w, http.StatusOK, map[string]interface{}{
			"server":            map[string]string{"name": "complement", "version": "mock"},
			"unstable_features": features,
		})
	}).Methods("GET")
	m.HandleFunc(msc4521Prefix+"room_digest/{roomID}", func(w http.ResponseWriter, r *http.Request) {
		if !p.advertise {
			reply(w, 404, map[string]string{"errcode": "M_UNRECOGNIZED"})
			return
		}
		reply(w, 200, p.digestJSON(false))
	}).Methods("GET")
	m.HandleFunc(msc4521Prefix+"room_digest/{roomID}/strata", func(w http.ResponseWriter, r *http.Request) {
		if !p.advertise {
			reply(w, 404, map[string]string{"errcode": "M_UNRECOGNIZED"})
			return
		}
		reply(w, 200, p.digestJSON(true))
	}).Methods("GET")
	m.HandleFunc(msc4521Prefix+"room_diff/{roomID}", func(w http.ResponseWriter, r *http.Request) {
		if !p.advertise {
			reply(w, 404, map[string]string{"errcode": "M_UNRECOGNIZED"})
			return
		}
		p.mu.Lock()
		offered := append([]string{}, p.offered...)
		p.mu.Unlock()
		d := p.digestJSON(false)
		reply(w, 200, map[string]interface{}{
			"digest_type": "algebraic_v1.0.0", "frame_id": p.frameID,
			"missing_event_ids": offered, "requester_only_short_ids": []string{},
			"expected_requester_side_accumulator": "AAAAAAAAAAAAAAAAAAAAAA",
			"remote_known_event_count":            d["known_event_count"],
			"remote_extremity_event_ids":          p.anchors,
			"frame_status":                        "not_requested",
			"scope":                               "event_set",
			"sketch_status":                       "decoded",
			"truncated":                           false,
		})
	}).Methods("POST")
	t.Cleanup(p.srv.Listen())
	p.userID = p.srv.UserID("peer")
	if join {
		p.room = p.srv.MustJoinRoom(t, deployment, deployment.GetFullyQualifiedHomeserverName(t, "hs1"), roomID, p.userID)
	}
	return p
}

// requireSupported fails the test when the homeserver under test does not serve
// room_digest. Congruent serves it and Complement enables it, so a missing
// endpoint is a regression, not a reason to skip.
func requireSupported(t *testing.T, digestStatus int) {
	t.Helper()
	if digestStatus == http.StatusNotFound || digestStatus == http.StatusNotImplemented {
		t.Fatalf("homeserver under test does not serve MSC4521 room_digest (status %d)", digestStatus)
	}
}

// settleOn waits for the homeserver's activity, measured by count, to start
// and then go quiet. It returns after quiet without change once there has
// been activity, after noActivityGrace if there never is, or after settle at
// the latest, so a homeserver that does nothing fails in seconds instead of
// sleeping out the whole bound.
func settleOn(count func() int, quiet time.Duration) {
	start := time.Now()
	last, changed := count(), time.Now()
	for time.Since(start) < settle {
		time.Sleep(250 * time.Millisecond)
		if n := count(); n != last {
			last, changed = n, time.Now()
		}
		if last == 0 && time.Since(start) >= noActivityGrace {
			return
		}
		if last > 0 && time.Since(changed) >= quiet {
			return
		}
	}
}

// waitFor polls cond until it holds or timeout passes, and reports which.
func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// rounds counts the exchanges the homeserver has started with this peer: each
// begins with a room_digest/strata request (see exchange in the reconcile
// service), which is also what separates it from a prober's plain digest read.
func (p *scriptedPeer) rounds() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, r := range p.reqs {
		if strings.HasSuffix(r, "/strata") {
			n++
		}
	}
	return n
}

func fakeEventID(n int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("fabricated-%d", n)))
	return "$" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func fakeIDs(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fakeEventID(i)
	}
	return ids
}

func timelineIDs(p *scriptedPeer) []string {
	p.room.TimelineMutex.RLock()
	defer p.room.TimelineMutex.RUnlock()
	var ids []string
	for _, ev := range p.room.Timeline {
		ids = append(ids, ev.EventID())
	}
	return ids
}

type adversaryEnv struct {
	deployment complement.Deployment
	alice      *client.CSAPI
	roomID     string
	peer       *scriptedPeer
}

func newAdversaryEnv(t *testing.T, join, advertise bool) *adversaryEnv {
	t.Helper()
	deployment := complement.Deploy(t, 1)
	t.Cleanup(func() { deployment.Destroy(t) })
	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	roomID := alice.MustCreateRoom(t, map[string]interface{}{"preset": "public_chat"})
	peer := newPeer(t, deployment, roomID, join, advertise)
	if join {
		body, status := getRoomDigest(t, peer.srv, deployment, roomID, "")
		requireSupported(t, status)
		must.Equal(t, status, 200, "hs1 digest status")
		peer.frameID = gjson.ParseBytes(body).Get("frame_id").Str
		peer.anchors = stringsOf(gjson.ParseBytes(body).Get("frame_event_ids"))
	}
	return &adversaryEnv{deployment, alice, roomID, peer}
}

func (e *adversaryEnv) hs1Digest(t *testing.T) (string, int64) {
	t.Helper()
	body, status := getRoomDigest(t, e.peer.srv, e.deployment, e.roomID, "")
	must.Equal(t, status, 200, "hs1 digest status")
	d := gjson.ParseBytes(body)
	return d.Get("digest").Str, d.Get("known_event_count").Int()
}

// triggerRoomActivity makes a claim change observable to the homeserver. A
// mock changing its digest in memory does not itself send a federation event.
func (e *adversaryEnv) triggerRoomActivity(t *testing.T) {
	t.Helper()
	e.alice.SendEventSynced(t, e.roomID, b.Event{
		Type:    "m.room.message",
		Content: map[string]interface{}{"msgtype": "m.text", "body": "trigger reconciliation"},
	})
}

// 1. A peer claims thousands of event IDs that do not exist.
func testFabricatedIDs(t *testing.T) {
	e := newAdversaryEnv(t, true, true)
	fakes := fakeIDs(5000)
	e.peer.claim(append(timelineIDs(e.peer), fakes...), fakes)
	e.triggerRoomActivity(t)
	digest, count := e.hs1Digest(t)

	settleOn(func() int { return e.peer.count("/federation/v1/event/") }, roundQuiet)

	fetches := e.peer.count("/federation/v1/event/")
	t.Logf("peer saw %d /event fetches for %d fabricated IDs", fetches, len(fakes))
	if fetches > maxFetchesPerRound {
		t.Errorf("homeserver fetched %d of %d fabricated IDs (limit %d)", fetches, len(fakes), maxFetchesPerRound)
	}
	d2, c2 := e.hs1Digest(t)
	must.Equal(t, d2, digest, "fabricated IDs must not change the homeserver's digest")
	must.Equal(t, c2, count, "fabricated IDs must not change the homeserver's event count")
}

// 2. A peer mixes real, servable events with fabricated ones. The homeserver
// should sample, find fakes, and abandon the round long before fetching all.
func testPartlyFakeClaimIsSampled(t *testing.T) {
	e := newAdversaryEnv(t, true, true)
	var real []string
	for i := 0; i < 100; i++ {
		ev := e.peer.srv.MustCreateEvent(t, e.peer.room, federation.Event{
			Type: "m.room.message", Sender: e.peer.userID,
			Content: map[string]interface{}{"msgtype": "m.text", "body": fmt.Sprintf("real %d", i)},
		})
		e.peer.room.AddEvent(ev)
		real = append(real, ev.EventID())
	}
	fakes := fakeIDs(100)
	offered := append(append([]string{}, real...), fakes...)
	e.peer.claim(append(timelineIDs(e.peer), fakes...), offered)
	e.triggerRoomActivity(t)

	settleOn(func() int { return e.peer.count("/federation/v1/event/") }, roundQuiet)

	fetches := e.peer.count("/federation/v1/event/")
	t.Logf("peer saw %d fetches for %d claimed IDs (50%% fake)", fetches, len(offered))
	if fetches > sampleFetchBound {
		t.Errorf("homeserver fetched %d of %d claimed IDs before abandoning the round (limit %d)", fetches, len(offered), sampleFetchBound)
	}
	// Lower bound, so a homeserver that never initiates cannot pass. The real
	// half cannot all be accepted: each is fetched individually and the round
	// is abandoned within sampleFetchBound fetches.
	if fetches == 0 {
		t.Fatal("homeserver never fetched any claimed event: it does not initiate reconciliation")
	}
}

// 3. Real, signed events that chain to the room's DAG are accepted.
func testValidChainingIsAccepted(t *testing.T) {
	e := newAdversaryEnv(t, true, true)
	var ids []string
	for i := 0; i < 5; i++ {
		ev := e.peer.srv.MustCreateEvent(t, e.peer.room, federation.Event{
			Type: "m.room.message", Sender: e.peer.userID,
			Content: map[string]interface{}{"msgtype": "m.text", "body": fmt.Sprintf("chained %d", i)},
		})
		e.peer.room.AddEvent(ev)
		ids = append(ids, ev.EventID())
	}
	e.peer.claim(timelineIDs(e.peer), ids)
	e.triggerRoomActivity(t)

	start := time.Now()
	deadline := start.Add(60 * time.Second)
	for {
		have := map[string]bool{}
		for _, id := range roomEventIDs(t, e.alice, e.roomID) {
			have[id] = true
		}
		missing := 0
		for _, id := range ids {
			if !have[id] {
				missing++
			}
		}
		if missing == 0 {
			return
		}
		if time.Since(start) >= noActivityGrace && e.peer.count("/federation/v1/event/") == 0 {
			t.Fatalf("homeserver never fetched any of the %d claimed events (%d missing): it does not initiate reconciliation", len(ids), missing)
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d valid chained events never reached the homeserver", missing, len(ids))
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// 4. An event the homeserver rejects is not fetched again every round.
func testRejectedEventNotRefetched(t *testing.T) {
	e := newAdversaryEnv(t, true, true)
	stateKey := ""
	// The peer's user has no power to rename the room: auth rejects this event.
	bad := e.peer.srv.MustCreateEvent(t, e.peer.room, federation.Event{
		Type: "m.room.name", StateKey: &stateKey, Sender: e.peer.userID,
		Content: map[string]interface{}{"name": "not allowed"},
	})
	e.peer.room.AddEvent(bad)
	e.peer.claim(timelineIDs(e.peer), []string{bad.EventID()})
	e.triggerRoomActivity(t)

	badPath := "/federation/v1/event/" + bad.EventID()
	// Positive: the offered event must be fetched, or rejection was not tested.
	if !waitFor(noActivityGrace, func() bool { return e.peer.count(badPath) >= 1 }) {
		t.Fatal("homeserver never fetched the offered event, so the test did not exercise rejection")
	}
	// Negative: a later exchange must have run to completion before silence
	// means anything. Exchanges with a peer never overlap, so the start of the
	// next one shows the previous one is over. Two triggers make the one that
	// could have refetched finish before the count is read.
	observed := true
	for i := 0; i < 2 && observed; i++ {
		want := e.peer.rounds() + 1
		e.triggerRoomActivity(t)
		observed = waitFor(laterRoundWait, func() bool { return e.peer.rounds() >= want })
	}
	if !observed {
		t.Logf("no later exchange started within %s of a trigger; the check below rests on silence alone", laterRoundWait)
	}

	n := e.peer.count(badPath)
	t.Logf("rejected event fetched %d time(s)", n)
	if n > 1 {
		t.Errorf("rejected event refetched %d times; it should be remembered", n)
	}
}

// 5. Servers that are not in the room, or are ACL-blocked, are neither
// queried nor answered.
func testNonMembersAndACLBlocked(t *testing.T) {
	e := newAdversaryEnv(t, true, true)
	stranger := newPeer(t, e.deployment, e.roomID, false, true)
	stranger.claim(fakeIDs(10), fakeIDs(10))
	blocked := e.peer
	blocked.claim(fakeIDs(10), fakeIDs(10))
	// ACL entries match the host only: an entry with a port matches nothing.
	blockedHost, _, err := net.SplitHostPort(string(blocked.srv.ServerName()))
	must.NotError(t, "split the blocked server's name", err)
	e.alice.SendEventSynced(t, e.roomID, b.Event{
		Type: "m.room.server_acl", StateKey: b.Ptr(""),
		Content: map[string]interface{}{
			"allow": []string{"*"},
			"deny":  []string{blockedHost},
		},
	})
	before := blocked.count("room_digest") + blocked.count("room_diff")

	settleOn(func() int {
		return blocked.count("room_digest") + blocked.count("room_diff") +
			stranger.count("room_digest") + stranger.count("room_diff")
	}, quietPeriod)

	for name, p := range map[string]*scriptedPeer{"stranger": stranger} {
		if n := p.count("room_digest") + p.count("room_diff"); n != 0 {
			t.Errorf("%s was sent %d reconciliation requests", name, n)
		}
	}
	if after := blocked.count("room_digest") + blocked.count("room_diff"); after != before {
		t.Errorf("ACL-blocked server was sent %d reconciliation requests after the ACL", after-before)
	}
	for name, p := range map[string]*scriptedPeer{"stranger": stranger, "blocked": blocked} {
		_, status := getRoomDigest(t, p.srv, e.deployment, e.roomID, "")
		if status == 200 {
			t.Errorf("%s was served room_digest", name)
		}
	}
}

// 6. A peer that does not serve the reconciliation endpoints is handled with
// ordinary federation fetches and is not hammered with retries.
func testNonAdvertisingPeerFallsBack(t *testing.T) {
	e := newAdversaryEnv(t, true, false)
	m := e.peer.srv.Mux()
	first := e.peer.srv.MustCreateEvent(t, e.peer.room, federation.Event{
		Type: "m.room.message", Sender: e.peer.userID, Content: map[string]interface{}{"msgtype": "m.text", "body": "gap"},
	})
	e.peer.room.AddEvent(first)
	m.HandleFunc("/_matrix/federation/v1/get_missing_events/{roomID}", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"events": []json.RawMessage{first.JSON()}})
	})
	m.HandleFunc("/_matrix/federation/v1/state_ids/{roomID}", func(w http.ResponseWriter, r *http.Request) {
		var ids []string
		for _, ev := range e.peer.room.AllCurrentState() {
			ids = append(ids, ev.EventID())
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"pdu_ids": ids, "auth_chain_ids": ids})
	})
	second := e.peer.srv.MustCreateEvent(t, e.peer.room, federation.Event{
		Type: "m.room.message", Sender: e.peer.userID, Content: map[string]interface{}{"msgtype": "m.text", "body": "after gap"},
	})
	e.peer.room.AddEvent(second)
	e.peer.srv.MustSendTransaction(t, e.deployment, e.deployment.GetFullyQualifiedHomeserverName(t, "hs1"),
		[]json.RawMessage{second.JSON()}, nil)

	settleOn(func() int {
		return e.peer.count("/get_missing_events/") + e.peer.count("/state_ids/") + e.peer.count("/federation/v1/event/")
	}, quietPeriod)

	ordinary := e.peer.count("/get_missing_events/") + e.peer.count("/state_ids/") + e.peer.count("/federation/v1/event/")
	if ordinary == 0 {
		t.Error("homeserver used no ordinary federation fetch to resolve the gap")
	}
	if n := e.peer.count("room_digest") + e.peer.count("room_diff"); n > 3 {
		t.Errorf("homeserver sent %d reconciliation requests to a peer that does not serve them", n)
	}
}
