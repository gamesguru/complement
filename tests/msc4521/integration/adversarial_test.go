//go:build !dendrite_blacklist && !venator_blacklist

package integration

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	maxFetchesPerRound = 100 // upper bound on /event fetches in one exchange with one peer
	sampleFetchBound   = 40  // upper bound on fetches before a partly fake claim is abandoned
	settle             = 20 * time.Second
)

const msc4521Prefix = "/_matrix/federation/unstable/tk.nutra.msc4521/"

// scriptedPeer is a federation server that joins a room and answers the
// reconciliation endpoints however a test tells it to, recording every
// request it receives.
type scriptedPeer struct {
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
		"digest_type": "algebraic_v1", "digest": k.Accumulator().EncodeDigest(),
		"frame_id": p.frameID, "known_event_count": k.Accumulator().Count,
		"frame_event_ids": []string{},
	}
	if withStrata {
		out["strata"] = make([]string, 32)
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
			"digest_type": "algebraic_v1", "frame_id": p.frameID, "digest": d["digest"],
			"missing_event_ids": offered, "requester_only_short_ids": []string{},
		})
	}).Methods("POST")
	t.Cleanup(p.srv.Listen())
	p.userID = p.srv.UserID("peer")
	if join {
		p.room = p.srv.MustJoinRoom(t, deployment, deployment.GetFullyQualifiedHomeserverName(t, "hs1"), roomID, p.userID)
	}
	return p
}

// skipIfUnsupported skips the test when the homeserver under test does not
// serve room_digest (feature off or not implemented). Feature detection, not a
// flag: the tests start running as soon as the endpoint exists.
func skipIfUnsupported(t *testing.T, digestStatus int) {
	t.Helper()
	if digestStatus == http.StatusNotFound || digestStatus == http.StatusNotImplemented {
		t.Skip("homeserver under test does not serve MSC4521 room_digest")
	}
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
		skipIfUnsupported(t, status)
		must.Equal(t, status, 200, "hs1 digest status")
		peer.frameID = gjson.ParseBytes(body).Get("frame_id").Str
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

// 1. A peer claims thousands of event IDs that do not exist.
func TestMSC4521FabricatedIDs(t *testing.T) {
	e := newAdversaryEnv(t, true, true)
	fakes := fakeIDs(5000)
	e.peer.claim(append(timelineIDs(e.peer), fakes...), fakes)
	digest, count := e.hs1Digest(t)

	time.Sleep(settle)

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
func TestMSC4521PartlyFakeClaimIsSampled(t *testing.T) {
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

	time.Sleep(settle)

	fetches := e.peer.count("/federation/v1/event/")
	t.Logf("peer saw %d fetches for %d claimed IDs (50%% fake)", fetches, len(offered))
	if fetches > sampleFetchBound {
		t.Errorf("homeserver fetched %d of %d claimed IDs before abandoning the round (limit %d)", fetches, len(offered), sampleFetchBound)
	}
	// Lower bound, so a homeserver that never initiates cannot pass: the honest
	// half must still be fetched and accepted.
	have := map[string]bool{}
	for _, id := range roomEventIDs(t, e.alice, e.roomID) {
		have[id] = true
	}
	for _, id := range real {
		if !have[id] {
			t.Fatalf("real event %s was never accepted from the partly fake claim", id)
		}
	}
}

// 3. Real, signed events that chain to the room's DAG are accepted.
func TestMSC4521ValidChainingIsAccepted(t *testing.T) {
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

	deadline := time.Now().Add(60 * time.Second)
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
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d valid chained events never reached the homeserver", missing, len(ids))
		}
		time.Sleep(time.Second)
	}
}

// 4. An event the homeserver rejects is not fetched again every round.
func TestMSC4521RejectedEventNotRefetched(t *testing.T) {
	e := newAdversaryEnv(t, true, true)
	stateKey := ""
	// The peer's user has no power to rename the room: auth rejects this event.
	bad := e.peer.srv.MustCreateEvent(t, e.peer.room, federation.Event{
		Type: "m.room.name", StateKey: &stateKey, Sender: e.peer.userID,
		Content: map[string]interface{}{"name": "not allowed"},
	})
	e.peer.room.AddEvent(bad)
	e.peer.claim(timelineIDs(e.peer), []string{bad.EventID()})

	time.Sleep(settle)

	n := e.peer.count("/federation/v1/event/" + bad.EventID())
	t.Logf("rejected event fetched %d time(s) over %s", n, settle)
	if n == 0 {
		t.Fatal("homeserver never fetched the offered event, so the test did not exercise rejection")
	}
	if n > 1 {
		t.Errorf("rejected event refetched %d times; it should be remembered", n)
	}
}

// 5. Servers that are not in the room, or are ACL-blocked, are neither
// queried nor answered.
func TestMSC4521NonMembersAndACLBlocked(t *testing.T) {
	e := newAdversaryEnv(t, true, true)
	stranger := newPeer(t, e.deployment, e.roomID, false, true)
	stranger.claim(fakeIDs(10), fakeIDs(10))
	blocked := e.peer
	blocked.claim(fakeIDs(10), fakeIDs(10))
	e.alice.SendEventSynced(t, e.roomID, b.Event{
		Type: "m.room.server_acl", StateKey: b.Ptr(""),
		Content: map[string]interface{}{
			"allow": []string{"*"},
			"deny":  []string{string(blocked.srv.ServerName())},
		},
	})
	before := blocked.count("room_digest") + blocked.count("room_diff")

	time.Sleep(settle)

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
func TestMSC4521NonAdvertisingPeerFallsBack(t *testing.T) {
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

	time.Sleep(settle)

	ordinary := e.peer.count("/get_missing_events/") + e.peer.count("/state_ids/") + e.peer.count("/federation/v1/event/")
	if ordinary == 0 {
		t.Error("homeserver used no ordinary federation fetch to resolve the gap")
	}
	if n := e.peer.count("room_digest") + e.peer.count("room_diff"); n > 3 {
		t.Errorf("homeserver sent %d reconciliation requests to a peer that does not serve them", n)
	}
}
