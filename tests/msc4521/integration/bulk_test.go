//go:build !dendrite_blacklist && !venator_blacklist

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wombat-Foundation/gomatrixcrypto/reconcile"
	"github.com/matrix-org/gomatrixserverlib/fclient"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/gjson"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/federation/linkproxy"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/must"
)

// numGossipers is both the number of deployed homeservers and the number of
// scripted origin servers. Each homeserver i is the ONLY server that receives
// origin i's seeded events directly.
const numGossipers = 16

// seededPerOrigin is how many events each scripted origin sends to its one
// homeserver.
const seededPerOrigin = 10

// testBulkReconciliation checks that 16 real homeservers converge on an
// exact event set that was seeded sparsely, with no way to converge except by
// exchanging events with each other.
//
// Why no hold/release proxy is needed to get sparse sets: a Matrix homeserver
// only pushes events it originates. Events that origin i signs and sends to
// homeserver i alone are therefore never relayed, and nobody asks for them
// because every seeded event hangs off the common tip (no missing ancestors)
// and no homeserver sends anything after seeding. So at the start homeserver i
// alone holds origin i's events: 16 disjoint sparse subsets.
//
// Why convergence proves homeserver-to-homeserver exchange: the origins serve
// nothing (every request they receive is recorded and answered 404), so the
// seeded events can only come from another homeserver. A /state_ids or
// /get_missing_events request reaching an origin is a failure.
//
// Not observable: which homeserver talked to which, and in how many rounds.
// Complement sees only traffic addressed to its own servers. The test records
// when each homeserver converges, as a coarse spread profile, but asserts only
// the final exact state, never timing.
//
// Opt-in: needs an MSC4521-capable image that initiates exchanges itself.
func testBulkReconciliation(t *testing.T) {
	if os.Getenv("COMPLEMENT_MSC4521_BULK") == "" {
		t.Skip("set COMPLEMENT_MSC4521_BULK=1 with an MSC4521-capable image that initiates reconciliation")
	}
	e := newBulkEnv(t)
	e.joinHomeservers(t)
	e.joinOrigins(t)
	e.waitForBaseSet(t)
	e.restrictToHypercube()

	t.Run("DigestAndStrata", e.testDigestAndStrata)
	e.seed(t)
	t.Run("SparseStart", e.testSparseStart)
	t.Run("Converges", e.testConverges)
	t.Run("ExactEventSet", e.testExactEventSet)
	t.Run("NoFallbackToOrigins", e.testNoFallbackToOrigins)
	t.Run("ExchangesOnlyOverHypercubeEdges", e.testHypercubeEdges)
}

// isHypercubeEdge reports whether homeservers i and j are adjacent in the
// 4-dimensional hypercube: their indices differ in exactly one bit.
func isHypercubeEdge(i, j int) bool {
	x := i ^ j
	return x != 0 && x&(x-1) == 0
}

// restrictToHypercube blocks every link between non-adjacent homeservers, so
// the only way for events to spread is hop by hop along hypercube edges.
// Blocked links fail fast with 503 and are logged, so violations are visible.
func (e *bulkEnv) restrictToHypercube() {
	for i := 0; i < numGossipers; i++ {
		for j := 0; j < numGossipers; j++ {
			if i != j && !isHypercubeEdge(i, j) {
				e.proxy.Set(hsName(i), hsName(j), linkproxy.Block)
			}
		}
	}
}

// testHypercubeEdges asserts reconciliation traffic only succeeded between
// adjacent homeservers, and logs how many exchanges each edge carried. This is
// the observable spread profile: the Complement-visible record of who talked
// to whom.
func (e *bulkEnv) testHypercubeEdges(t *testing.T) {
	perEdge := map[string]int{}
	for _, en := range e.proxy.Log() {
		if !strings.Contains(en.Path, "room_diff") && !strings.Contains(en.Path, "room_digest") {
			continue
		}
		var i, j int
		if _, err := fmt.Sscanf(en.Src+" "+en.Dst, "hs%d hs%d", &i, &j); err != nil {
			continue
		}
		if en.Status == http.StatusOK && !isHypercubeEdge(i-1, j-1) {
			t.Errorf("reconciliation succeeded over a non-edge: %s -> %s %s", en.Src, en.Dst, en.Path)
		}
		if en.Status == http.StatusOK {
			perEdge[en.Src+"->"+en.Dst]++
		}
	}
	for edge, n := range perEdge {
		t.Logf("%s carried %d reconciliation requests", edge, n)
	}
	if len(perEdge) == 0 {
		t.Error("no reconciliation request crossed any link: the homeservers did not initiate exchanges")
	}
}

type bulkOrigin struct {
	srv  *federation.Server
	room *federation.ServerRoom
	user string
}

// bulkEnv holds the state shared by the bulk test's phases.
type bulkEnv struct {
	deployment complement.Deployment
	prober     *federation.Server
	proxy      *linkproxy.Proxy
	hs1        spec.ServerName
	users      []*client.CSAPI
	roomID     string
	origins    []bulkOrigin

	mu             sync.Mutex
	originRequests []string

	baseIDs     []string
	baseDigest  string
	expected    reconcile.ResidentKernel
	expectedIDs []string
	shortToID   map[uint64]string
	wantDigest  string
	wantCount   int64
}

func hsName(i int) string { return fmt.Sprintf("hs%d", i+1) }

func newBulkEnv(t *testing.T) *bulkEnv {
	t.Helper()
	deployment := complement.Deploy(t, numGossipers)
	t.Cleanup(func() { deployment.Destroy(t) })
	// Prober: a scripted server that only queries digests/room_diff.
	prober := federation.NewServer(t, deployment, federation.HandleKeyRequests())
	t.Cleanup(prober.Listen())
	names := make([]string, numGossipers)
	for i := range names {
		names[i] = hsName(i)
	}
	proxy := linkproxy.New(t, deployment, names...)
	t.Cleanup(proxy.Close)
	return &bulkEnv{
		deployment: deployment,
		prober:     prober,
		proxy:      proxy,
		hs1:        deployment.GetFullyQualifiedHomeserverName(t, "hs1"),
	}
}

// joinHomeservers has all homeservers join one room and each originate a real event.
func (e *bulkEnv) joinHomeservers(t *testing.T) {
	t.Helper()
	e.users = make([]*client.CSAPI, numGossipers)
	for i := range e.users {
		e.users[i] = e.deployment.Register(t, hsName(i), helpers.RegistrationOpts{})
	}
	e.roomID = e.users[0].MustCreateRoom(t, map[string]interface{}{"preset": "public_chat"})
	for i := 1; i < numGossipers; i++ {
		e.users[i].MustJoinRoom(t, e.roomID, []spec.ServerName{e.hs1})
	}
	for i := range e.users {
		e.users[i].SendEventSynced(t, e.roomID, b.Event{Type: "m.room.message", Content: map[string]interface{}{"msgtype": "m.text", "body": "base from " + hsName(i)}})
	}
}

// joinOrigins creates the scripted origins, each a distinct server name and
// signing identity, that answer 404 to everything and record it.
func (e *bulkEnv) joinOrigins(t *testing.T) {
	t.Helper()
	e.origins = make([]bulkOrigin, numGossipers)
	for i := range e.origins {
		i := i
		srv := federation.NewServer(t, e.deployment,
			federation.HandleKeyRequests(),
			federation.HandleTransactionRequests(nil, nil),
		)
		srv.Mux().NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			e.mu.Lock()
			e.originRequests = append(e.originRequests, fmt.Sprintf("origin%d %s %s", i, r.Method, r.URL.Path))
			e.mu.Unlock()
			w.WriteHeader(http.StatusNotFound)
		})
		t.Cleanup(srv.Listen())
		user := srv.UserID("origin")
		e.origins[i] = bulkOrigin{srv: srv, user: user, room: srv.MustJoinRoom(t, e.deployment, e.hs1, e.roomID, user)}
	}
}

func (e *bulkEnv) digestOf(t *testing.T, hs string) gjson.Result {
	t.Helper()
	body, status := getRoomDigestFrom(t, e.prober, e.deployment, hs, e.roomID, "")
	must.Equal(t, status, 200, hs+" room digest status")
	return gjson.ParseBytes(body)
}

// waitAll polls every homeserver until want holds for all of them.
func (e *bulkEnv) waitAll(t *testing.T, want func(gjson.Result) bool, what string, onFirst func(int)) {
	t.Helper()
	start := time.Now()
	done := make([]bool, numGossipers)
	for {
		n := 0
		for i := 0; i < numGossipers; i++ {
			if !done[i] && want(e.digestOf(t, hsName(i))) {
				done[i] = true
				if onFirst != nil {
					onFirst(i)
				}
			}
			if done[i] {
				n++
			}
		}
		if n == numGossipers {
			return
		}
		if time.Since(start) > 120*time.Second {
			t.Fatalf("timed out waiting for %s: %d/%d homeservers ready", what, n, numGossipers)
		}
		time.Sleep(time.Second)
	}
}

// waitForBaseSet lets every homeserver agree on the base set (all joins, base
// messages) and captures it exactly.
func (e *bulkEnv) waitForBaseSet(t *testing.T) {
	t.Helper()
	e.baseIDs = roomEventIDs(t, e.users[0], e.roomID)
	base := reconcile.NewResidentKernel()
	for _, id := range e.baseIDs {
		h, err := reconcile.FromMatrixEventID(id, reconcile.V4Plus)
		must.NotError(t, "hash base event", err)
		must.NotError(t, "insert base event", base.Insert(h))
	}
	e.baseDigest = base.Accumulator().EncodeDigest()
	e.waitAll(t, func(d gjson.Result) bool {
		return d.Get("digest").Str == e.baseDigest && d.Get("known_event_count").Int() == int64(len(e.baseIDs))
	}, "base set", nil)
}

// seed sends origin i's events to homeserver i only. Every event hangs off the
// common tip, so no homeserver is missing an ancestor.
func (e *bulkEnv) seed(t *testing.T) {
	t.Helper()
	tip := e.baseIDs[0]
	if latest := roomLatestEventID(t, e.users[0], e.roomID); latest != "" {
		tip = latest
	}
	e.expected = reconcile.NewResidentKernel()
	e.expectedIDs = nil
	e.shortToID = map[uint64]string{}
	for _, id := range e.baseIDs {
		e.record(t, id)
	}
	for i, o := range e.origins {
		dest := e.deployment.GetFullyQualifiedHomeserverName(t, hsName(i))
		for j := 0; j < seededPerOrigin; j++ {
			ev := o.srv.MustCreateEvent(t, o.room, federation.Event{
				Type:       "m.room.message",
				Sender:     o.user,
				Content:    map[string]interface{}{"body": fmt.Sprintf("seed %d/%d", i, j)},
				PrevEvents: []string{tip},
			})
			o.room.AddEvent(ev)
			e.record(t, ev.EventID())
			o.srv.MustSendTransaction(t, e.deployment, dest, []json.RawMessage{ev.JSON()}, nil)
		}
	}
	e.wantDigest = e.expected.Accumulator().EncodeDigest()
	e.wantCount = int64(len(e.expectedIDs))
	t.Logf("seeded %d events across %d origins; expecting %d total events (%d u64 short IDs)", numGossipers*seededPerOrigin, numGossipers, e.wantCount, len(e.shortToID))
}

// record adds an event ID to the expected set, failing on a u64 collision.
func (e *bulkEnv) record(t *testing.T, eventID string) {
	t.Helper()
	h, err := reconcile.FromMatrixEventID(eventID, reconcile.V4Plus)
	must.NotError(t, "hash event", err)
	must.NotError(t, "insert event", e.expected.Insert(h))
	if prev, dup := e.shortToID[h.H64]; dup {
		t.Fatalf("u64 collision in test data: %s vs %s", prev, eventID)
	}
	e.shortToID[h.H64] = eventID
	e.expectedIDs = append(e.expectedIDs, eventID)
}

func (e *bulkEnv) testDigestAndStrata(t *testing.T) {
	d := e.digestOf(t, "hs1")
	must.Equal(t, d.Get("digest_type").Str, "algebraic_v1", "digest type")
	body, status := getRoomDigestFrom(t, e.prober, e.deployment, "hs1", e.roomID, "/strata")
	must.Equal(t, status, 200, "strata status")
	must.Equal(t, len(gjson.ParseBytes(body).Get("strata").Array()), 32, "strata count")
}

// testSparseStart checks no homeserver already holds more than the expected set.
// It is a weak check: it cannot prove the start was sparse once reconciliation
// may already be running.
func (e *bulkEnv) testSparseStart(t *testing.T) {
	for i := 0; i < numGossipers; i++ {
		got := e.digestOf(t, hsName(i)).Get("known_event_count").Int()
		if got > e.wantCount {
			t.Errorf("%s holds more events (%d) than the expected set (%d)", hsName(i), got, e.wantCount)
		}
	}
}

func (e *bulkEnv) testConverges(t *testing.T) {
	start := time.Now()
	e.waitAll(t, func(d gjson.Result) bool {
		return d.Get("digest").Str == e.wantDigest && d.Get("known_event_count").Int() == e.wantCount
	}, "exact expected set", func(i int) {
		t.Logf("%s reached the exact expected set after %s", hsName(i), time.Since(start).Round(time.Millisecond))
	})
}

// testExactEventSet goes beyond equal digests: a zero-difference room_diff
// against each homeserver must find nothing missing in either direction.
func (e *bulkEnv) testExactEventSet(t *testing.T) {
	sketch, err := reconcile.NewSyndromeSketch(2)
	must.NotError(t, "new sketch", err)
	for h64 := range e.shortToID {
		must.NotError(t, "toggle", sketch.Toggle(h64))
	}
	for i := 0; i < numGossipers; i++ {
		d := e.digestOf(t, hsName(i))
		req, err := json.Marshal(map[string]interface{}{
			"mode": "sketch", "frame_id": d.Get("frame_id").Str,
			"local_digest": e.wantDigest, "digest_type": "algebraic_v1",
			"local_known_event_count": e.expected.Accumulator().Count,
			"frame_event_ids":         d.Get("frame_event_ids").Value(), "estimated_delta": 0,
			"requests":       []map[string]interface{}{{"depth": 0, "prefix": 0, "capacity": 2}},
			"local_sketches": []string{sketch.Encode()}, "limit": 100,
		})
		must.NotError(t, "encode room_diff", err)
		resp := postRoomDiff(t, e.prober, e.deployment, hsName(i), e.roomID, req)
		must.Equal(t, len(resp.Get("missing_event_ids").Array()), 0, hsName(i)+" is missing no expected event")
		must.Equal(t, len(resp.Get("requester_only_short_ids").Array()), 0, hsName(i)+" holds no unexpected event")
	}
	// Independent of the MSC4521 endpoints: the client-visible timeline.
	got := map[string]bool{}
	for _, id := range roomEventIDs(t, e.users[numGossipers-1], e.roomID) {
		got[id] = true
	}
	for _, id := range e.expectedIDs {
		if !got[id] {
			t.Errorf("%s: event %s not visible in the room timeline", hsName(numGossipers-1), id)
		}
	}
}

func (e *bulkEnv) testNoFallbackToOrigins(t *testing.T) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range e.originRequests {
		t.Logf("origin received: %s", r)
		if strings.Contains(r, "/state_ids/") || strings.Contains(r, "/get_missing_events/") || strings.Contains(r, "/event/") {
			t.Errorf("a homeserver fetched history from a scripted origin instead of a peer: %s", r)
		}
	}
}

// roomEventIDs returns every event ID in the room timeline as seen by c.
func roomEventIDs(t *testing.T, c *client.CSAPI, roomID string) []string {
	t.Helper()
	var ids []string
	from := ""
	for {
		q := url.Values{"dir": {"b"}, "limit": {"100"}}
		if from != "" {
			q.Set("from", from)
		}
		res := c.MustDo(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "messages"}, client.WithQueries(q))
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		must.NotError(t, "read /messages", err)
		chunk := gjson.GetBytes(body, "chunk").Array()
		for _, ev := range chunk {
			ids = append(ids, ev.Get("event_id").Str)
		}
		from = gjson.GetBytes(body, "end").Str
		if len(chunk) == 0 || from == "" {
			return ids
		}
	}
}

// roomLatestEventID returns the newest event ID in the room timeline.
func roomLatestEventID(t *testing.T, c *client.CSAPI, roomID string) string {
	t.Helper()
	res := c.MustDo(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "messages"},
		client.WithQueries(url.Values{"dir": {"b"}, "limit": {"1"}}))
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	must.NotError(t, "read /messages", err)
	return gjson.GetBytes(body, "chunk.0.event_id").Str
}

func postRoomDiff(t *testing.T, srv *federation.Server, deployment complement.Deployment, hs, roomID string, body []byte) gjson.Result {
	t.Helper()
	path := msc4521Prefix + "room_diff/" + url.PathEscape(roomID)
	req := fclient.NewFederationRequest("POST", srv.ServerName(), deployment.GetFullyQualifiedHomeserverName(t, hs), path)
	must.NotError(t, "set room_diff body", req.SetContent(body))
	res, err := srv.DoFederationRequest(context.Background(), t, deployment, req)
	must.NotError(t, "POST room_diff", err)
	defer res.Body.Close()
	out, err := io.ReadAll(res.Body)
	must.NotError(t, "read room_diff", err)
	must.Equal(t, res.StatusCode, 200, hs+" room_diff status: "+string(out))
	return gjson.ParseBytes(out)
}
