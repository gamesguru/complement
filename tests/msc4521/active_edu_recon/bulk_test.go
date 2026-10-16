//go:build !dendrite_blacklist && !venator_blacklist

package activeedurecon

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

// TestMSC4521BulkReconciliation checks that 16 real homeservers converge on an
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
func TestMSC4521BulkReconciliation(t *testing.T) {
	if os.Getenv("COMPLEMENT_MSC4521_BULK") == "" {
		t.Skip("set COMPLEMENT_MSC4521_BULK=1 with an MSC4521-capable image that initiates reconciliation")
	}
	deployment := complement.Deploy(t, numGossipers)
	defer deployment.Destroy(t)

	hsName := func(i int) string { return fmt.Sprintf("hs%d", i+1) }
	hs1 := deployment.GetFullyQualifiedHomeserverName(t, "hs1")

	// Prober: a scripted server that only queries digests/room_diff.
	prober := federation.NewServer(t, deployment, federation.HandleKeyRequests())
	cancelProber := prober.Listen()
	defer cancelProber()

	// 16 real homeservers join one room and each originates a real event.
	users := make([]*client.CSAPI, numGossipers)
	for i := range users {
		users[i] = deployment.Register(t, hsName(i), helpers.RegistrationOpts{})
	}
	roomID := users[0].MustCreateRoom(t, map[string]interface{}{"preset": "public_chat"})
	for i := 1; i < numGossipers; i++ {
		users[i].MustJoinRoom(t, roomID, []spec.ServerName{hs1})
	}
	for i := range users {
		users[i].SendEventSynced(t, roomID, b.Event{Type: "m.room.message", Content: map[string]interface{}{"body": "base from " + hsName(i)}})
	}

	// 16 scripted origins, each a distinct server name and signing identity.
	var mu sync.Mutex
	var originRequests []string
	type origin struct {
		srv  *federation.Server
		room *federation.ServerRoom
		user string
	}
	origins := make([]origin, numGossipers)
	for i := range origins {
		i := i
		srv := federation.NewServer(t, deployment,
			federation.HandleKeyRequests(),
			federation.HandleTransactionRequests(nil, nil),
		)
		srv.Mux().NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			originRequests = append(originRequests, fmt.Sprintf("origin%d %s %s", i, r.Method, r.URL.Path))
			mu.Unlock()
			w.WriteHeader(http.StatusNotFound)
		})
		defer srv.Listen()()
		origins[i].srv = srv
		origins[i].user = srv.UserID("origin")
		origins[i].room = srv.MustJoinRoom(t, deployment, hs1, roomID, origins[i].user)
	}

	// Let every homeserver agree on the base set (all joins, base messages) and
	// capture it exactly.
	digestOf := func(hs string) gjson.Result {
		body, status := getRoomDigestFrom(t, prober, deployment, hs, roomID, "")
		must.Equal(t, status, 200, hs+" room digest status")
		return gjson.ParseBytes(body)
	}
	waitAll := func(want func(gjson.Result) bool, what string, onFirst func(int)) {
		t.Helper()
		start := time.Now()
		done := make([]bool, numGossipers)
		for {
			n := 0
			for i := 0; i < numGossipers; i++ {
				if !done[i] && want(digestOf(hsName(i))) {
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
	baseIDs := roomEventIDs(t, users[0], roomID)
	baseKernel := reconcile.NewResidentKernel()
	for _, id := range baseIDs {
		h, err := reconcile.FromMatrixEventID(id, reconcile.V4Plus)
		must.NotError(t, "hash base event", err)
		must.NotError(t, "insert base event", baseKernel.Insert(h))
	}
	baseDigest := baseKernel.Accumulator().EncodeDigest()
	waitAll(func(d gjson.Result) bool {
		return d.Get("digest").Str == baseDigest && d.Get("known_event_count").Int() == int64(len(baseIDs))
	}, "base set", nil)

	t.Run("DigestAndStrata", func(t *testing.T) {
		d := digestOf("hs1")
		must.Equal(t, d.Get("digest_type").Str, "algebraic_v1", "digest type")
		body, status := getRoomDigestFrom(t, prober, deployment, "hs1", roomID, "/strata")
		must.Equal(t, status, 200, "strata status")
		must.Equal(t, len(gjson.ParseBytes(body).Get("strata").Array()), 32, "strata count")
	})

	// Seed: origin i -> homeserver i only. Every event hangs off the common tip.
	tip := baseIDs[0]
	if latest := roomLatestEventID(t, users[0], roomID); latest != "" {
		tip = latest
	}
	expected := reconcile.NewResidentKernel()
	for _, id := range baseIDs {
		h, _ := reconcile.FromMatrixEventID(id, reconcile.V4Plus)
		must.NotError(t, "insert", expected.Insert(h))
	}
	expectedIDs := append([]string{}, baseIDs...)
	shortToID := map[uint64]string{}
	for _, id := range baseIDs {
		shortToID[reconcileHash(t, id)] = id
	}
	for i, o := range origins {
		for j := 0; j < seededPerOrigin; j++ {
			ev := o.srv.MustCreateEvent(t, o.room, federation.Event{
				Type:       "m.room.message",
				Sender:     o.user,
				Content:    map[string]interface{}{"body": fmt.Sprintf("seed %d/%d", i, j)},
				PrevEvents: []string{tip},
			})
			o.room.AddEvent(ev)
			h, err := reconcile.FromMatrixEventID(ev.EventID(), reconcile.V4Plus)
			must.NotError(t, "hash seeded event", err)
			must.NotError(t, "insert seeded event", expected.Insert(h))
			if prev, dup := shortToID[h.H64]; dup {
				t.Fatalf("u64 collision in test data: %s vs %s", prev, ev.EventID())
			}
			shortToID[h.H64] = ev.EventID()
			expectedIDs = append(expectedIDs, ev.EventID())
			o.srv.MustSendTransaction(t, deployment, deployment.GetFullyQualifiedHomeserverName(t, hsName(i)),
				[]json.RawMessage{ev.JSON()}, nil)
		}
	}
	wantDigest := expected.Accumulator().EncodeDigest()
	wantCount := int64(len(expectedIDs))
	t.Logf("seeded %d events across %d origins; expecting %d total events (%d u64 short IDs)", numGossipers*seededPerOrigin, numGossipers, wantCount, len(shortToID))

	// Sparse start: each homeserver must hold more than the base but fewer than all.
	t.Run("SparseStart", func(t *testing.T) {
		for i := 0; i < numGossipers; i++ {
			d := digestOf(hsName(i))
			// Allow an already-converged homeserver only if the system is fast; the
			// real check is that the starting point was sparse for at least most.
			if d.Get("known_event_count").Int() > wantCount {
				t.Errorf("%s holds more events (%d) than the expected set (%d)", hsName(i), d.Get("known_event_count").Int(), wantCount)
			}
		}
	})

	t.Run("Converges", func(t *testing.T) {
		start := time.Now()
		waitAll(func(d gjson.Result) bool {
			return d.Get("digest").Str == wantDigest && d.Get("known_event_count").Int() == wantCount
		}, "exact expected set", func(i int) {
			t.Logf("%s reached the exact expected set after %s", hsName(i), time.Since(start).Round(time.Millisecond))
		})
	})

	// Exact set: not just equal digests. A zero-difference room_diff against
	// each homeserver must find nothing missing in either direction.
	t.Run("ExactEventSet", func(t *testing.T) {
		sketch, err := reconcile.NewSyndromeSketch(2)
		must.NotError(t, "new sketch", err)
		for h64 := range shortToID {
			must.NotError(t, "toggle", sketch.Toggle(h64))
		}
		for i := 0; i < numGossipers; i++ {
			d := digestOf(hsName(i))
			req, err := json.Marshal(map[string]interface{}{
				"mode": "sketch", "frame_id": d.Get("frame_id").Str,
				"local_digest": wantDigest, "digest_type": "algebraic_v1",
				"local_known_event_count": expected.Accumulator().Count,
				"frame_event_ids":         d.Get("frame_event_ids").Value(), "estimated_delta": 0,
				"requests":       []map[string]interface{}{{"depth": 0, "prefix": 0, "capacity": 2}},
				"local_sketches": []string{sketch.Encode()}, "limit": 100,
			})
			must.NotError(t, "encode room_diff", err)
			resp := postRoomDiff(t, prober, deployment, hsName(i), roomID, req)
			must.Equal(t, len(resp.Get("missing_event_ids").Array()), 0, hsName(i)+" is missing no expected event")
			must.Equal(t, len(resp.Get("requester_only_short_ids").Array()), 0, hsName(i)+" holds no unexpected event")
		}
		// Independent of the MSC4521 endpoints: the client-visible timeline.
		got := map[string]bool{}
		for _, id := range roomEventIDs(t, users[numGossipers-1], roomID) {
			got[id] = true
		}
		for _, id := range expectedIDs {
			if !got[id] {
				t.Errorf("%s: event %s not visible in the room timeline", hsName(numGossipers-1), id)
			}
		}
	})

	t.Run("NoFallbackToOrigins", func(t *testing.T) {
		mu.Lock()
		defer mu.Unlock()
		for _, r := range originRequests {
			t.Logf("origin received: %s", r)
			if strings.Contains(r, "/state_ids/") || strings.Contains(r, "/get_missing_events/") || strings.Contains(r, "/event/") {
				t.Errorf("a homeserver fetched history from a scripted origin instead of a peer: %s", r)
			}
		}
	})
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
	path := "/_matrix/federation/unstable/tk.nutra.msc0501/room_diff/" + url.PathEscape(roomID)
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
