//go:build !dendrite_blacklist && !venator_blacklist

package activeedurecon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/gjson"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/must"
)

// numHomeservers is the number of deployed, gossiping homeservers. Raise to 16
// for the full-scale case; every other quantity derives from it.
const numHomeservers = 4

// stateEventsPerServer is how many state events each homeserver is the only
// one to receive directly from the scripted origin server.
const stateEventsPerServer = 10

// TestMSC4521BulkReconciliation seeds disjoint sparse event subsets on each
// homeserver and waits for the homeservers' own MSC4521 exchange to converge.
//
// The scripted server is only an origin and a witness: it sends each batch of
// leaf state events (all sharing one prev_event, so no ancestors are missing)
// to exactly one homeserver, and answers no history-fetch requests. Any
// convergence therefore has to come from homeserver-to-homeserver traffic, and
// any /state_ids request that reaches the scripted server is recorded.
func TestMSC4521BulkReconciliation(t *testing.T) {
	deployment := complement.Deploy(t, numHomeservers)
	defer deployment.Destroy(t)

	var mu sync.Mutex
	var fetches []string
	srv := federation.NewServer(t, deployment,
		federation.HandleKeyRequests(),
		federation.HandleMakeSendJoinRequests(),
		federation.HandleTransactionRequests(nil, nil),
	)
	srv.Mux().NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fetches = append(fetches, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	})
	cancel := srv.Listen()
	defer cancel()

	hsName := func(i int) string { return fmt.Sprintf("hs%d", i+1) }
	hs1 := deployment.GetFullyQualifiedHomeserverName(t, "hs1")

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	roomID := alice.MustCreateRoom(t, map[string]interface{}{"preset": "public_chat"})
	for i := 1; i < numHomeservers; i++ {
		u := deployment.Register(t, hsName(i), helpers.RegistrationOpts{})
		u.MustJoinRoom(t, roomID, []spec.ServerName{hs1})
	}
	charlie := srv.UserID("charlie")
	room := srv.MustJoinRoom(t, deployment, hs1, roomID, charlie)

	t.Run("DigestAndStrata", func(t *testing.T) {
		body, status := getRoomDigest(t, srv, deployment, roomID, "")
		must.Equal(t, status, 200, "room digest status")
		must.Equal(t, gjson.ParseBytes(body).Get("digest_type").Str, "algebraic_v1", "digest type")
		body, status = getRoomDigest(t, srv, deployment, roomID, "/strata")
		must.Equal(t, status, 200, "strata status")
		must.Equal(t, len(gjson.ParseBytes(body).Get("strata").Array()), 32, "strata count")
	})

	// All seeded events hang off the same tip so none has a missing ancestor.
	tip := room.Timeline[len(room.Timeline)-1].EventID()
	seeded := map[string]bool{}
	for i := 0; i < numHomeservers; i++ {
		for j := 0; j < stateEventsPerServer; j++ {
			key := fmt.Sprintf("seed-%d-%d", i, j)
			ev := srv.MustCreateEvent(t, room, federation.Event{
				Type:       "tk.nutra.msc4521.seed",
				StateKey:   &key,
				Sender:     charlie,
				Content:    map[string]interface{}{"origin_hs": i, "n": j},
				PrevEvents: []string{tip},
			})
			seeded[ev.EventID()] = true
			srv.MustSendTransaction(t, deployment, deployment.GetFullyQualifiedHomeserverName(t, hsName(i)),
				[]json.RawMessage{ev.JSON()}, nil)
		}
	}

	t.Run("Converges", func(t *testing.T) {
		start := time.Now()
		deadline := start.Add(60 * time.Second)
		for {
			digests := map[string]bool{}
			counts := map[int64]bool{}
			for i := 0; i < numHomeservers; i++ {
				body, status := getRoomDigestFrom(t, srv, deployment, hsName(i), roomID, "")
				must.Equal(t, status, 200, hsName(i)+" room digest status")
				d := gjson.ParseBytes(body)
				digests[d.Get("digest").Str] = true
				counts[d.Get("known_event_count").Int()] = true
			}
			if len(digests) == 1 && len(counts) == 1 {
				t.Logf("%d homeservers converged on %d seeded events in %s", numHomeservers, len(seeded), time.Since(start))
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("homeservers did not converge: %d distinct digests, %d distinct counts", len(digests), len(counts))
			}
			time.Sleep(time.Second)
		}
	})

	t.Run("NoNaiveStateFetch", func(t *testing.T) {
		mu.Lock()
		defer mu.Unlock()
		for _, p := range fetches {
			t.Logf("unhandled request to scripted origin: %s", p)
			if strings.Contains(p, "/state_ids/") || strings.Contains(p, "/get_missing_events/") {
				t.Errorf("homeserver fell back to naive fetch from scripted origin: %s", p)
			}
		}
	})
}
