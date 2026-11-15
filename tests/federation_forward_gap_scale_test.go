//go:build !venator_blacklist

// Venator: does not yet implement federation

package tests

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/matrix-org/gomatrixserverlib"
	"github.com/tidwall/gjson"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/ct"
)

// forwardGapScaleGaps is how many open gaps the test leaves in the room. A
// homeserver that costs O(E) work per gap per request does O(E^2) work here:
// at 500 that is ~125k position lookups per request. This is a stress test, not
// a proof of complexity: the call-count assertions in
// syncapi/routing/messages_forward_gap_test.go in dendrite are what pin the
// O(E) bound.
const forwardGapScaleGaps = 500

// forwardGapWarmBudget is a liveness check on a request that only has to serve
// stored history: every gap has already been tried, so nothing is left to
// fetch. It is far above what a linear implementation needs, and it is not a
// measurement of scaling: a slow runner or a mildly super-linear implementation
// can still pass or fail it.
const forwardGapWarmBudget = 2 * time.Second

// TestFederationForwardGapWithManyOpenGapsStaysBounded checks that a forward
// /messages request with hundreds of open gaps settles, asks the remote a
// bounded number of times, and then answers quickly. It cannot prove the
// per-request work is linear; it only fails an implementation that is slow or
// chatty enough to show up in wall time or remote request counts.
//
// Room shape, oldest event on the left (E = held by hs1, L = never served):
//
//	before ── E1 ── E2 ── E3 ── ... ── E500        hs1 has this chain
//	            \     \     \             \
//	             L1    L2    L3   ...      L500     each Ei also names Li as a
//	                                                parent, and no server can serve
//	                                                it: 500 independent open gaps
//
// Each Ei is a backward extremity (its parent Li is missing), so a forward
// page that starts before E1 has 500 gaps ahead of its cursor.
//
// A plain forward page can only ever select one gap: the first stored event
// is at or below every extremity, so only an extremity sitting on it is
// eligible. A type filter that matches nothing removes every stored event
// from the page, so the fill is bounded by the raw end of the range and all
// 500 gaps are eligible at once. That is the request this test sends.
//
// Expected, and what a chatty or very slow implementation fails:
//
//  1. Federation cost is bounded. Each gap is fetched about once. Every
//     request that has to look at all the gaps must not re-ask the remote for
//     gaps that already failed (a failure is remembered), so the remote sees
//     at most a few /backfill requests per gap in total, not one per gap per
//     request.
//  2. Once every gap has been tried, a request completes within
//     forwardGapWarmBudget, and sends the remote nothing.
//  3. Progress is made at all: the request settles with a 200 in bounded
//     time rather than answering "history is still being fetched" forever.
func TestFederationForwardGapWithManyOpenGapsStaysBounded(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)
	hs1 := deployment.GetFullyQualifiedHomeserverName(t, "hs1")

	var before gomatrixserverlib.PDU
	rr, roomID, cancel := newRealRoom(t, deployment, true, func(rr *realRoom) {
		before = rr.event(t, "before the gaps", nil, 0, true)
		rr.srv.MustSendTransaction(t, deployment, hs1, []json.RawMessage{before.JSON()}, nil)
	})
	defer cancel()
	defer rr.logRequests(t)

	// hs1 holds `before`; its prev_batch is a cursor that sits below every
	// event created below, which is where the forward walk starts.
	var cursor string
	rr.alice.MustSyncUntil(t, client.SyncReq{}, func(_ string, sync gjson.Result) error {
		room := sync.Get("rooms.join." + client.GjsonEscape(roomID))
		if !room.Get("timeline.events").Exists() {
			return fmt.Errorf("no timeline for %s yet", roomID)
		}
		for _, ev := range room.Get("timeline.events").Array() {
			if ev.Get("event_id").Str == before.EventID() {
				cursor = room.Get("timeline.prev_batch").Str
				if cursor == "" {
					return fmt.Errorf("no prev_batch for %s yet", roomID)
				}
				return nil
			}
		}
		return fmt.Errorf("hs1 has not synced %s yet", before.EventID())
	})

	// Build the chain. Li is registered as lost before Ei is delivered, so hs1
	// can never fetch it and Ei stays a backward extremity.
	depth := int64(before.Depth()) + 1
	prev := before.EventID()
	var lostIDs []string
	var chain []json.RawMessage
	var lastID string
	for i := 1; i <= forwardGapScaleGaps; i++ {
		lost := rr.event(t, fmt.Sprintf("lost %d", i), []string{prev}, depth, true)
		rr.mu.Lock()
		rr.lost[lost.EventID()] = true
		rr.mu.Unlock()
		lostIDs = append(lostIDs, lost.EventID())

		held := rr.event(t, fmt.Sprintf("gap %d", i), []string{lost.EventID(), prev}, depth+1, true)
		chain = append(chain, held.JSON())
		prev, lastID = held.EventID(), held.EventID()
		depth += 2
	}
	// 50 is the most PDUs a transaction may carry.
	for start := 0; start < len(chain); start += 50 {
		end := start + 50
		if end > len(chain) {
			end = len(chain)
		}
		rr.srv.MustSendTransaction(t, deployment, hs1, chain[start:end], nil)
	}
	rr.alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, lastID))

	// A filter that matches nothing, with a limit that covers the whole chain.
	forward := func() (int, string, time.Duration) {
		q := url.Values{}
		q.Set("dir", "f")
		q.Set("from", cursor)
		q.Set("limit", fmt.Sprintf("%d", 2*forwardGapScaleGaps+50))
		q.Set("filter", `{"types":["org.example.matches.nothing"]}`)
		start := time.Now()
		res := rr.alice.Do(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "messages"}, client.WithQueries(q))
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		elapsed := time.Since(start)
		if err != nil {
			ct.Fatalf(t, "reading /messages response: %s", err)
		}
		return res.StatusCode, string(body), elapsed
	}

	// Settle: keep asking, as a client would, until every gap has been tried.
	settleBy := time.Now().Add(3 * time.Minute)
	requests := 0
	for {
		requests++
		status, body, elapsed := forward()
		t.Logf("settling request %d: status %d in %s", requests, status, elapsed)
		if status == http.StatusOK {
			break
		}
		if status != http.StatusTooManyRequests {
			ct.Fatalf(t, "forward /messages returned %d, want 200 or 429 while hs1 is still fetching: %s", status, body)
		}
		if time.Now().After(settleBy) {
			ct.Fatalf(t, "the filtered forward request did not settle within 3m (%d requests); hs1 is not making progress through %d open gaps",
				requests, forwardGapScaleGaps)
		}
		time.Sleep(250 * time.Millisecond)
	}

	// The fixture must really have produced the gaps, or the checks below
	// would pass vacuously.
	asked := map[string]int{}
	rr.mu.Lock()
	for _, from := range rr.backfillFroms {
		for _, id := range from {
			asked[id]++
		}
	}
	total := len(rr.backfillFroms)
	rr.mu.Unlock()
	tried := 0
	for _, id := range lostIDs {
		if asked[id] > 0 {
			tried++
		}
	}
	t.Logf("remote saw %d /backfill requests for %d gaps (%d distinct gaps tried), over %d settling requests",
		total, forwardGapScaleGaps, tried, requests)
	if tried < forwardGapScaleGaps*9/10 {
		ct.Fatalf(t, "the fixture is broken: hs1 asked the remote about only %d of %d gaps, so the scale checks would not exercise them",
			tried, forwardGapScaleGaps)
	}

	// (1) Bounded federation cost: a failed gap is remembered, not re-asked on
	// every request. Allow a few attempts per gap for retries on the way in.
	if limit := 3 * forwardGapScaleGaps; total > limit {
		ct.Errorf(t, "the remote saw %d /backfill requests for %d gaps (limit %d): failed gaps are being re-fetched instead of remembered",
			total, forwardGapScaleGaps, limit)
	}

	// (2) With every gap tried, a request is cheap and silent.
	for i := 1; i <= 3; i++ {
		status, body, elapsed := forward()
		t.Logf("warm request %d: status %d in %s", i, status, elapsed)
		if status != http.StatusOK {
			ct.Errorf(t, "warm request %d returned %d, want 200: %s", i, status, body)
			continue
		}
		if elapsed > forwardGapWarmBudget {
			ct.Errorf(t, "warm request %d took %s with %d open gaps (budget %s): the request is far slower than a request over stored history should be",
				i, elapsed, forwardGapScaleGaps, forwardGapWarmBudget)
		}
	}
	rr.mu.Lock()
	after := len(rr.backfillFroms)
	rr.mu.Unlock()
	if after != total {
		ct.Errorf(t, "warm requests sent the remote %d more /backfill requests: gaps that already failed must not be re-asked",
			after-total)
	}
}
