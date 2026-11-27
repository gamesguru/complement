//go:build !venator_blacklist

// Venator: does not yet implement federation

package tests

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
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

func forwardGapScaleCount(t *testing.T) int {
	t.Helper()
	if raw, ok := os.LookupEnv("COMPLEMENT_FORWARD_GAP_SCALE_GAPS"); ok {
		gaps, err := strconv.Atoi(raw)
		if err != nil || gaps < 10 {
			t.Fatalf("COMPLEMENT_FORWARD_GAP_SCALE_GAPS must be an integer >= 10, got %q", raw)
		}
		return gaps
	}
	return forwardGapScaleGaps
}

func forwardGapRequestCount(rr *realRoom) int {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	return len(rr.backfillFroms)
}

func assertForwardGapRequests(t *testing.T, rr *realRoom, gaps int, lostIDs []string, settleRequests int) int {
	t.Helper()
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
		total, gaps, tried, settleRequests)
	if tried < gaps*9/10 {
		t.Fatalf("the fixture is broken: hs1 asked the remote about only %d of %d gaps, so the scale checks would not exercise them",
			tried, gaps)
	}
	if limit := 3 * gaps; total > limit {
		t.Errorf("the remote saw %d /backfill requests for %d gaps (limit %d): failed gaps are being re-fetched instead of remembered",
			total, gaps, limit)
	}
	return total
}

func assertForwardGapWarmRequests(t *testing.T, gaps int, forward func() (int, string, time.Duration)) {
	t.Helper()
	for i := 1; i <= 3; i++ {
		status, body, elapsed := forward()
		t.Logf("warm request %d: status %d in %s", i, status, elapsed)
		if status != http.StatusOK {
			t.Errorf("warm request %d returned %d, want 200: %s", i, status, body)
			continue
		}
		if elapsed > forwardGapWarmBudget {
			t.Errorf("warm request %d took %s with %d open gaps (budget %s): the request is far slower than a request over stored history should be",
				i, elapsed, gaps, forwardGapWarmBudget)
		}
	}
}

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
	// Override the default for local scaling experiments. Keep the same room
	// shape and assertions at each size; setup is logged separately below.
	gaps := forwardGapScaleCount(t)
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
	buildStart := time.Now()
	depth := int64(before.Depth()) + 1
	prev := before.EventID()
	var lostIDs []string
	var chain []json.RawMessage
	heldIDs := map[string]bool{}
	var lastID string
	for i := 1; i <= gaps; i++ {
		lost := rr.event(t, fmt.Sprintf("lost %d", i), []string{prev}, depth, true)
		rr.mu.Lock()
		rr.lost[lost.EventID()] = true
		rr.mu.Unlock()
		lostIDs = append(lostIDs, lost.EventID())

		held := rr.event(t, fmt.Sprintf("gap %d", i), []string{lost.EventID(), prev}, depth+1, true)
		chain = append(chain, held.JSON())
		heldIDs[held.EventID()] = true
		prev, lastID = held.EventID(), held.EventID()
		depth += 2
	}
	t.Logf("generated %d open gaps (%d events) in %s", gaps, 2*gaps, time.Since(buildStart))
	ingestStart := time.Now()
	// 50 is the most PDUs a transaction may carry.
	for start := 0; start < len(chain); start += 50 {
		end := start + 50
		if end > len(chain) {
			end = len(chain)
		}
		rr.srv.MustSendTransaction(t, deployment, hs1, chain[start:end], nil)
	}
	waitForForwardGapIngest(t, rr, roomID, heldIDs, lastID, ingestStart)

	// A filter that matches nothing, with a limit that covers the whole chain.
	forward := func() (int, string, time.Duration) {
		q := url.Values{}
		q.Set("dir", "f")
		q.Set("from", cursor)
		q.Set("limit", fmt.Sprintf("%d", 2*gaps+50))
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
	// The next round of fetching is only triggered by the next request, so
	// this delay is multiplied by the number of rounds: at 5 gaps tried per
	// round a fixed 250ms pause spent ~25s asleep on a 500-gap run. Start
	// short and back off to 125ms, so a stalled server is
	// still polled gently. The settle is setup, not the property under test.
	delay := 10 * time.Millisecond
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
				requests, gaps)
		}
		time.Sleep(delay)
		if delay < 125*time.Millisecond {
			delay *= 2
			if delay > 125*time.Millisecond {
				delay = 125 * time.Millisecond
			}
		}
	}

	// The fixture must really have produced the gaps, or the checks below
	// would pass vacuously.
	total := assertForwardGapRequests(t, rr, gaps, lostIDs, requests)

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
				i, elapsed, gaps, forwardGapWarmBudget)
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

// waitForForwardGapIngest blocks until rr.alice has synced lastID, the tip of the chain of held
// events. It fails the test if ingest stalls or overruns.
func waitForForwardGapIngest(t *testing.T, rr *realRoom, roomID string, held map[string]bool, lastID string, ingestStart time.Time) {
	t.Helper()
	// Wait for the tip without losing the ability to tell "slow" from "stuck".
	//
	// Ingest is setup, not the property under test, but it is not free: each gap
	// costs about one federation round trip to the fixture. The 500-gap run
	// that failed in CI had served about 100 /get_missing_events and about 20
	// /state_ids when the 5s default expired, and earlier local runs of this
	// test have taken 3.4-7.4s to ingest. The 5s SyncUntilTimeout is a client-liveness
	// budget, not a fixture budget, and MustSyncUntil only reports a bare
	// "timed out", so a failure says nothing about whether hs1 was still
	// making progress. Poll here instead: a generous deadline, a stall
	// detector, and a count of how many held events have arrived. Only this
	// wait is widened; the measured budgets below are unchanged.
	// Room v3+ PDUs carry no event_id field, so the IDs come from the events as
	// they were built, not from the raw JSON.
	const (
		ingestDeadline = 60 * time.Second
		stallAfter     = 15 * time.Second
	)
	seenHeld := make(map[string]bool, len(held))
	since := ""
	lastCount := 0
	lastProgress := time.Now()
	for {
		if elapsed := time.Since(ingestStart); elapsed > ingestDeadline {
			ct.Fatalf(t, "ingest did not finish within %s: hs1 synced %d of %d gap events (last progress %s ago)",
				ingestDeadline, len(seenHeld), len(held),
				time.Since(lastProgress).Round(time.Millisecond))
		}
		if stalled := time.Since(lastProgress); stalled > stallAfter {
			ct.Fatalf(t, "ingest stalled: hs1 made no progress for %s after syncing %d of %d gap events",
				stalled.Round(time.Millisecond), len(seenHeld), len(held))
		}
		sync, next := rr.alice.MustSync(t, client.SyncReq{Since: since, TimeoutMillis: "1000"})
		since = next
		for _, ev := range sync.Get("rooms.join." + client.GjsonEscape(roomID) + ".timeline.events").Array() {
			if id := ev.Get("event_id").Str; held[id] {
				seenHeld[id] = true
			}
		}
		if len(seenHeld) > lastCount {
			lastCount = len(seenHeld)
			lastProgress = time.Now()
		}
		if seenHeld[lastID] {
			break
		}
	}
	t.Logf("ingested %d held events and synced the tip in %s",
		len(held), time.Since(ingestStart).Round(time.Millisecond))
}
