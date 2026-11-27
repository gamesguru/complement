//go:build !venator_blacklist

// Venator: does not yet implement federation

package tests

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"

	"github.com/tidwall/gjson"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/ct"
)

// TestFederationForwardMessagesFillsGapBehindWedgedOne checks that a forward
// /messages request fills a gap that can be filled even when an older gap ahead
// of the same cursor cannot be.
//
//	before ── W ── ...                W = held by hs1, its parent LOST is never served
//	   └──── E ── ...                E = held by hs1, its parent FILL is served later
//
// Both W and E are backward extremities ahead of the cursor. The wedged gap
// fails first (it is the oldest) and must not stop hs1 from asking about FILL.
// Expected: the forward page contains FILL, once, and the remote was asked
// about FILL.
func TestFederationForwardMessagesFillsGapBehindWedgedOne(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)
	hs1 := deployment.GetFullyQualifiedHomeserverName(t, "hs1")

	var before string
	var baseDepth int64
	rr, roomID, cancel := newRealRoom(t, deployment, true, func(rr *realRoom) {
		ev := rr.event(t, "before the gaps", nil, 0, true)
		before = ev.EventID()
		baseDepth = int64(ev.Depth())
		rr.srv.MustSendTransaction(t, deployment, hs1, []json.RawMessage{ev.JSON()}, nil)
	})
	defer cancel()
	defer rr.logRequests(t)

	var cursor string
	rr.alice.MustSyncUntil(t, client.SyncReq{}, func(_ string, sync gjson.Result) error {
		room := sync.Get("rooms.join." + client.GjsonEscape(roomID))
		for _, ev := range room.Get("timeline.events").Array() {
			if ev.Get("event_id").Str == before {
				if cursor = room.Get("timeline.prev_batch").Str; cursor != "" {
					return nil
				}
			}
		}
		return fmt.Errorf("hs1 has not synced %s with a prev_batch yet", before)
	})

	// W's parent is lost for good. FILL starts lost too, so hs1 cannot fetch it
	// while E is delivered, and is served afterwards.
	lost := rr.event(t, "lost", []string{before}, baseDepth+1, true)
	wedged := rr.event(t, "wedged", []string{lost.EventID(), before}, baseDepth+2, true)
	fill := rr.event(t, "fill", []string{before}, baseDepth+1, true)
	held := rr.event(t, "held", []string{fill.EventID(), wedged.EventID()}, baseDepth+3, true)
	rr.mu.Lock()
	rr.lost[lost.EventID()] = true
	rr.lost[fill.EventID()] = true
	rr.mu.Unlock()

	rr.srv.MustSendTransaction(t, deployment, hs1, []json.RawMessage{wedged.JSON(), held.JSON()}, nil)
	rr.alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, held.EventID()))

	rr.mu.Lock()
	delete(rr.lost, fill.EventID())
	rr.mu.Unlock()

	forwardIDs := func() []string {
		q := url.Values{}
		q.Set("dir", "f")
		q.Set("from", cursor)
		q.Set("limit", "100")
		res := rr.alice.MustDo(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "messages"}, client.WithQueries(q))
		body := gjson.ParseBytes(client.ParseJSON(t, res))
		var ids []string
		for _, ev := range body.Get("chunk").Array() {
			ids = append(ids, ev.Get("event_id").Str)
		}
		return ids
	}

	var ids []string
	for attempt := 0; attempt < 6; attempt++ {
		if ids = forwardIDs(); len(missingFrom([]string{fill.EventID()}, ids)) == 0 {
			break
		}
	}
	if missing := missingFrom([]string{fill.EventID()}, ids); len(missing) > 0 {
		ct.Errorf(t, "a forward /messages request did not fill the gap that can be filled (an older gap that cannot be must not block it): %v in %v", missing, ids)
	}
	assertNoDuplicates(t, "forward /messages", ids)

	rr.mu.Lock()
	asked := map[string]bool{}
	for _, from := range rr.backfillFroms {
		for _, id := range from {
			asked[id] = true
		}
	}
	rr.mu.Unlock()
	if !asked[fill.EventID()] {
		ct.Errorf(t, "hs1 never asked the remote for the fillable gap's missing parent %s", fill.EventID())
	}
}

// TestFederationForwardMessagesDoesNotRepeatFailedGap checks that a gap the
// remote cannot fill is asked about a bounded number of times across repeated
// forward requests, not once per request.
func TestFederationForwardMessagesDoesNotRepeatFailedGap(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)
	hs1 := deployment.GetFullyQualifiedHomeserverName(t, "hs1")

	var before string
	var baseDepth int64
	rr, roomID, cancel := newRealRoom(t, deployment, true, func(rr *realRoom) {
		ev := rr.event(t, "before the gap", nil, 0, true)
		before = ev.EventID()
		baseDepth = int64(ev.Depth())
		rr.srv.MustSendTransaction(t, deployment, hs1, []json.RawMessage{ev.JSON()}, nil)
	})
	defer cancel()
	defer rr.logRequests(t)

	var cursor string
	rr.alice.MustSyncUntil(t, client.SyncReq{}, func(_ string, sync gjson.Result) error {
		room := sync.Get("rooms.join." + client.GjsonEscape(roomID))
		for _, ev := range room.Get("timeline.events").Array() {
			if ev.Get("event_id").Str == before {
				if cursor = room.Get("timeline.prev_batch").Str; cursor != "" {
					return nil
				}
			}
		}
		return fmt.Errorf("hs1 has not synced %s with a prev_batch yet", before)
	})

	lost := rr.event(t, "lost", []string{before}, baseDepth+1, true)
	held := rr.event(t, "held", []string{lost.EventID(), before}, baseDepth+2, true)
	rr.mu.Lock()
	rr.lost[lost.EventID()] = true
	rr.mu.Unlock()
	rr.srv.MustSendTransaction(t, deployment, hs1, []json.RawMessage{held.JSON()}, nil)
	rr.alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, held.EventID()))

	rr.mu.Lock()
	baseline := len(rr.backfillFroms)
	rr.mu.Unlock()

	const requests = 10
	for i := 0; i < requests; i++ {
		q := url.Values{}
		q.Set("dir", "f")
		q.Set("from", cursor)
		q.Set("limit", "100")
		res := rr.alice.MustDo(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "messages"}, client.WithQueries(q))
		client.ParseJSON(t, res)
	}

	rr.mu.Lock()
	extra := len(rr.backfillFroms) - baseline
	rr.mu.Unlock()
	if extra > 3 {
		ct.Errorf(t, "%d forward /messages requests sent the remote %d /backfill requests for one unfillable gap; a failed gap must be remembered", requests, extra)
	}
}
