//go:build !venator_blacklist

// Venator: does not yet implement federation

package tests

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/tidwall/gjson"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/ct"
)

// A homeserver that joins a room over federation starts with the room's state
// and none of its history. The history has to be fetched (/backfill) while the
// client paginates backwards, so what the client sees depends on the order that
// backfill lands relative to the pagination cursor.
//
// The client's view must stay honest: every event exactly once, in order, and
// never "you have reached the start of the room" while history is known to be
// missing.

// backwardPage returns the event IDs of one backward /messages page and the
// continuation token, if any. A 429 is the homeserver saying history is still
// being fetched, so the client retries. If it is still 429 after the retries,
// stillFetching is true: the homeserver is reporting an open gap, which callers
// may treat as acceptable (a gap it cannot fill) or as a failure (a gap it
// should have filled).
func backwardPage(t *testing.T, c *client.CSAPI, roomID, from string, limit int) (ids []string, end string, stillFetching bool) {
	t.Helper()
	for attempt := 0; attempt < 40; attempt++ {
		q := url.Values{}
		q.Set("dir", "b")
		q.Set("from", from)
		q.Set("limit", fmt.Sprint(limit))
		res := c.Do(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "messages"}, client.WithQueries(q))
		if res.StatusCode == http.StatusTooManyRequests {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if res.StatusCode != http.StatusOK {
			ct.Fatalf(t, "backward /messages returned %d", res.StatusCode)
		}
		body := gjson.ParseBytes(client.ParseJSON(t, res))
		for _, ev := range body.Get("chunk").Array() {
			ids = append(ids, ev.Get("event_id").Str)
		}
		return ids, body.Get("end").Str, false
	}
	return nil, "", true
}

// joinedPrevBatch waits for the room to appear in a sync and returns the
// pagination token for the start of its timeline.
func joinedPrevBatch(t *testing.T, c *client.CSAPI, roomID string) string {
	t.Helper()
	var cursor string
	c.MustSyncUntil(t, client.SyncReq{}, func(_ string, sync gjson.Result) error {
		room := sync.Get("rooms.join." + client.GjsonEscape(roomID))
		if !room.Exists() {
			return fmt.Errorf("%s has not synced room %s yet", c.UserID, roomID)
		}
		if cursor = room.Get("timeline.prev_batch").Str; cursor == "" {
			return fmt.Errorf("room %s has no prev_batch yet", roomID)
		}
		return nil
	})
	return cursor
}

// TestFederationBackwardMessagesReturnsEveryEventOnce checks that paginating
// backwards through a freshly joined room, whose history is all fetchable but
// takes several /backfill batches, returns every event exactly once and in
// order.
//
//	hs1 joins after:  [h1]--[h2]-- ... --[h60]
//
// Expected: pages of 10, newest first, h60 down to h1, nothing missing, nothing
// repeated, and no end-of-timeline before h1.
func TestFederationBackwardMessagesReturnsEveryEventOnce(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	const total = 60
	var history []string
	rr, roomID, cancel := newRealRoom(t, deployment, false, func(rr *realRoom) {
		for i := 1; i <= total; i++ {
			ev := rr.event(t, fmt.Sprintf("history %d", i), nil, 0, true)
			history = append(history, ev.EventID())
		}
	})
	defer cancel()
	defer rr.logRequests(t)

	cursor := joinedPrevBatch(t, rr.alice, roomID)

	var newestFirst []string
	for page := 0; ; page++ {
		if page > 100 {
			ct.Fatalf(t, "backward pagination did not terminate after %d pages", page)
		}
		ids, end, stillFetching := backwardPage(t, rr.alice, roomID, cursor, 10)
		if stillFetching {
			ct.Fatalf(t, "backward /messages was still being fetched after retries, but every event can be served")
		}
		newestFirst = append(newestFirst, ids...)
		if end == "" {
			break
		}
		cursor = end
	}

	var got []string
	want := map[string]bool{}
	for _, id := range history {
		want[id] = true
	}
	for _, id := range newestFirst {
		if want[id] {
			got = append(got, id)
		}
	}

	assertNoDuplicates(t, "backward /messages", got)
	if missing := missingFrom(history, got); len(missing) > 0 {
		ct.Errorf(t, "backward /messages never returned %d of %d events (the client is left with a hole): %v", len(missing), total, missing)
	}
	// Newest first: the reverse of the order they were sent in.
	next := total - 1
	for _, id := range got {
		for next >= 0 && history[next] != id {
			next--
		}
		if next < 0 {
			ct.Errorf(t, "backward /messages returned %s out of order: %v", id, got)
			break
		}
		next--
	}
}

// TestFederationBackwardMessagesDoesNotReportStartWhileGapOpen checks that a
// hole the homeserver cannot fill is reported as a hole, not as the start of
// the room.
//
//	hs1 joins after:  [h1]--[h2]--[h3]--[lost]--[h5]--[h6]--[h7]--[h8]
//	                                      ^^^^
//	             the remote refuses /event, /backfill and /state_ids for it,
//	             so h1..h3 are not reachable by backfill and h5 has a missing
//	             parent (a backward extremity)
//
// Expected: backward pagination returns h8..h5. It must not then answer "there
// is nothing more" (no continuation token): a client reads that as the
// beginning of the conversation and renders it over a hole. Either a
// continuation token or a "still being fetched" (429) answer is acceptable.
func TestFederationBackwardMessagesDoesNotReportStartWhileGapOpen(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	var visible []string
	rr, roomID, cancel := newRealRoom(t, deployment, false, func(rr *realRoom) {
		var lost string
		for i := 1; i <= 8; i++ {
			ev := rr.event(t, fmt.Sprintf("history %d", i), nil, 0, true)
			if i == 4 {
				lost = ev.EventID()
			}
			if i > 4 {
				visible = append(visible, ev.EventID())
			}
		}
		rr.mu.Lock()
		rr.lost[lost] = true
		rr.mu.Unlock()
	})
	defer cancel()
	defer rr.logRequests(t)

	cursor := joinedPrevBatch(t, rr.alice, roomID)

	var got []string
	reportedStart := false
	for page := 0; page < 20; page++ {
		ids, end, stillFetching := backwardPage(t, rr.alice, roomID, cursor, 10)
		if stillFetching {
			// The homeserver keeps reporting the gap as unfilled: acceptable.
			break
		}
		got = append(got, ids...)
		if end == "" {
			reportedStart = true
			break
		}
		cursor = end
	}

	if missing := missingFrom(visible, got); len(missing) > 0 {
		ct.Errorf(t, "the events above the gap were not returned: %v", missing)
	}
	if reportedStart {
		ct.Errorf(t, "backward /messages ended with no continuation token while history below h5 is known to be missing; "+
			"a client renders that as the beginning of the room")
	}
}
