//go:build !venator_blacklist

// Venator: does not yet implement federation

package tests

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/gomatrixserverlib/fclient"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/matrix-org/util"
	"github.com/tidwall/gjson"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/ct"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
)

// lateEventFixture is a room owned by a Complement federation server which hs1
// has joined with two local users. Events the Complement server creates can be
// backdated (origin_server_ts) and given explicit prev_events/depth, so tests
// can inject "late" federated events at chosen positions in the DAG.
type lateEventFixture struct {
	srv        *federation.Server
	room       *federation.ServerRoom
	alice, bob *client.CSAPI
	charlie    string
	// tsOffset is applied to origin_server_ts of the next event the
	// Complement server signs. Reset after each use.
	tsOffset time.Duration
}

func newLateEventFixture(t *testing.T, deployment complement.Deployment) (*lateEventFixture, func()) {
	t.Helper()
	f, _, cancel := newLateEventFixtureWithHistory(t, deployment, 0)
	return f, cancel
}

// newLateEventFixtureWithHistory is newLateEventFixture, except the Complement
// server first sends historyLen messages into the room, before hs1 joins. hs1
// can only learn them over /backfill. The event IDs are returned oldest first.
func newLateEventFixtureWithHistory(t *testing.T, deployment complement.Deployment, historyLen int) (*lateEventFixture, []string, func()) {
	t.Helper()
	f := &lateEventFixture{}

	f.srv = federation.NewServer(t, deployment,
		federation.HandleKeyRequests(),
		federation.HandleMakeSendJoinRequests(),
		federation.HandleTransactionRequests(nil, nil),
	)
	f.srv.UnexpectedRequestsAreErrors = false
	cancel := f.srv.Listen()

	f.alice = deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	f.bob = deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	impl := &federation.ServerRoomImplCustom{
		EventCreatorFn: func(def federation.ServerRoomImpl, room *federation.ServerRoom, s *federation.Server, proto *gomatrixserverlib.ProtoEvent) (gomatrixserverlib.PDU, error) {
			verImpl, err := gomatrixserverlib.GetRoomVersion(room.Version)
			if err != nil {
				return nil, err
			}
			eb := verImpl.NewEventBuilderFromProtoEvent(proto)
			ts := time.Now().Add(f.tsOffset)
			f.tsOffset = 0
			return eb.Build(ts, s.ServerName(), s.KeyID, s.Priv)
		},
	}

	ver := f.alice.GetDefaultRoomVersion(t)
	f.charlie = f.srv.UserID("charlie")
	f.room = f.srv.MustMakeRoom(t, ver, federation.InitialRoomEvents(ver, f.charlie), federation.WithImpl(impl))
	alias := f.srv.MakeAliasMapping("late-ordering", f.room.RoomID)

	history := make([]string, 0, historyLen)
	for i := 1; i <= historyLen; i++ {
		ev := f.createCharlieMessage(t, fmt.Sprintf("history %d", i), 0, nil, 0)
		f.room.AddEvent(ev)
		history = append(history, ev.EventID())
	}

	f.alice.MustJoinRoom(t, alias, []spec.ServerName{f.srv.ServerName()})
	f.bob.MustJoinRoom(t, alias, []spec.ServerName{f.srv.ServerName()})
	return f, history, cancel
}

// createCharlieMessage creates (but does not send) a message from the remote
// user. prevEvents/depth of nil/0 means "use the room's forward extremities".
func (f *lateEventFixture) createCharlieMessage(t *testing.T, body string, tsOffset time.Duration, prevEvents []string, depthOverride int64) gomatrixserverlib.PDU {
	t.Helper()
	ev := federation.Event{
		Sender: f.charlie,
		Type:   "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    body,
		},
	}
	if prevEvents != nil {
		ev.PrevEvents = prevEvents
	}
	// ProtoEventCreator derives depth from room.Depth+1, so temporarily lower
	// it to place the event at the depth we want.
	savedDepth := f.room.Depth
	if depthOverride > 0 {
		f.room.Depth = depthOverride - 1
	}
	f.tsOffset = tsOffset
	pdu := f.srv.MustCreateEvent(t, f.room, ev)
	f.room.Depth = savedDepth
	return pdu
}

// waitForServerEvent blocks until the Complement server has received eventID
// from hs1 over federation.
func (f *lateEventFixture) waitForServerEvent(t *testing.T, eventID string) gomatrixserverlib.PDU {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ev, ok := f.room.GetEventInTimeline(eventID); ok {
			return ev
		}
		time.Sleep(50 * time.Millisecond)
	}
	ct.Fatalf(t, "Complement server never received %s from hs1", eventID)
	return nil
}

func timelineEventIDs(res gjson.Result, roomID string) []string {
	var ids []string
	for _, ev := range res.Get(fmt.Sprintf("rooms.join.%s.timeline.events", client.GjsonEscape(roomID))).Array() {
		ids = append(ids, ev.Get("event_id").Str)
	}
	return ids
}

func countOf(ids []string, want string) int {
	n := 0
	for _, id := range ids {
		if id == want {
			n++
		}
	}
	return n
}

// paginateBackward calls /messages?dir=b starting at from ("" = live end).
// It stops after maxPages pages (0 = until exhausted) and returns the event
// IDs of each page and the `end` token of the last page fetched ("" if the
// history was exhausted).
func paginateBackward(t *testing.T, c *client.CSAPI, roomID, from string, limit, maxPages int) (pages [][]string, end string) {
	t.Helper()
	token := from
	for i := 0; maxPages == 0 || i < maxPages; i++ {
		if i > 200 {
			ct.Fatalf(t, "paginateBackward: no end after 200 pages")
		}
		q := url.Values{}
		q.Set("dir", "b")
		q.Set("limit", fmt.Sprintf("%d", limit))
		if token != "" {
			q.Set("from", token)
		}
		res := c.MustDo(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "messages"}, client.WithQueries(q))
		body := gjson.ParseBytes(client.ParseJSON(t, res))
		var page []string
		for _, ev := range body.Get("chunk").Array() {
			page = append(page, ev.Get("event_id").Str)
		}
		pages = append(pages, page)
		next := body.Get("end")
		if !next.Exists() || next.Str == "" {
			return pages, ""
		}
		token = next.Str
	}
	return pages, token
}

func flatten(pages [][]string) []string {
	var out []string
	for _, p := range pages {
		out = append(out, p...)
	}
	return out
}

func duplicates(ids []string) []string {
	seen := map[string]int{}
	var dups []string
	for _, id := range ids {
		seen[id]++
		if seen[id] == 2 {
			dups = append(dups, id)
		}
	}
	return dups
}

// TestFederationLateEventSyncBatchOrder checks that an incremental /sync
// timeline is ordered by arrival at the homeserver, as the spec says:
//
//	"Events are ordered in this API according to the arrival time of the
//	event on the homeserver."  -- client-server API, Syncing
//
// The batch holds a local event A followed by a federated event E which
// arrives after A, is at the same depth, has the same parent, and has an
// origin_server_ts an hour older than A. Both events' parents are outside
// the batch, so any server which re-sorts the batch by DAG position with
// an origin_server_ts tie-break will put E before A.
//
// (MSC4445 proposes topological order only for initial sync / newly joined
// rooms, and keeps arrival order for incremental sync.)
func TestFederationLateEventSyncBatchOrder(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	f, cancel := newLateEventFixture(t, deployment)
	defer cancel()
	roomID := f.room.RoomID

	// Bob must have already seen the room, so the next sync is a plain
	// incremental sync rather than a "newly joined room" response.
	bobSince := f.bob.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(f.bob.UserID, roomID))

	// E: created now (same parent as A will have), backdated an hour, not sent yet.
	eventE := f.createCharlieMessage(t, "E (late, backdated)", -time.Hour, nil, 0)
	f.room.AddEvent(eventE)

	// A: local event, arrives first.
	eventA := f.alice.SendEventSynced(t, roomID, b.Event{
		Type:    "m.room.message",
		Content: map[string]interface{}{"msgtype": "m.text", "body": "A (local, first)"},
	})

	// E arrives second.
	f.srv.MustSendTransaction(t, deployment, deployment.GetFullyQualifiedHomeserverName(t, "hs1"), []json.RawMessage{eventE.JSON()}, nil)
	f.alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, eventE.EventID()))

	// One incremental sync for Bob, so A and E are in the same response.
	res, _ := f.bob.MustSync(t, client.SyncReq{
		Since:  bobSince,
		Filter: `{"room":{"timeline":{"limit":20}}}`,
	})
	ids := timelineEventIDs(res, roomID)
	t.Logf("bob incremental timeline: %v (A=%s E=%s)", ids, eventA, eventE.EventID())

	if limited := res.Get(fmt.Sprintf("rooms.join.%s.timeline.limited", client.GjsonEscape(roomID))).Bool(); limited {
		ct.Fatalf(t, "timeline unexpectedly limited; test needs A and E in one unlimited batch")
	}
	if countOf(ids, eventA) != 1 || countOf(ids, eventE.EventID()) != 1 {
		ct.Fatalf(t, "want A and E exactly once in the batch, got %v", ids)
	}
	posA, posE := -1, -1
	for i, id := range ids {
		switch id {
		case eventA:
			posA = i
		case eventE.EventID():
			posE = i
		}
	}
	if posA > posE {
		ct.Errorf(t, "incremental /sync is not in arrival order: E (arrived second, older origin_server_ts) at %d is before A (arrived first) at %d", posE, posA)
	}
}

// TestFederationLateSameDepthEventPagination covers a federated event which
// arrives (via /send, so it is a live event) after a client has already
// paginated backwards past its depth, using a stale /messages cursor.
//
// Spec-backed expectations:
//   - the event comes down incremental /sync exactly once;
//   - a fresh /messages walk from the live end contains it exactly once and
//     loses nothing;
//   - resuming the stale cursor yields no duplicates and loses no event that
//     existed before the cursor was issued.
//
// Whether the resumed (stale) walk returns the late event is not specified:
// it sorts into history the client has already read and the client received
// it via /sync. That outcome is only logged.
func TestFederationLateSameDepthEventPagination(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	f, cancel := newLateEventFixture(t, deployment)
	defer cancel()
	roomID := f.room.RoomID
	hs1 := deployment.GetFullyQualifiedHomeserverName(t, "hs1")

	bobSince := f.bob.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(f.bob.UserID, roomID))

	// M1..M10 in a linear chain.
	var msgs []string
	for i := 1; i <= 10; i++ {
		msgs = append(msgs, f.alice.SendEventSynced(t, roomID, b.Event{
			Type:    "m.room.message",
			Content: map[string]interface{}{"msgtype": "m.text", "body": fmt.Sprintf("M%d", i)},
		}))
	}
	bobSince = f.bob.MustSyncUntil(t, client.SyncReq{Since: bobSince}, client.SyncTimelineHasEventID(roomID, msgs[9]))

	// Bob scrolls back 3 pages of 3: [M10 M9 M8] [M7 M6 M5] [M4 M3 M2].
	// His cursor is now below M6's depth with M1 and the room's state
	// events still older than it.
	const limit = 3
	beforePages, staleCursor := paginateBackward(t, f.bob, roomID, "", limit, 3)
	if staleCursor == "" {
		ct.Fatalf(t, "history exhausted before the cursor got past M6; pages=%v", beforePages)
	}
	before := flatten(beforePages)
	t.Logf("pages before late event: %v, cursor=%s", beforePages, staleCursor)

	// E: child of M5, so depth(E) == depth(M6). Sent after Bob's cursor
	// passed that depth.
	m5 := f.waitForServerEvent(t, msgs[4])
	eventE := f.createCharlieMessage(t, "E (late, same depth as M6)", 0, []string{m5.EventID()}, m5.Depth()+1)
	f.srv.MustSendTransaction(t, deployment, hs1, []json.RawMessage{eventE.JSON()}, nil)

	// /sync: E exactly once. Sync until E, then until a sentinel, counting E.
	seenE := 0
	nextBatch := f.bob.MustSyncUntil(t, client.SyncReq{Since: bobSince}, func(clientUserID string, topLevelSyncJSON gjson.Result) error {
		seenE += countOf(timelineEventIDs(topLevelSyncJSON, roomID), eventE.EventID())
		if seenE == 0 {
			return fmt.Errorf("E not yet in /sync")
		}
		return nil
	})
	sentinel := f.alice.SendEventSynced(t, roomID, b.Event{
		Type:    "m.room.message",
		Content: map[string]interface{}{"msgtype": "m.text", "body": "sentinel"},
	})
	f.bob.MustSyncUntil(t, client.SyncReq{Since: nextBatch}, func(clientUserID string, topLevelSyncJSON gjson.Result) error {
		ids := timelineEventIDs(topLevelSyncJSON, roomID)
		seenE += countOf(ids, eventE.EventID())
		if countOf(ids, sentinel) == 0 {
			return fmt.Errorf("sentinel not yet in /sync")
		}
		return nil
	})
	if seenE != 1 {
		ct.Errorf(t, "late event E came down /sync %d times, want exactly 1", seenE)
	}

	// Resume the stale cursor to the start of the room.
	afterPages, _ := paginateBackward(t, f.bob, roomID, staleCursor, limit, 0)
	after := flatten(afterPages)
	t.Logf("pages resumed from stale cursor: %v", afterPages)
	combined := append(append([]string{}, before...), after...)
	if d := duplicates(combined); len(d) > 0 {
		ct.Errorf(t, "stale-cursor resume produced duplicates: %v", d)
	}
	for i, id := range msgs {
		if countOf(combined, id) != 1 {
			ct.Errorf(t, "stale-cursor walk: M%d (%s) seen %d times, want 1", i+1, id, countOf(combined, id))
		}
	}
	t.Logf("stale-cursor walk returned late event E: %v (unspecified; informational)", countOf(after, eventE.EventID()) > 0)

	// Fresh walk from the live end: E exactly once, nothing lost.
	freshPages, _ := paginateBackward(t, f.bob, roomID, "", limit, 0)
	fresh := flatten(freshPages)
	t.Logf("fresh walk: %v", freshPages)
	if d := duplicates(fresh); len(d) > 0 {
		ct.Errorf(t, "fresh /messages walk produced duplicates: %v", d)
	}
	if n := countOf(fresh, eventE.EventID()); n != 1 {
		ct.Errorf(t, "fresh /messages walk: late event E seen %d times, want 1", n)
	}
	for i, id := range append(append([]string{}, msgs...), sentinel) {
		if countOf(fresh, id) != 1 {
			ct.Errorf(t, "fresh /messages walk: event #%d (%s) seen %d times, want 1", i+1, id, countOf(fresh, id))
		}
	}
}

// TestFederationBackfillAheadOfStaleCursor covers history which a homeserver
// only learns via /backfill, landing in a part of the timeline a client has
// already paginated past.
//
// DAG (hs1's view once everything is known):
//
//	... M1 - M2 - M3 - ... - M10 - Y
//	           \                  /
//	            X1 - X2 - X3 -----
//
// The Complement server keeps the X branch hidden. Bob pages back past the
// X depths and saves his cursor. Only then does the Complement server send
// the live event Y (prev_events = [M10, X3]). It answers
// /get_missing_events with nothing and serves X3 via /event (so hs1 can
// compute state), but X1 and X2 are only available via /backfill.
//
// Expectations:
//   - Y is live: it comes down /sync exactly once. (spec)
//   - X1 and X2 are learned only via /backfill and never come down /sync.
//     (Not in the spec, but every implementation we know of behaves this way.)
//   - Resuming Bob's stale cursor yields no duplicates and loses nothing
//     older than the cursor. (spec)
//   - A fresh /messages walk from the live end contains every event,
//     including the X branch, exactly once.
//   - Whether the stale-cursor walk returns the X branch is unspecified:
//     X sorts ahead of the cursor, and nothing is sent down /sync either,
//     so a client that never reloads history may never see it. Logged only.
func TestFederationBackfillAheadOfStaleCursor(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	f, cancel := newLateEventFixture(t, deployment)
	defer cancel()
	roomID := f.room.RoomID
	hs1 := deployment.GetFullyQualifiedHomeserverName(t, "hs1")

	hb := newHiddenBranchServer(t, f)
	hb.register()

	bobSince := f.bob.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(f.bob.UserID, roomID))
	msgs := sendNumberedMessages(t, f.alice, roomID, 10)
	bobSince = f.bob.MustSyncUntil(t, client.SyncReq{Since: bobSince}, client.SyncTimelineHasEventID(roomID, msgs[9]))

	// Hidden branch X1 - X2 - X3 forking from M2, at the depths of M3..M5.
	// X1 and X2 are only served via /backfill; X3 is also served via /event.
	m2 := f.waitForServerEvent(t, msgs[1])
	m10 := f.waitForServerEvent(t, msgs[9])
	xs := hb.createHiddenChain(t, m2, 3)
	xIDs := asEventIDs(xs)

	// Bob pages back 3 pages of 3: [M10 M9 M8] [M7 M6 M5] [M4 M3 M2].
	// His cursor is now below every X depth, with M1 and the room's state
	// events still older than it.
	const limit = 3
	beforePages, staleCursor := paginateBackward(t, f.bob, roomID, "", limit, 3)
	if staleCursor == "" {
		ct.Fatalf(t, "history exhausted before the cursor got past the X depths; pages=%v", beforePages)
	}
	t.Logf("pages before Y: %v, cursor=%s", beforePages, staleCursor)

	// Y: live merge of M10 and the hidden branch.
	x3 := xs[len(xs)-1]
	eventY := f.createCharlieMessage(t, "Y (merges hidden branch)", 0,
		[]string{m10.EventID(), x3.EventID()}, max(m10.Depth(), x3.Depth())+1)
	f.room.AddEvent(eventY)
	f.srv.MustSendTransaction(t, deployment, hs1, []json.RawMessage{eventY.JSON()}, nil)

	// Every event ID Bob's /sync stream returns from here on.
	syncSeen := map[string]int{}
	bobSince = syncCollectUntil(t, f.bob, roomID, bobSince, syncSeen, eventY.EventID())

	// Resume the stale cursor. This is where hs1 is expected to backfill
	// the X branch, which sorts ahead of the cursor.
	afterPages, _ := paginateBackward(t, f.bob, roomID, staleCursor, limit, 0)
	after := flatten(afterPages)
	t.Logf("pages resumed from stale cursor: %v", afterPages)
	combined := append(flatten(beforePages), after...)
	assertNoDuplicates(t, "stale-cursor resume", combined)
	assertEachOnce(t, "stale-cursor walk", combined, msgs)
	for i, id := range xIDs {
		t.Logf("stale-cursor walk returned X%d: %v (unspecified; informational)", i+1, countOf(after, id) > 0)
	}

	// Synapse may backfill in the background, so wait until hs1 has the
	// X branch before the fresh walk; otherwise the walk could pass the X
	// depths before the branch is persisted.
	if !waitForLocalEvents(t, f.bob, roomID, xIDs, 10*time.Second) {
		t.Logf("hs1 did not persist the whole X branch within 10s")
	}

	// Fresh walk from the live end: everything exactly once, X branch included.
	freshPages, _ := paginateBackward(t, f.bob, roomID, "", limit, 0)
	fresh := flatten(freshPages)
	t.Logf("fresh walk: %v", freshPages)
	assertNoDuplicates(t, "fresh /messages walk", fresh)
	assertEachOnce(t, "fresh /messages walk", fresh, append(append(append([]string{}, msgs...), xIDs...), eventY.EventID()))

	// Drain /sync up to a sentinel, then check what came down it.
	sentinel := f.alice.SendEventSynced(t, roomID, b.Event{
		Type:    "m.room.message",
		Content: map[string]interface{}{"msgtype": "m.text", "body": "sentinel"},
	})
	syncCollectUntil(t, f.bob, roomID, bobSince, syncSeen, sentinel)
	if n := syncSeen[eventY.EventID()]; n != 1 {
		ct.Errorf(t, "live event Y came down /sync %d times, want 1", n)
	}
	for i, id := range xIDs[:len(xIDs)-1] {
		if n := syncSeen[id]; n != 0 {
			ct.Errorf(t, "X%d (%s) is only available via /backfill but came down /sync %d times", i+1, id, n)
		}
	}
	t.Logf("X3 (fetchable via /event) came down /sync %d times (informational)", syncSeen[x3.EventID()])
	hb.logRequests()
}

// TestFederationBackfilledHistoryReachableFromPrevBatch checks that history
// which hs1 backfills while a client pages back is still returned when the
// client pages back again from the same /sync `prev_batch`, as happens on every
// client reload that restores the cached sync token.
//
// The room has history from before hs1 joined, so hs1 only learns it via
// /backfill. The backfilled events are persisted after Alice's `prev_batch`
// was issued, so their stream positions are higher than the token. They are
// still older history and must not be hidden from a /messages walk that starts
// at that token. (spec: /messages from a prev_batch token returns the events
// before the timeline.)
//
// Expectations:
//   - Both walks return every history message exactly once.
//   - The second walk is not shorter than the first.
func TestFederationBackfilledHistoryReachableFromPrevBatch(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	const historyLen = 30
	f, history, cancel := newLateEventFixtureWithHistory(t, deployment, historyLen)
	defer cancel()
	roomID := f.room.RoomID

	// Serve /backfill (and the state lookups it triggers) from the room's
	// timeline.
	hb := newHiddenBranchServer(t, f)
	hb.register()
	defer hb.logRequests()

	// Alice's /sync from before any backfill: remember the room's prev_batch.
	var prevBatch string
	f.alice.MustSyncUntil(t, client.SyncReq{}, func(_ string, sync gjson.Result) error {
		pb := sync.Get("rooms.join." + client.GjsonEscape(roomID) + ".timeline.prev_batch")
		if !pb.Exists() || pb.Str == "" {
			return fmt.Errorf("no prev_batch for %s yet", roomID)
		}
		prevBatch = pb.Str
		return nil
	})
	t.Logf("prev_batch = %s", prevBatch)

	// First walk: hs1 backfills the history while we page.
	const limit = 10
	firstPages, _ := paginateBackward(t, f.alice, roomID, prevBatch, limit, 0)
	first := flatten(firstPages)
	t.Logf("first walk pages: %v", firstPages)
	assertNoDuplicates(t, "first /messages walk", first)
	assertEachOnce(t, "first /messages walk", first, history)

	// Second walk from the very same prev_batch. Everything is stored locally
	// now, so this must return the same history.
	secondPages, _ := paginateBackward(t, f.alice, roomID, prevBatch, limit, 0)
	second := flatten(secondPages)
	t.Logf("second walk pages: %v", secondPages)
	assertNoDuplicates(t, "second /messages walk from the same prev_batch", second)
	assertEachOnce(t, "second /messages walk from the same prev_batch", second, history)
	if len(second) < len(first) {
		ct.Errorf(t, "second walk returned %d events, fewer than the first walk's %d", len(second), len(first))
	}
}

// sendNumberedMessages sends M1..Mn from c into roomID, returning their IDs.
func sendNumberedMessages(t *testing.T, c *client.CSAPI, roomID string, n int) []string {
	t.Helper()
	ids := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		ids = append(ids, c.SendEventSynced(t, roomID, b.Event{
			Type:    "m.room.message",
			Content: map[string]interface{}{"msgtype": "m.text", "body": fmt.Sprintf("M%d", i)},
		}))
	}
	return ids
}

// syncCollectUntil syncs from since until untilID appears in roomID's
// timeline, adding every timeline event ID it sees to seen. Returns the new
// since token.
func syncCollectUntil(t *testing.T, c *client.CSAPI, roomID, since string, seen map[string]int, untilID string) string {
	t.Helper()
	return c.MustSyncUntil(t, client.SyncReq{Since: since}, func(_ string, res gjson.Result) error {
		for _, id := range timelineEventIDs(res, roomID) {
			seen[id]++
		}
		if seen[untilID] == 0 {
			return fmt.Errorf("%s not yet in /sync", untilID)
		}
		return nil
	})
}

// waitForLocalEvents polls the client /event API until every event in ids
// is visible on the homeserver, or timeout elapses. Returns whether all
// events became visible.
func waitForLocalEvents(t *testing.T, c *client.CSAPI, roomID string, ids []string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for _, id := range ids {
		for {
			res := c.Do(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "event", id})
			res.Body.Close()
			if res.StatusCode == 200 {
				break
			}
			if time.Now().After(deadline) {
				return false
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return true
}

func assertNoDuplicates(t *testing.T, label string, ids []string) {
	t.Helper()
	if d := duplicates(ids); len(d) > 0 {
		ct.Errorf(t, "%s produced duplicates: %v", label, d)
	}
}

func assertEachOnce(t *testing.T, label string, ids, want []string) {
	t.Helper()
	for _, id := range want {
		if n := countOf(ids, id); n != 1 {
			ct.Errorf(t, "%s: %s seen %d times, want 1", label, id, n)
		}
	}
}

// hiddenBranchServer serves federation requests for a lateEventFixture room
// so that some events (hidden) are only obtainable via /backfill, while
// others (fetchable) can also be fetched via /event. /get_missing_events
// always returns nothing, and /state_ids returns the room's current state.
type hiddenBranchServer struct {
	t            *testing.T
	f            *lateEventFixture
	mu           sync.Mutex
	hidden       map[string]gomatrixserverlib.PDU
	fetchable    map[string]gomatrixserverlib.PDU
	backfillReqs [][]string
	eventReqs    []string
}

func newHiddenBranchServer(t *testing.T, f *lateEventFixture) *hiddenBranchServer {
	return &hiddenBranchServer{
		t:         t,
		f:         f,
		hidden:    map[string]gomatrixserverlib.PDU{},
		fetchable: map[string]gomatrixserverlib.PDU{},
	}
}

func (h *hiddenBranchServer) register() {
	mux := h.f.srv.Mux()
	valid := h.f.srv.ValidFederationRequest
	mux.HandleFunc("/_matrix/federation/v1/event/{eventID}", valid(h.t, h.handleEvent))
	mux.HandleFunc("/_matrix/federation/v1/get_missing_events/{roomID}", valid(h.t, h.handleGetMissingEvents))
	mux.HandleFunc("/_matrix/federation/v1/state_ids/{roomID}", valid(h.t, h.handleStateIDs))
	mux.HandleFunc("/_matrix/federation/v1/backfill/{roomID}", valid(h.t, h.handleBackfill))
}

// createHiddenChain creates n linked messages forking from parent. All but
// the last are hidden (only via /backfill); the last is also fetchable via
// /event so the homeserver can resolve state when it is referenced as a
// prev_event.
func (h *hiddenBranchServer) createHiddenChain(t *testing.T, parent gomatrixserverlib.PDU, n int) []gomatrixserverlib.PDU {
	t.Helper()
	xs := make([]gomatrixserverlib.PDU, 0, n)
	prev, depth := parent.EventID(), parent.Depth()
	for i := 1; i <= n; i++ {
		x := h.f.createCharlieMessage(t, fmt.Sprintf("X%d (hidden branch)", i), 0, []string{prev}, depth+1)
		xs = append(xs, x)
		prev, depth = x.EventID(), x.Depth()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, x := range xs[:n-1] {
		h.hidden[x.EventID()] = x
	}
	h.fetchable[xs[n-1].EventID()] = xs[n-1]
	return xs
}

func (h *hiddenBranchServer) logRequests() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.t.Logf("/backfill requests (v=): %v", h.backfillReqs)
	h.t.Logf("/event requests: %v", h.eventReqs)
}

func (h *hiddenBranchServer) lookup(id string) (gomatrixserverlib.PDU, bool) {
	if ev, ok := h.f.room.GetEventInTimeline(id); ok {
		return ev, true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if ev, ok := h.fetchable[id]; ok {
		return ev, true
	}
	ev, ok := h.hidden[id]
	return ev, ok
}

func (h *hiddenBranchServer) txnResp(pdus []gomatrixserverlib.PDU) util.JSONResponse {
	raw := make([]json.RawMessage, 0, len(pdus))
	for _, p := range pdus {
		raw = append(raw, p.JSON())
	}
	return util.JSONResponse{Code: 200, JSON: gomatrixserverlib.Transaction{
		Origin:         h.f.srv.ServerName(),
		OriginServerTS: spec.AsTimestamp(time.Now()),
		PDUs:           raw,
	}}
}

func (h *hiddenBranchServer) wrongRoom(got string) *util.JSONResponse {
	if got == h.f.room.RoomID {
		return nil
	}
	h.t.Errorf("federation request for unexpected room %s", got)
	return &util.JSONResponse{Code: 400, JSON: map[string]string{"error": "wrong room"}}
}

func (h *hiddenBranchServer) handleEvent(_ *fclient.FederationRequest, pathParams map[string]string) util.JSONResponse {
	id := pathParams["eventID"]
	h.mu.Lock()
	h.eventReqs = append(h.eventReqs, id)
	_, isHidden := h.hidden[id]
	h.mu.Unlock()
	ev, ok := h.lookup(id)
	if !ok || isHidden {
		return util.JSONResponse{Code: 404, JSON: map[string]string{"errcode": "M_NOT_FOUND"}}
	}
	return h.txnResp([]gomatrixserverlib.PDU{ev})
}

func (h *hiddenBranchServer) handleGetMissingEvents(_ *fclient.FederationRequest, pathParams map[string]string) util.JSONResponse {
	if r := h.wrongRoom(pathParams["roomID"]); r != nil {
		return *r
	}
	return util.JSONResponse{Code: 200, JSON: map[string]interface{}{"events": []interface{}{}}}
}

func (h *hiddenBranchServer) handleStateIDs(_ *fclient.FederationRequest, pathParams map[string]string) util.JSONResponse {
	if r := h.wrongRoom(pathParams["roomID"]); r != nil {
		return *r
	}
	// No state changes happen after the joins, so the state at any hidden
	// event is the room's current state.
	state := h.f.room.AllCurrentState()
	return util.JSONResponse{Code: 200, JSON: map[string][]string{
		"pdu_ids":        asEventIDs(state),
		"auth_chain_ids": asEventIDs(h.f.room.AuthChainForEvents(state)),
	}}
}

func (h *hiddenBranchServer) handleBackfill(fr *fclient.FederationRequest, pathParams map[string]string) util.JSONResponse {
	if r := h.wrongRoom(pathParams["roomID"]); r != nil {
		return *r
	}
	req, err := fr.HTTPRequest()
	if err != nil {
		return util.JSONResponse{Code: 500, JSON: err.Error()}
	}
	from := req.URL.Query()["v"]
	limit := 100
	if l, err := strconv.Atoi(req.URL.Query().Get("limit")); err == nil && l > 0 {
		limit = l
	}
	h.mu.Lock()
	h.backfillReqs = append(h.backfillReqs, from)
	h.mu.Unlock()
	return h.txnResp(h.walkBack(from, limit))
}

// walkBack does a breadth-first walk back along prev_events from the given
// events (inclusive), returning at most limit events.
func (h *hiddenBranchServer) walkBack(from []string, limit int) []gomatrixserverlib.PDU {
	var out []gomatrixserverlib.PDU
	seen := map[string]bool{}
	queue := append([]string{}, from...)
	for len(queue) > 0 && len(out) < limit {
		id := queue[0]
		queue = queue[1:]
		if seen[id] {
			continue
		}
		seen[id] = true
		if ev, ok := h.lookup(id); ok {
			out = append(out, ev)
			queue = append(queue, ev.PrevEventIDs()...)
		}
	}
	return out
}

// TestFederationMessagesDoesNotBackfillNewerGaps checks that a backward
// /messages request positioned before every stored event ends the history
// instead of backfilling from backward extremities that sit later in the room.
// Backfilling one of those returns events newer than the cursor, and clients
// then place that block on the wrong side of the timeline (for example, recent
// messages above the room's create event).
func TestFederationMessagesDoesNotBackfillNewerGaps(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	const historyLen = 30
	f, _, cancel := newLateEventFixtureWithHistory(t, deployment, historyLen)
	defer cancel()
	roomID := f.room.RoomID

	// Serve /backfill from the test so the test can tell whether it is called
	// at all, and let Alice see the room so her join is in hs1's timeline.
	hb := newHiddenBranchServer(t, f)
	hb.register()
	defer hb.logRequests()
	f.alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(f.alice.UserID, roomID))

	// hs1 holds only the join, so its backward extremity (the join's missing
	// prev event) sits at the join's depth. Both cursors are older than that.
	for _, from := range []string{"t1_0", "t2_0"} {
		q := url.Values{}
		q.Set("dir", "b")
		q.Set("limit", "10")
		q.Set("from", from)
		res := f.alice.MustDo(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "messages"}, client.WithQueries(q))
		body := gjson.ParseBytes(client.ParseJSON(t, res))
		if chunk := body.Get("chunk"); chunk.Exists() && len(chunk.Array()) > 0 {
			ct.Errorf(t, "backward /messages from %s returned %d events newer than the cursor: %s", from, len(chunk.Array()), chunk.Raw)
		}
	}

	hb.mu.Lock()
	reqs := append([][]string(nil), hb.backfillReqs...)
	hb.mu.Unlock()
	if len(reqs) > 0 {
		ct.Errorf(t, "backward /messages before all stored history backfilled newer gaps: %v", reqs)
	}
}
