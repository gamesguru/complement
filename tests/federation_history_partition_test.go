//go:build !venator_blacklist

// Venator: does not yet implement federation

package tests

import (
	"encoding/json"
	"fmt"
	"sort"
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
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/ct"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
)

// These tests model a real production room: a federated room with years of
// history, in which the homeserver under test has two kinds of hole in its view
// of the timeline.
//
//   - A "wedged" hole low in the history. The remote server has the events
//     around it but cannot serve one event, so any backfill that reaches it can
//     never complete (a hidden parent that /event, /backfill and /state_ids all
//     refuse).
//   - A "partition" hole higher up: a long stretch of history, longer than the
//     /get_missing_events limit, with a forked DAG and several state events in
//     the middle of it, which the homeserver never received because it was not
//     in the room (or was partitioned from it) at the time.
//
// The homeserver must still fill the partition hole. A hole it cannot fill
// must not stop it from filling the ones above it, and /get_missing_events
// answers that are truncated by the limit and by a forked DAG must not be taken
// as having closed a gap they did not close.
//
// The room, oldest event on the left, newest on the right:
//
//	 create                wedged             partition hole               tip
//	   |                     |           (> /get_missing_events limit)      |
//	   v                     v          .-----------------------------.     v
//	[old 1..4]--[lost]--[above 1..6]--[ p1..p12 ]-(dave joins)-<fork>-[ p13..p24 ]--[recent 1..3]
//	             ^^^^                  '-----------------------------'
//	  /event, /backfill, /state_ids       homeserver never received these;
//	  all refuse it: backfill dies        it must fill them from the tip
//	  here, every time                    with /get_missing_events
//
// Legend: [x] = events the remote can serve, [lost] = events it cannot.

// realRoom is a Complement-server-owned room whose complete DAG is kept in
// `all`, and which serves /event, /backfill, /state_ids and
// /get_missing_events from it, except for events listed in `lost`.
type realRoom struct {
	*lateEventFixture
	deployment complement.Deployment
	tb         *testing.T

	mu   sync.Mutex
	all  map[string]gomatrixserverlib.PDU
	lost map[string]bool

	gmeLimits     []int
	gmeHandlerDur []time.Duration // handler time per /get_missing_events (diagnostic)
	backfillFroms [][]string
	stateIDsFor   []string
}

// gmeServedLimit mirrors the cap real servers apply to /get_missing_events.
const gmeServedLimit = 20

func newRealRoom(t *testing.T, deployment complement.Deployment, joinBeforeBuild bool, build func(rr *realRoom)) (*realRoom, string, func()) {
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
	alias := f.srv.MakeAliasMapping("history-partition", f.room.RoomID)

	rr := &realRoom{
		lateEventFixture: f,
		deployment:       deployment,
		tb:               t,
		all:              map[string]gomatrixserverlib.PDU{},
		lost:             map[string]bool{},
	}
	for _, ev := range f.room.Timeline {
		rr.all[ev.EventID()] = ev
	}
	rr.register()

	join := func() { f.alice.MustJoinRoom(t, alias, []spec.ServerName{f.srv.ServerName()}) }
	if joinBeforeBuild {
		join()
	}
	build(rr)
	if !joinBeforeBuild {
		join()
	}
	return rr, f.room.RoomID, cancel
}

// event creates a message from charlie. A nil prev means "the room's forward
// extremities". main=false leaves it off the room's main line (it is a side
// branch that a later event merges), but it is still served.
func (rr *realRoom) event(t *testing.T, body string, prev []string, depth int64, main bool) gomatrixserverlib.PDU {
	t.Helper()
	ev := rr.createCharlieMessage(t, body, 0, prev, depth)
	rr.mu.Lock()
	rr.all[ev.EventID()] = ev
	rr.mu.Unlock()
	if main {
		rr.room.AddEvent(ev)
	}
	return ev
}

// remoteJoin makes a second remote user join: a state event in the middle of history,
// which the homeserver will receive as part of the room state when it joins
// (stored without a timeline position), not as history.
func (rr *realRoom) remoteJoin(t *testing.T, localpart string) gomatrixserverlib.PDU {
	t.Helper()
	user := rr.srv.UserID(localpart)
	ev := rr.srv.MustCreateEvent(t, rr.room, federation.Event{
		Sender:   user,
		Type:     "m.room.member",
		StateKey: &user,
		Content:  map[string]interface{}{"membership": "join"},
	})
	rr.mu.Lock()
	rr.all[ev.EventID()] = ev
	rr.mu.Unlock()
	rr.room.AddEvent(ev)
	return ev
}

func (rr *realRoom) register() {
	mux := rr.srv.Mux()
	valid := rr.srv.ValidFederationRequest
	mux.HandleFunc("/_matrix/federation/v1/event/{eventID}", valid(rr.tb, rr.handleEvent))
	mux.HandleFunc("/_matrix/federation/v1/backfill/{roomID}", valid(rr.tb, rr.handleBackfill))
	mux.HandleFunc("/_matrix/federation/v1/state_ids/{roomID}", valid(rr.tb, rr.handleStateIDs))
	mux.HandleFunc("/_matrix/federation/v1/get_missing_events/{roomID}", valid(rr.tb, rr.handleGetMissingEvents))
}

func (rr *realRoom) lookup(id string) (gomatrixserverlib.PDU, bool) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	if rr.lost[id] {
		return nil, false
	}
	ev, ok := rr.all[id]
	return ev, ok
}

func (rr *realRoom) txn(pdus []gomatrixserverlib.PDU) util.JSONResponse {
	raw := make([]json.RawMessage, 0, len(pdus))
	for _, p := range pdus {
		raw = append(raw, p.JSON())
	}
	return util.JSONResponse{Code: 200, JSON: gomatrixserverlib.Transaction{
		Origin:         rr.srv.ServerName(),
		OriginServerTS: spec.AsTimestamp(time.Now()),
		PDUs:           raw,
	}}
}

func notFound() util.JSONResponse {
	return util.JSONResponse{Code: 404, JSON: map[string]string{"errcode": "M_NOT_FOUND", "error": "not found"}}
}

func (rr *realRoom) handleEvent(_ *fclient.FederationRequest, pathParams map[string]string) util.JSONResponse {
	ev, ok := rr.lookup(pathParams["eventID"])
	if !ok {
		return notFound()
	}
	return rr.txn([]gomatrixserverlib.PDU{ev})
}

// handleBackfill walks breadth-first back along prev_events, as real servers
// do, so a forked DAG spends the limit on both branches. An event that is lost
// ends its branch: nothing behind it is reachable through it.
func (rr *realRoom) handleBackfill(fr *fclient.FederationRequest, _ map[string]string) util.JSONResponse {
	req, err := fr.HTTPRequest()
	if err != nil {
		return util.JSONResponse{Code: 500, JSON: err.Error()}
	}
	from := req.URL.Query()["v"]
	limit := 100
	if l, convErr := strconv.Atoi(req.URL.Query().Get("limit")); convErr == nil && l > 0 {
		limit = l
	}
	rr.mu.Lock()
	rr.backfillFroms = append(rr.backfillFroms, from)
	rr.mu.Unlock()

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
		if ev, ok := rr.lookup(id); ok {
			out = append(out, ev)
			queue = append(queue, ev.PrevEventIDs()...)
		}
	}
	ids := make([]string, 0, len(out))
	for _, ev := range out {
		ids = append(ids, ev.EventID())
	}
	rr.tb.Logf("/backfill: v=%v limit=%d answering %d events: %v", from, limit, len(out), ids)
	return rr.txn(out)
}

// handleStateIDs returns the room's current state for any event that can be
// served. No state event is replaced after the first of the tests' state
// events, so the current state is a faithful state at every event that matters.
// It refuses events that are lost.
func (rr *realRoom) handleStateIDs(fr *fclient.FederationRequest, _ map[string]string) util.JSONResponse {
	req, err := fr.HTTPRequest()
	if err != nil {
		return util.JSONResponse{Code: 500, JSON: err.Error()}
	}
	eventID := req.URL.Query().Get("event_id")
	rr.mu.Lock()
	rr.stateIDsFor = append(rr.stateIDsFor, eventID)
	lost := rr.lost[eventID]
	rr.mu.Unlock()
	if lost {
		return notFound()
	}
	state := rr.room.AllCurrentState()
	return util.JSONResponse{Code: 200, JSON: map[string][]string{
		"pdu_ids":        asEventIDs(state),
		"auth_chain_ids": asEventIDs(rr.room.AuthChainForEvents(state)),
	}}
}

// handleGetMissingEvents behaves like a real server: a breadth-first walk back
// from latest_events that does not expand events the caller already has
// (earliest_events), capped at gmeServedLimit, oldest first. In a forked DAG,
// the walk spends the cap on the branches in breadth-first order, so the answer
// can hold the newest part of a long chain and omit the middle of it.
//
// Walk order (numbers are the order events are visited; the cap cuts the walk
// off before it reaches the oldest events, so the answer is a suffix of the
// stretch, not all of it):
//
//	latest_events ──> 1 ──> 2 ──> 3 ... (cap reached: stop)
//	                                    older events never visited
//	earliest_events ─> already held by the caller; not expanded
//
// In the fork, both branches are visited level by level, so the cap is spent
// on both at once:
//
//	        ┌─ a3 (3) ─ a2 (5) ─ a1 (7) ─┐
//	merge (1)                             base (9)
//	        └─ b3 (2) ─ b2 (4) ─ b1 (6) ─┘
func (rr *realRoom) handleGetMissingEvents(fr *fclient.FederationRequest, _ map[string]string) util.JSONResponse {
	handlerStart := time.Now()
	defer func() {
		rr.mu.Lock()
		rr.gmeHandlerDur = append(rr.gmeHandlerDur, time.Since(handlerStart))
		rr.mu.Unlock()
	}()
	body := gjson.ParseBytes(fr.Content())
	limit := int(body.Get("limit").Int())
	if limit <= 0 || limit > gmeServedLimit {
		limit = gmeServedLimit
	}
	rr.mu.Lock()
	rr.gmeLimits = append(rr.gmeLimits, limit)
	rr.mu.Unlock()

	seen := map[string]bool{}
	for _, e := range body.Get("earliest_events").Array() {
		seen[e.Str] = true
	}
	var queue []string
	for _, l := range body.Get("latest_events").Array() {
		ev, ok := rr.lookup(l.Str)
		rr.tb.Logf("/get_missing_events: latest=%s servable=%v earliest=%d", l.Str, ok, len(seen))
		if ok {
			queue = append(queue, ev.PrevEventIDs()...)
			for _, pid := range ev.PrevEventIDs() {
				_, pok := rr.lookup(pid)
				rr.tb.Logf("/get_missing_events:   prev %s servable=%v inEarliest=%v", pid, pok, seen[pid])
			}
		}
	}
	var out []gomatrixserverlib.PDU
	for len(queue) > 0 && len(out) < limit {
		id := queue[0]
		queue = queue[1:]
		if seen[id] {
			continue
		}
		seen[id] = true
		ev, ok := rr.lookup(id)
		if !ok {
			continue
		}
		out = append(out, ev)
		queue = append(queue, ev.PrevEventIDs()...)
	}
	rr.tb.Logf("/get_missing_events: answering %d events", len(out))
	sort.SliceStable(out, func(i, j int) bool { return out[i].Depth() < out[j].Depth() })
	raw := make([]json.RawMessage, 0, len(out))
	for _, ev := range out {
		raw = append(raw, ev.JSON())
	}
	return util.JSONResponse{Code: 200, JSON: map[string]interface{}{"events": raw}}
}

func (rr *realRoom) logRequests(t *testing.T) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	t.Logf("/get_missing_events limits served: %v", rr.gmeLimits)
	if n := len(rr.gmeHandlerDur); n > 0 {
		var sum, max time.Duration
		for _, d := range rr.gmeHandlerDur {
			sum += d
			if d > max {
				max = d
			}
		}
		t.Logf("/get_missing_events handler time (fixture side only): %d calls, total %s, avg %s, max %s",
			n, sum.Round(time.Millisecond), (sum / time.Duration(n)).Round(time.Microsecond), max.Round(time.Microsecond))
	}
	t.Logf("/backfill requests (v=): %v", rr.backfillFroms)
	t.Logf("/state_ids requests (event_id=): %v", rr.stateIDsFor)
}

// partitionHole builds the partition stretch: a long linear run, a fork that
// is merged again, a state event in the middle, and a second long run. It
// returns every timeline event of the stretch (oldest first by depth), the ID of
// the state-only join in the middle of it, and the tip.
//
//	p1 ─ p2 ─ ... ─ p12 ─ dave ─┬─ a1 ─ a2 ─ a3 ─┬─ merge ─ p13 ─ ... ─ p24
//	                            │  (side branch)  │
//	                            └─ b1 ─ b2 ─ b3 ─┘
//	                               (main line)
//
//	 dave = m.room.member join: delivered to the homeserver as room state
//	        on join, with no timeline position.
//	 a1-a3 are served but not on the room's main line; merge has both
//	 a3 and b3 as prev_events.
func (rr *realRoom) partitionHole(t *testing.T) (ids []string, dave string, tip gomatrixserverlib.PDU) {
	t.Helper()
	add := func(ev gomatrixserverlib.PDU) { ids = append(ids, ev.EventID()) }

	var last gomatrixserverlib.PDU
	for i := 1; i <= 12; i++ {
		last = rr.event(t, fmt.Sprintf("partition %d", i), nil, 0, true)
		add(last)
	}
	// A state event in the middle of the history: the homeserver receives it as
	// state when it joins, without any position in the timeline.
	daveJoin := rr.remoteJoin(t, "dave")
	dave = daveJoin.EventID()
	last = daveJoin

	// A fork from the last event: branch a (side) and branch b (main line),
	// three events each, merged by one event with both tips as prev_events.
	base := last
	prevA, depthA := base.EventID(), base.Depth()
	var tipA gomatrixserverlib.PDU
	for i := 1; i <= 3; i++ {
		tipA = rr.event(t, fmt.Sprintf("branch a %d", i), []string{prevA}, depthA+1, false)
		add(tipA)
		prevA, depthA = tipA.EventID(), tipA.Depth()
	}
	var tipB gomatrixserverlib.PDU
	prevB, depthB := base.EventID(), base.Depth()
	for i := 1; i <= 3; i++ {
		tipB = rr.event(t, fmt.Sprintf("branch b %d", i), []string{prevB}, depthB+1, true)
		add(tipB)
		prevB, depthB = tipB.EventID(), tipB.Depth()
	}
	merge := rr.event(t, "merge", []string{tipA.EventID(), tipB.EventID()}, max(tipA.Depth(), tipB.Depth())+1, true)
	add(merge)

	last = merge
	for i := 13; i <= 24; i++ {
		last = rr.event(t, fmt.Sprintf("partition %d", i), nil, 0, true)
		add(last)
	}
	return ids, dave, last
}

// walkAll pages /messages backwards from `from` until the history is
// exhausted, returning every event ID in the order returned.
func walkAll(t *testing.T, c *client.CSAPI, roomID, from string) []string {
	t.Helper()
	pages, _ := paginateBackward(t, c, roomID, from, 10, 0)
	return flatten(pages)
}

// assertTopologicalNewestFirst checks that for every returned event, each of
// its prev_events that is also returned comes later in the (newest first)
// walk.
func assertTopologicalNewestFirst(t *testing.T, rr *realRoom, label string, walk []string) {
	t.Helper()
	index := map[string]int{}
	for i, id := range walk {
		index[id] = i
	}
	for i, id := range walk {
		ev, ok := rr.lookup(id)
		if !ok {
			continue
		}
		for _, p := range ev.PrevEventIDs() {
			if j, ok := index[p]; ok && j < i {
				ct.Errorf(t, "%s: event %s (position %d) is returned after its prev_event %s (position %d)", label, id, i, p, j)
			}
		}
	}
}

func missingFrom(want, got []string) []string {
	have := map[string]bool{}
	for _, id := range got {
		have[id] = true
	}
	var missing []string
	for _, id := range want {
		if !have[id] {
			missing = append(missing, id)
		}
	}
	return missing
}

// TestFederationJoinedRoomFillsPartitionHoleBehindWedgedGap models the room as
// it was on the day it broke. hs1 joins a room with a long history. The history
// has an old hole the remote cannot serve, then a run of events that backfill
// can reach, then the partition stretch (longer than the
// /get_missing_events limit, forked, with a state event inside it), then the
// newest events. hs1 learns the state events from the join, with no timeline
// around them.
//
// A client that pages back from its first sync token (a cursor of depth 0, as
// for any room joined over federation) must be shown the whole partition
// stretch, exactly once, in order. An old gap that cannot be filled must not
// keep the newer ones from being filled: before the fix every /messages
// request spent its whole backfill budget retrying the old gap and returned
// "history gap not yet closed", while the partition stretch, which a request
// starting above the old gap filled in one go, was never reached.
//
//	Before the fix (every /messages request):
//
//	  client ── /messages ──> hs1 ── /backfill ──> [lost]  ✗ retry, budget spent
//	                                  partition hole never reached
//	                          <── "history gap not yet closed"
//
//	After the fix:
//
//	  client ── /messages ──> hs1 ── /backfill ──> [lost]  ✗ give up on this gap
//	                              └─ /backfill / /get_missing_events ─> partition hole ✓
//	                          <── whole stretch, once, in order
func TestFederationJoinedRoomFillsPartitionHoleBehindWedgedGap(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	var oldIDs, partition, recent []string
	var wedged string
	rr, roomID, cancel := newRealRoom(t, deployment, false, func(rr *realRoom) {
		// Old history, then one event the remote can never serve: a hole every
		// backfill that reaches it runs into.
		for i := 1; i <= 4; i++ {
			oldIDs = append(oldIDs, rr.event(t, fmt.Sprintf("old %d", i), nil, 0, true).EventID())
		}
		lost := rr.event(t, "lost", nil, 0, true)
		wedged = lost.EventID()
		rr.mu.Lock()
		rr.lost[wedged] = true
		rr.mu.Unlock()
		// History above the wedged hole that backfill can reach.
		for i := 1; i <= 6; i++ {
			oldIDs = append(oldIDs, rr.event(t, fmt.Sprintf("above the wedge %d", i), nil, 0, true).EventID())
		}
		partition, _, _ = rr.partitionHole(t)
		for i := 1; i <= 3; i++ {
			recent = append(recent, rr.event(t, fmt.Sprintf("recent %d", i), nil, 0, true).EventID())
		}
	})
	defer cancel()
	defer rr.logRequests(t)

	t.Logf("fixture: old=%v wedged=%s recent=%v", oldIDs, wedged, recent)
	for i, id := range partition {
		t.Logf("fixture: partition[%d]=%s", i, id)
	}

	var prevBatch string
	rr.alice.MustSyncUntil(t, client.SyncReq{}, func(_ string, sync gjson.Result) error {
		pb := sync.Get("rooms.join." + client.GjsonEscape(roomID) + ".timeline.prev_batch")
		if !pb.Exists() || pb.Str == "" {
			return fmt.Errorf("no prev_batch for %s yet", roomID)
		}
		prevBatch = pb.Str
		return nil
	})

	// The first walk may need several requests while hs1 backfills; a client
	// retries until the history is complete, so allow a few walks and require
	// that the partition stretch shows up.
	var walk []string
	for attempt := 1; attempt <= 6; attempt++ {
		walk = walkAll(t, rr.alice, roomID, prevBatch)
		if len(missingFrom(partition, walk)) == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Logf("walk returned %d events", len(walk))

	if missing := missingFrom(partition, walk); len(missing) > 0 {
		have := map[string]bool{}
		for _, id := range walk {
			have[id] = true
		}
		var idx []int
		for i, id := range partition {
			if !have[id] {
				idx = append(idx, i)
			}
		}
		t.Logf("partition indexes missing from the walk (0 = oldest): %v; wedged=%s", idx, wedged)
		ct.Errorf(t, "the partition stretch is missing %d of %d events after paging back (an unfillable older gap must not block it): %v",
			len(missing), len(partition), missing)
	}
	assertNoDuplicates(t, "/messages walk", walk)
	assertTopologicalNewestFirst(t, rr, "/messages walk", walk)

	// What backfill can reach above the wedged hole must also be there.
	if missing := missingFrom(append(append([]string{}, oldIDs[4:]...), recent...), walk); len(missing) > 0 {
		ct.Errorf(t, "reachable history is missing %d events: %v", len(missing), missing)
	}
}

// TestFederationPartitionHealsOverForkedMissingEvents is the live version of
// the same fault. hs1 is in the room. The Complement server is partitioned from
// hs1 while it creates the partition stretch, then delivers one live event
// whose prev_events lead into it. hs1 has to find the stretch with
// /get_missing_events, which the server answers like a real one: capped at 20
// events, breadth first through the fork, oldest first. A single answer
// therefore holds the newest part of the stretch, not all of it, and may start
// with events hs1 already has. hs1 must not treat that answer as having closed
// the gap.
//
// Expected: afterwards the client sees every event of the stretch, once, in
// topological order, in /messages and no event is silently skipped.
//
//	time ───────────────────────────────────────────────────────────>
//
//	server  [before] ──────── [partition stretch, 32 events] ──── [live]
//	            │                 (created, never delivered)          │
//	            │ delivered              ╳ partition ╳                │ delivered
//	            v                                                     v
//	hs1     [before] ·················································· [live]
//	                                                                  │
//	              /get_missing_events (latest=[live], earliest=[before])
//	                                                                  │
//	              answer 1: newest 20 only (limit), fork spends the cap
//	              answer 2..n: hs1 keeps asking until `before` is reached
//	                                                                  v
//	client  /messages: before, the 32-event stretch (with fork), live  — once, in order
func TestFederationPartitionHealsOverForkedMissingEvents(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)
	hs1 := deployment.GetFullyQualifiedHomeserverName(t, "hs1")

	var partition []string
	rr, roomID, cancel := newRealRoom(t, deployment, true, func(rr *realRoom) {
		// A message hs1 does receive, so it holds a recent event of the room.
		before := rr.event(t, "before the partition", nil, 0, true)
		rr.srv.MustSendTransaction(t, deployment, hs1, []json.RawMessage{before.JSON()}, nil)
	})
	defer cancel()
	defer rr.logRequests(t)

	// hs1 holds "before the partition" once it shows up in its sync.
	rr.alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHas(roomID, func(ev gjson.Result) bool {
		return ev.Get("content.body").Str == "before the partition"
	}))

	// The partition: the stretch is created and never delivered.
	var dave string
	partition, dave, _ = rr.partitionHole(t)

	// The partition heals with one live event.
	live := rr.event(t, "first event after the partition", nil, 0, true)
	rr.srv.MustSendTransaction(t, deployment, hs1, []json.RawMessage{live.JSON()}, nil)

	rr.alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, live.EventID()))

	// hs1 fetches the stretch with /get_missing_events, so the join in the middle
	// of it arrives as a timeline event too.
	want := append(append([]string{}, partition...), dave, live.EventID())
	var walk []string
	for attempt := 1; attempt <= 6; attempt++ {
		walk = walkAll(t, rr.alice, roomID, "")
		if len(missingFrom(want, walk)) == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if missing := missingFrom(want, walk); len(missing) > 0 {
		ct.Errorf(t, "after the partition healed, %d of %d events are missing from /messages: %v", len(missing), len(want), missing)
	}
	assertNoDuplicates(t, "/messages walk", walk)
	assertTopologicalNewestFirst(t, rr, "/messages walk", walk)

	// The stretch is longer than the served cap, so recovering it takes more
	// than one /get_missing_events answer; with fewer it was found another way
	// and this test is not exercising a truncated answer.
	rr.mu.Lock()
	gme := len(rr.gmeLimits)
	rr.mu.Unlock()
	if gme < 2 {
		ct.Errorf(t, "hs1 sent %d /get_missing_events requests, want at least 2 for a %d-event stretch capped at %d",
			gme, len(want)-1, gmeServedLimit)
	}
}
