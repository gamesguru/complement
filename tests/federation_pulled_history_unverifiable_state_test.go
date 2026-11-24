//go:build !venator_blacklist

// Venator: does not yet implement federation

package tests

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/gomatrixserverlib/fclient"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/matrix-org/util"
	"github.com/tidwall/sjson"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/ct"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
)

// TestPulledHistoryDoesNotRefetchUnverifiableStateEvent is the pull-path
// counterpart of TestUnverifiableStateEventIsNotRefetchedForEveryGap.
//
// hs1 joins a room with a long history and paginates /messages backwards, so
// all of the history is pulled over /backfill in several batches. Whenever a
// batch ends at an event whose parent hs1 does not have, hs1 asks /state_ids
// for the state at that parent and fetches the state events it lacks. One state
// event listed there is served with an invalid signature, so it can never be
// verified.
//
//	hs1 joins after:  [h1]--[h2]-- ... --[h250]
//	                    \
//	                     (X)   unverifiable state event: listed by /state_ids
//	                           for every event, served by /event with a bad
//	                           signature, and never part of the backfilled DAG
//
// Expected:
//
//  1. Progress. Pagination terminates, never reports "still fetching" (every
//     message can be served), and returns every message exactly once. A
//     homeserver that "finishes" the sweep by dropping the batches whose state
//     it cannot complete fails here, not on the request counts.
//  2. The unverifiable event is fetched a bounded number of times, not once per
//     batch.
//  3. The whole sweep finishes within a deliberately generous deadline. It is
//     there to catch a backoff sleep or a lock stall, not to measure speed.
func TestPulledHistoryDoesNotRefetchUnverifiableStateEvent(t *testing.T) {
	const total = 250
	// One fetch is expected; one more is tolerated for a fetch already in
	// flight when the first failure comes back.
	const maxUnverifiableFetches = 2
	const sweepDeadline = 90 * time.Second

	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	srv := federation.NewServer(t, deployment,
		federation.HandleKeyRequests(),
		federation.HandleMakeSendJoinRequests(),
		federation.HandleTransactionRequests(nil, nil),
	)
	srv.UnexpectedRequestsAreErrors = false
	cancel := srv.Listen()
	defer cancel()

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	ver := alice.GetDefaultRoomVersion(t)
	charlie := srv.UserID("charlie")
	room := srv.MustMakeRoom(t, ver, federation.InitialRoomEvents(ver, charlie))
	alias := srv.MakeAliasMapping("pulled-unverifiable", room.RoomID)

	all := map[string]gomatrixserverlib.PDU{}
	for _, ev := range room.Timeline {
		all[ev.EventID()] = ev
	}
	var history []string
	for i := 1; i <= total; i++ {
		ev := srv.MustCreateEvent(t, room, federation.Event{
			Type:    "m.room.message",
			Sender:  charlie,
			Content: map[string]interface{}{"msgtype": "m.text", "body": fmt.Sprintf("history %d", i)},
		})
		room.AddEvent(ev)
		all[ev.EventID()] = ev
		history = append(history, ev.EventID())
	}

	// The unverifiable state event hangs off the first message and is never
	// added to the room, so it is not reachable through /backfill and is not in
	// the state hs1 gets when it joins. Only /state_ids will mention it.
	emptyStateKey := ""
	unverifiable := srv.MustCreateEvent(t, room, federation.Event{
		Type:       "org.example.unverifiable",
		Sender:     charlie,
		StateKey:   &emptyStateKey,
		Content:    map[string]interface{}{"note": "served with an invalid signature"},
		PrevEvents: []string{history[0]},
	})
	// Event IDs do not cover signatures, so the corrupted copy keeps its ID.
	badSig := base64.RawStdEncoding.EncodeToString(make([]byte, 64))
	unverifiableJSON, err := sjson.SetBytes(
		unverifiable.JSON(),
		"signatures",
		map[string]interface{}{
			string(srv.ServerName()): map[string]interface{}{string(srv.KeyID): badSig},
		},
	)
	if err != nil {
		t.Fatalf("failed to corrupt the signature: %s", err)
	}
	t.Logf("unverifiable state event: %s", unverifiable.EventID())

	var stateIDsRequests, unverifiableFetches, backfillRequests int32
	txn := func(pdus ...json.RawMessage) util.JSONResponse {
		return util.JSONResponse{Code: 200, JSON: gomatrixserverlib.Transaction{
			Origin:         srv.ServerName(),
			OriginServerTS: spec.AsTimestamp(time.Now()),
			PDUs:           pdus,
		}}
	}
	notFoundResponse := util.JSONResponse{Code: 404, JSON: map[string]string{"errcode": "M_NOT_FOUND", "error": "not found"}}
	valid := srv.ValidFederationRequest
	mux := srv.Mux()

	mux.HandleFunc("/_matrix/federation/v1/event/{eventID}", valid(t, func(_ *fclient.FederationRequest, pathParams map[string]string) util.JSONResponse {
		eventID := pathParams["eventID"]
		if eventID == unverifiable.EventID() {
			atomic.AddInt32(&unverifiableFetches, 1)
			return txn(unverifiableJSON)
		}
		if ev, ok := all[eventID]; ok {
			return txn(ev.JSON())
		}
		return notFoundResponse
	}))

	// Walk breadth-first back along prev_events, as real servers do.
	mux.HandleFunc("/_matrix/federation/v1/backfill/{roomID}", valid(t, func(fr *fclient.FederationRequest, _ map[string]string) util.JSONResponse {
		atomic.AddInt32(&backfillRequests, 1)
		req, err := fr.HTTPRequest()
		if err != nil {
			return util.JSONResponse{Code: 500, JSON: err.Error()}
		}
		limit := 100
		if l, convErr := strconv.Atoi(req.URL.Query().Get("limit")); convErr == nil && l > 0 {
			limit = l
		}
		queue := append([]string{}, req.URL.Query()["v"]...)
		seen := map[string]bool{}
		var out []json.RawMessage
		for len(queue) > 0 && len(out) < limit {
			id := queue[0]
			queue = queue[1:]
			if seen[id] {
				continue
			}
			seen[id] = true
			if ev, ok := all[id]; ok {
				out = append(out, ev.JSON())
				queue = append(queue, ev.PrevEventIDs()...)
			}
		}
		return txn(out...)
	}))

	// The state at any event in the history: the room's state plus the
	// unverifiable event.
	mux.HandleFunc("/_matrix/federation/v1/state_ids/{roomID}", valid(t, func(_ *fclient.FederationRequest, _ map[string]string) util.JSONResponse {
		atomic.AddInt32(&stateIDsRequests, 1)
		state := room.AllCurrentState()
		pduIDs := append(asEventIDs(state), unverifiable.EventID())
		return util.JSONResponse{Code: 200, JSON: map[string][]string{
			"pdu_ids":        pduIDs,
			"auth_chain_ids": asEventIDs(room.AuthChainForEvents(state)),
		}}
	}))

	alice.MustJoinRoom(t, alias, []spec.ServerName{srv.ServerName()})
	roomID := room.RoomID

	start := time.Now()
	cursor := joinedPrevBatch(t, alice, roomID)

	var newestFirst []string
	for page := 0; ; page++ {
		if page > 200 {
			ct.Fatalf(t, "backward pagination did not terminate after %d pages", page)
		}
		if elapsed := time.Since(start); elapsed > sweepDeadline {
			ct.Fatalf(t, "the backward sweep was still running after %s (%d events so far): hs1 is stuck, not just slow",
				elapsed, len(newestFirst))
		}
		ids, end, stillFetching := backwardPage(t, alice, roomID, cursor, 10)
		if stillFetching {
			ct.Fatalf(t, "backward /messages was still being fetched after retries, but every message can be served (%d events so far)",
				len(newestFirst))
		}
		newestFirst = append(newestFirst, ids...)
		if end == "" {
			break
		}
		cursor = end
	}
	elapsed := time.Since(start)

	want := map[string]bool{}
	for _, id := range history {
		want[id] = true
	}
	var got []string
	for _, id := range newestFirst {
		if want[id] {
			got = append(got, id)
		}
	}

	states := atomic.LoadInt32(&stateIDsRequests)
	fetches := atomic.LoadInt32(&unverifiableFetches)
	t.Logf("sweep took %s: %d /backfill, %d /state_ids, %d fetches of the unverifiable event; %d of %d messages returned",
		elapsed, atomic.LoadInt32(&backfillRequests), states, fetches, len(got), total)

	// Progress and outcomes first: they say whether the sweep really finished.
	assertNoDuplicates(t, "backward /messages", got)
	if missing := missingFrom(history, got); len(missing) > 0 {
		ct.Errorf(t, "backward /messages never returned %d of %d messages (the client is left with a hole): %v",
			len(missing), total, missing)
	}

	// The fixture only means something if hs1 really did recover state.
	if states < 1 {
		t.Fatalf("hs1 never asked for /state_ids during the sweep, so the unverifiable state event was never reached")
	}
	if fetches > maxUnverifiableFetches {
		t.Errorf("hs1 fetched the unverifiable event %s %d times across %d /state_ids recoveries (at most %d expected): "+
			"a fetch that cannot succeed is being repeated for every batch",
			unverifiable.EventID(), fetches, states, maxUnverifiableFetches)
	}
}
