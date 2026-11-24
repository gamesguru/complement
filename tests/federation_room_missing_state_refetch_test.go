package tests

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/sjson"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
)

// TestUnverifiableStateEventIsNotRefetchedForEveryGap guards against a retry
// loop in state recovery.
//
// A server is pushed several events, each with a gap before it. For every gap
// the homeserver asks /state_ids for the state at the missing prev_event, then
// fetches the listed state events it does not have. One of those state events
// is served with an invalid signature, so it can never be verified.
//
// A fetch that cannot succeed must not be repeated for every gap: each repeat
// costs a full /state_ids response plus the event fetches, and a client
// paginating /messages over a range with many such gaps (or retrying the
// same request) pays that cost every time. The homeserver should learn from
// the first failure that this event is unverifiable and stop asking for it.
func TestUnverifiableStateEventIsNotRefetchedForEveryGap(t *testing.T) {
	const gaps = 5
	// One fetch is expected. One retry is tolerated, for a fetch already in
	// flight when the first failure comes back.
	const maxUnverifiableFetches = 2

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

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{LocalpartSuffix: "alice"})
	roomID := alice.MustCreateRoom(t, map[string]interface{}{
		"preset":       "public_chat",
		"room_version": "10",
	})
	bob := srv.UserID("bob")
	srvRoom := srv.MustJoinRoom(t, deployment, "hs1", roomID, bob)
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(bob, roomID))

	createEvent := srvRoom.CurrentState(spec.MRoomCreate, "")
	plEvent := srvRoom.CurrentState(spec.MRoomPowerLevels, "")
	bobJoinEvent := srvRoom.CurrentState(spec.MRoomMember, bob)
	authEvents := []string{createEvent.EventID(), plEvent.EventID(), bobJoinEvent.EventID()}

	// A state event that hs1 will be told about but can never verify.
	emptyStateKey := ""
	unverifiable := srv.MustCreateEvent(t, srvRoom, federation.Event{
		Type:     "org.example.unverifiable",
		Sender:   bob,
		StateKey: &emptyStateKey,
		Content:  map[string]interface{}{"note": "served with an invalid signature"},
	})
	srvRoom.AddEvent(unverifiable)
	t.Logf("unverifiable state event: %s", unverifiable.EventID())

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

	// Each pair is a prev_event that hs1 does not have, and an event built on
	// it. The gap event also names an event hs1 does have: a *pushed* event
	// whose prev_events are all missing is rejected before any state is
	// recovered. With one known prev it is kept as a forward gap, and state
	// recovery runs for the missing one -- the same code path, with
	// ignore_pull_backoff=True, that a forwarded event with an open gap takes.
	var gapEvents []json.RawMessage
	var missingPrevs []gomatrixserverlib.PDU
	for i := 0; i < gaps; i++ {
		prev := srv.MustCreateEvent(t, srvRoom, federation.Event{
			Type:       "m.room.message",
			Sender:     bob,
			Content:    map[string]interface{}{"msgtype": "m.text", "body": fmt.Sprintf("missing prev %d", i)},
			PrevEvents: []string{bobJoinEvent.EventID()},
			AuthEvents: authEvents,
		})
		srvRoom.AddEvent(prev)
		missingPrevs = append(missingPrevs, prev)
		ev := srv.MustCreateEvent(t, srvRoom, federation.Event{
			Type:    "m.room.message",
			Sender:  bob,
			Content: map[string]interface{}{"msgtype": "m.text", "body": fmt.Sprintf("after gap %d", i)},
			// A known prev_event is required: Synapse rejects (403) a pushed
			// event whose only prev_events are unfetchable, and only recovers
			// state for a forward gap when it also has a known prev_event.
			PrevEvents: []string{prev.EventID(), bobJoinEvent.EventID()},
			AuthEvents: authEvents,
		})
		srvRoom.AddEvent(ev)
		gapEvents = append(gapEvents, ev.JSON())
	}

	// hs1 cannot close the gaps with /get_missing_events, so it falls back to
	// the state at the missing prev_event.
	srv.Mux().HandleFunc("/_matrix/federation/v1/get_missing_events/{roomID}", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"events":[]}`))
	})

	var stateIDsRequests, unverifiableFetches int32
	srv.Mux().HandleFunc("/_matrix/federation/v1/state_ids/{roomID}", func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&stateIDsRequests, 1)
		var pduIDs []string
		for _, ev := range srvRoom.AllCurrentState() {
			pduIDs = append(pduIDs, ev.EventID())
		}
		authChain := srvRoom.AuthChainForEvents(srvRoom.AllCurrentState())
		authChainIDs := make([]string, 0, len(authChain))
		for _, ev := range authChain {
			authChainIDs = append(authChainIDs, ev.EventID())
		}
		res, err := json.Marshal(struct {
			AuthChainIDs []string `json:"auth_chain_ids"`
			PDUIDs       []string `json:"pdu_ids"`
		}{AuthChainIDs: authChainIDs, PDUIDs: pduIDs})
		if err != nil {
			t.Errorf("failed to marshal /state_ids response: %s", err)
		}
		w.WriteHeader(200)
		w.Write(res)
	})

	srv.Mux().Handle("/_matrix/federation/v1/event/{eventID}", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		eventID := mux.Vars(req)["eventID"]
		// The missing prev_events must stay unfetchable, otherwise hs1 just
		// fetches them directly and there is no gap to recover state for.
		for _, prev := range missingPrevs {
			if prev.EventID() == eventID {
				w.WriteHeader(404)
				fmt.Fprintf(w, `complement: withholding prev_event: %s`, eventID)
				return
			}
		}
		var pdu json.RawMessage
		if eventID == unverifiable.EventID() {
			atomic.AddInt32(&unverifiableFetches, 1)
			pdu = unverifiableJSON
		} else {
			event, ok := srvRoom.GetEventInTimeline(eventID)
			if !ok {
				for _, ev := range srvRoom.AuthChainForEvents(srvRoom.AllCurrentState()) {
					if ev.EventID() == eventID {
						event, ok = ev, true
					}
				}
			}
			if !ok {
				w.WriteHeader(404)
				fmt.Fprintf(w, `complement: failed to find event: %s`, eventID)
				return
			}
			pdu = event.JSON()
		}
		res, err := json.Marshal(gomatrixserverlib.Transaction{
			Origin:         spec.ServerName(srv.ServerName()),
			OriginServerTS: spec.AsTimestamp(time.Now()),
			PDUs:           []json.RawMessage{pdu},
		})
		if err != nil {
			t.Errorf("failed to marshal /event response: %s", err)
		}
		w.WriteHeader(200)
		w.Write(res)
	}))

	// Push the gap events one at a time, waiting for hs1 to go and look at
	// the state for each, so the gaps are handled as separate recoveries.
	for i, ev := range gapEvents {
		srv.MustSendTransaction(t, deployment, "hs1", []json.RawMessage{ev}, nil)
		deadline := time.Now().Add(15 * time.Second)
		for atomic.LoadInt32(&stateIDsRequests) < int32(i+1) {
			if time.Now().After(deadline) {
				t.Fatalf("hs1 did not request /state_ids for gap %d", i)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	// A sentinel built on events hs1 knows tells us when hs1 has finished.
	sentinel := srv.MustCreateEvent(t, srvRoom, federation.Event{
		Type:       "m.room.message",
		Sender:     bob,
		Content:    map[string]interface{}{"msgtype": "m.text", "body": "finished"},
		PrevEvents: []string{bobJoinEvent.EventID()},
		AuthEvents: authEvents,
	})
	srv.MustSendTransaction(t, deployment, "hs1", []json.RawMessage{sentinel.JSON()}, nil)
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, sentinel.EventID()))

	states := atomic.LoadInt32(&stateIDsRequests)
	fetches := atomic.LoadInt32(&unverifiableFetches)
	t.Logf("/state_ids requests: %d, fetches of the unverifiable event: %d (%d gaps)", states, fetches, gaps)

	// The test only means something if hs1 really did recover state for
	// several gaps.
	if states < 2 {
		t.Fatalf("hs1 requested /state_ids %d time(s); the test did not exercise repeated gaps", states)
	}
	if fetches > maxUnverifiableFetches {
		t.Fatalf(
			"hs1 fetched the unverifiable event %s %d times across %d gaps (at most %d expected): "+
				"a fetch that cannot succeed is being repeated for every gap",
			unverifiable.EventID(), fetches, gaps, maxUnverifiableFetches,
		)
	}
}

// TestSharedMissingPrevStateIsNotRefetchedPerEvent covers the pulled/backfill
// shape: one transaction of events that all name the same prev_event, which
// the server cannot fetch because its signature cannot be verified. Each event
// independently recovers the state at that prev_event, and each recovery is a
// full /state_ids response plus the state-event fetches, so without a
// remembered failure the batch pays for the same unfetchable state once per
// event.
//
// This bounds /state_ids rather than /event: repeated event fetches are
// already deduped by the per-event fetch cache, while the whole-state fetch is
// not.
func TestSharedMissingPrevStateIsNotRefetchedPerEvent(t *testing.T) {
	const batchSize = 8
	const maxStateIDsRequests = 2

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

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{LocalpartSuffix: "alice"})
	roomID := alice.MustCreateRoom(t, map[string]interface{}{
		"preset":       "public_chat",
		"room_version": "10",
	})
	bob := srv.UserID("bob")
	srvRoom := srv.MustJoinRoom(t, deployment, "hs1", roomID, bob)
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(bob, roomID))

	createEvent := srvRoom.CurrentState(spec.MRoomCreate, "")
	plEvent := srvRoom.CurrentState(spec.MRoomPowerLevels, "")
	bobJoinEvent := srvRoom.CurrentState(spec.MRoomMember, bob)
	authEvents := []string{createEvent.EventID(), plEvent.EventID(), bobJoinEvent.EventID()}

	// A state event that hs1 is told about but can never verify. Event IDs do
	// not cover signatures, so the corrupted copy keeps the same ID and can be
	// both listed in /state_ids and served from /event.
	emptyStateKey := ""
	unverifiable := srv.MustCreateEvent(t, srvRoom, federation.Event{
		Type:     "org.example.unverifiable",
		Sender:   bob,
		StateKey: &emptyStateKey,
		Content:  map[string]interface{}{"note": "served with an invalid signature"},
	})
	srvRoom.AddEvent(unverifiable)
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

	// Every event in the batch names the same unverifiable state event as one
	// of its prev_events, plus an event hs1 does have: a pushed event whose
	// prev_events are all unfetchable is rejected before any state is
	// recovered, so without the known prev the batch would never reach
	// /state_ids (and the upper bound below would pass vacuously).
	batch := make([]json.RawMessage, 0, batchSize)
	for i := 0; i < batchSize; i++ {
		ev := srv.MustCreateEvent(t, srvRoom, federation.Event{
			Type:       "m.room.message",
			Sender:     bob,
			Content:    map[string]interface{}{"msgtype": "m.text", "body": fmt.Sprintf("batch %d", i)},
			PrevEvents: []string{unverifiable.EventID(), bobJoinEvent.EventID()},
			AuthEvents: authEvents,
		})
		srvRoom.AddEvent(ev)
		batch = append(batch, ev.JSON())
	}

	var stateIDsRequests int32
	srv.Mux().HandleFunc("/_matrix/federation/v1/state_ids/{roomID}", func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&stateIDsRequests, 1)
		var pduIDs []string
		for _, ev := range srvRoom.AllCurrentState() {
			pduIDs = append(pduIDs, ev.EventID())
		}
		authChain := srvRoom.AuthChainForEvents(srvRoom.AllCurrentState())
		authChainIDs := make([]string, 0, len(authChain))
		for _, ev := range authChain {
			authChainIDs = append(authChainIDs, ev.EventID())
		}
		res, err := json.Marshal(struct {
			AuthChainIDs []string `json:"auth_chain_ids"`
			PDUIDs       []string `json:"pdu_ids"`
		}{AuthChainIDs: authChainIDs, PDUIDs: pduIDs})
		if err != nil {
			t.Errorf("failed to marshal /state_ids response: %s", err)
		}
		w.WriteHeader(200)
		w.Write(res)
	})

	srv.Mux().Handle("/_matrix/federation/v1/event/{eventID}", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		eventID := mux.Vars(req)["eventID"]
		var pdu json.RawMessage
		if eventID == unverifiable.EventID() {
			pdu = unverifiableJSON
		} else {
			event, ok := srvRoom.GetEventInTimeline(eventID)
			if !ok {
				for _, ev := range srvRoom.AuthChainForEvents(srvRoom.AllCurrentState()) {
					if ev.EventID() == eventID {
						event, ok = ev, true
					}
				}
			}
			if !ok {
				w.WriteHeader(404)
				fmt.Fprintf(w, `complement: failed to find event: %s`, eventID)
				return
			}
			pdu = event.JSON()
		}
		res, err := json.Marshal(gomatrixserverlib.Transaction{
			Origin:         spec.ServerName(srv.ServerName()),
			OriginServerTS: spec.AsTimestamp(time.Now()),
			PDUs:           []json.RawMessage{pdu},
		})
		if err != nil {
			t.Errorf("failed to marshal /event response: %s", err)
		}
		w.WriteHeader(200)
		w.Write(res)
	}))

	srv.MustSendTransaction(t, deployment, "hs1", batch, nil)

	// A sentinel built on events hs1 knows tells us when hs1 has finished.
	sentinel := srv.MustCreateEvent(t, srvRoom, federation.Event{
		Type:       "m.room.message",
		Sender:     bob,
		Content:    map[string]interface{}{"msgtype": "m.text", "body": "finished"},
		PrevEvents: []string{bobJoinEvent.EventID()},
		AuthEvents: authEvents,
	})
	srv.MustSendTransaction(t, deployment, "hs1", []json.RawMessage{sentinel.JSON()}, nil)
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, sentinel.EventID()))

	states := atomic.LoadInt32(&stateIDsRequests)
	t.Logf("/state_ids requests: %d (%d events sharing one unverifiable prev_event)", states, batchSize)

	// Guard that the recovery actually ran: a fix that skips the fetch
	// entirely would make the upper bound pass vacuously.
	if states < 1 {
		t.Fatalf("hs1 never requested /state_ids; the test did not exercise missing-state recovery")
	}
	if states > maxStateIDsRequests {
		t.Fatalf(
			"hs1 requested /state_ids %d times for %d events sharing the same unfetchable prev_event (at most %d expected): "+
				"the same state recovery is being repeated for every event",
			states, batchSize, maxStateIDsRequests,
		)
	}
}
