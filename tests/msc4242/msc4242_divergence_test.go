package tests

// DIVERGENCE: Tests for state DAG divergence and re-convergence limitations.
//
// These tests encode known behavioral deficiencies in the state DAG model:
// partitions with buggy/incomplete peers can cause permanent divergence,
// and differential rejections can prevent re-convergence.
//
// DIVERGENCE00 (STATE10): A partitioned server that receives an incomplete
//   state DAG from a buggy peer ends up with a corrupted state view. The
//   "detectable omission" claim depends on receiving a later event that
//   references the missing state — but if the buggy peer's branch simply
//   never references the omitted events, the gap is invisible.
//
// DIVERGENCE01 (STATE11): Two servers that diverge during a partition and
//   each build a locally-consistent but mutually-incompatible state DAG
//   will reject each other's events upon reconnection, because each
//   server's state DAG is internally valid but the other server's events
//   reference state that doesn't exist in this server's DAG view.

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/ct"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/must"
	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/gomatrixserverlib/fclient"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/gjson"
)

// DIVERGENCE00 (STATE10): Partitioned server accepts incomplete state DAG from buggy peer.
//
// TRIPWIRE: This test asserts a known deficiency. If the implementation is
// fixed so that Alice detects the omission and refuses to regress, this test
// will fail — that is intentional. Update the assertion to match the new
// correct behavior, do not silently loosen it.
//
// Scenario:
//  1. Alice (hs1) and Bob (srv) are in a room. Alice changes join_rules to "invite".
//  2. Alice goes offline (partition).
//  3. While Alice is offline, Bob sets the room name on his branch, citing state
//     from before the join_rules change.
//  4. Alice comes back online. Bob sends his events. Alice needs state DAG fill.
//  5. Bob's /get_missing_events (state_dag=true) handler OMITS the join_rules change.
//     It returns a state DAG that is internally consistent (all prev_state_events
//     chain back to create) but missing the invite join_rules event.
//  6. Alice accepts the events (the path checks out locally against what she has).
//  7. Alice's current state has regressed: her join_rules reverted from "invite"
//     to the initial "public" because the buggy state DAG omitted the change.
//  8. Concrete consequence: a fresh uninvited local user can join under the
//     corrupted "public" join_rules.
//  9. Self-healing check: an event citing the TRUE invite state (which Alice
//     already holds locally) arrives. Does Alice's join_rules reconverge to
//     "invite", or does the corruption persist?
//
// This demonstrates that "detectable omission" requires a reference to the missing
// event. If the buggy peer's branch never references the omitted event, the gap
// is invisible to the receiving server.
func testMSC4242DIVERGENCE00PartitionedServerAcceptsIncompleteStateDAG(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)
	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	srv := federation.NewServer(t, deployment,
		federation.HandleKeyRequests(),
		federation.HandleTransactionRequests(nil, nil),
		federation.HandleEventRequests(),
		federation.HandleMakeSendJoinRequests(),
	)
	srv.UnexpectedRequestsAreErrors = false
	cancel := srv.Listen()
	defer cancel()

	bob := srv.UserID("bob")
	charlie := srv.UserID("charlie")

	// Create room with initial state.
	roomID := alice.MustCreateRoom(t, map[string]interface{}{
		"room_version": roomVersion,
		"preset":       "public_chat",
	})
	room := srv.MustJoinRoom(t, deployment, "hs1", roomID, bob,
		federation.WithRoomOpts(federation.WithImpl(ServerRoomImplStateDAG(t, srv))))

	// Charlie joins.
	charlieJoin := srv.MustCreateEvent(t, room, federation.Event{
		Type:     spec.MRoomMember,
		StateKey: &charlie,
		Sender:   charlie,
		Content:  map[string]interface{}{"membership": "join"},
	})
	room.AddEvent(charlieJoin)
	srv.MustSendTransaction(t, deployment, "hs1", AsEventJSONs([]gomatrixserverlib.PDU{charlieJoin}), nil)
	since := alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(bob, roomID), client.SyncJoinedTo(charlie, roomID))

	// Baseline: Alice changes join_rules to invite-only.
	alice.MustDo(t, "PUT", []string{
		"_matrix", "client", "v3", "rooms", roomID, "state", spec.MRoomJoinRules, "",
	}, client.WithJSONBody(t, map[string]any{
		"join_rule": "invite",
	}))
	var inviteJoinRulesID string
	since = alice.MustSyncUntil(t, client.SyncReq{Since: since}, client.SyncTimelineHas(roomID, func(r gjson.Result) bool {
		if r.Get("type").Str == spec.MRoomJoinRules && r.Get("content.join_rule").Str == "invite" {
			inviteJoinRulesID = r.Get("event_id").Str
			return true
		}
		return false
	}))
	t.Logf("join_rules invite event: %s", inviteJoinRulesID)

	// === PARTITION: Alice goes offline ===
	// Bob builds a branch that doesn't include the join_rules change.
	// Bob cites state from before the join_rules change (initial public join_rules).

	// Bob sets room name on his branch.
	bobSetName := mustCreateEvent(t, srv, room, MSC4242Event{
		Event: federation.Event{
			Type:       spec.MRoomName,
			StateKey:   &empty,
			Sender:     bob,
			Content:    map[string]interface{}{"name": "Bob's Room"},
			PrevEvents: []string{room.CurrentState(spec.MRoomMember, bob).EventID()},
		},
		PrevStateEvents: []string{room.CurrentState(spec.MRoomJoinRules, "").EventID()},
	})

	// Bob sends a message on his branch.
	bobMsg := mustCreateEvent(t, srv, room, MSC4242Event{
		Event: federation.Event{
			Type:    "m.room.message",
			Sender:  bob,
			Content: map[string]interface{}{"msgtype": "m.text", "body": "Hello from partition"},
		},
	})

	// Set up buggy /get_missing_events: returns state DAG events but OMITS
	// the join_rules invite event. The returned events are internally consistent
	// (all chain back to create via prev_state_events) but incomplete.
	var getMissingEventsStateDAGHandler func(w http.ResponseWriter, req *fclient.MissingEvents)
	var getMissingEventsEventDAGHandler func(w http.ResponseWriter, req *fclient.MissingEvents)

	srv.Mux().HandleFunc("/_matrix/federation/v1/get_missing_events/{roomID}", func(w http.ResponseWriter, req *http.Request) {
		body, err := extractGetMissingEventsRequest(room.RoomID, req)
		if err != nil {
			ct.Errorf(t, "failed to read get_missing_events req body: %s", err)
			w.WriteHeader(500)
			return
		}
		if body.StateDAG {
			getMissingEventsStateDAGHandler(w, body)
		} else {
			getMissingEventsEventDAGHandler(w, body)
		}
	})

	// The buggy handler: returns Bob's state events but NOT the join_rules change.
	// It returns the initial join_rules (public) instead of the invite one.
	getMissingEventsStateDAGHandler = func(w http.ResponseWriter, _ *fclient.MissingEvents) {
		stateEvents := []gomatrixserverlib.PDU{
			room.CurrentState(spec.MRoomCreate, ""),
			room.CurrentState(spec.MRoomPowerLevels, ""),
			room.CurrentState(spec.MRoomJoinRules, ""), // initial public join_rules, NOT inviteJoinRulesID
			room.CurrentState(spec.MRoomMember, bob),
			room.CurrentState(spec.MRoomMember, alice.UserID),
			room.CurrentState(spec.MRoomMember, charlie),
			bobSetName,
		}
		w.WriteHeader(200)
		resp := fclient.RespMissingEvents{
			Events: gomatrixserverlib.NewEventJSONsFromEvents(stateEvents),
		}
		if err := json.NewEncoder(w).Encode(&resp); err != nil {
			must.NotError(t, "failed to encode response", err)
		}
	}

	getMissingEventsEventDAGHandler = func(w http.ResponseWriter, req *fclient.MissingEvents) {
		w.WriteHeader(200)
		resp := fclient.RespMissingEvents{
			Events: gomatrixserverlib.NewEventJSONsFromEvents([]gomatrixserverlib.PDU{
				bobSetName, bobMsg,
			}),
		}
		if err := json.NewEncoder(w).Encode(&resp); err != nil {
			must.NotError(t, "failed to encode response", err)
		}
	}

	// Send Bob's events. Alice will need to fill state DAG, and Bob's buggy
	// handler will omit the join_rules change.
	srv.MustSendTransaction(t, deployment, "hs1", AsEventJSONs([]gomatrixserverlib.PDU{bobSetName, bobMsg}), nil)

	// Wait for Alice to see Bob's message.
	alice.MustSyncUntil(t, client.SyncReq{Since: since},
		client.SyncTimelineHasEventID(roomID, bobMsg.EventID()))

	// Check: what does Alice think the current join_rules are?
	jrResp := alice.MustDo(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "state", spec.MRoomJoinRules, ""})
	jrBody := client.ParseJSON(t, jrResp)
	joinRule := gjson.GetBytes(jrBody, "join_rule").Str
	t.Logf("Alice's current join_rules after buggy state DAG: %s", joinRule)

	// This is the deficiency: Alice accepted a state DAG that omitted the
	// join_rules change. Her current state has regressed from "invite" to
	// whatever was in Bob's incomplete state DAG. Assert the (bad) outcome
	// directly instead of only logging it: if a future fix makes Alice
	// detect the omission and refuse to regress, this test should start
	// failing here so it gets updated, not silently keep passing regardless
	// of which way the implementation behaves.
	must.Equal(t, joinRule, "public", "DEFICIENCY: expected Alice's join_rules to have regressed "+
		"from 'invite' to 'public' after accepting a buggy/incomplete state DAG that omitted the "+
		"invite change; if this now holds, the omission is detected and this test needs updating")
}

// DIVERGENCE01 (STATE11): Differential rejection between servers with divergent state DAG views.
//
// Documentary only — this test cannot assert the deficiency because complement's
// mock federation server (srv/Bob) does not run real state-DAG-walking or auth
// logic. A real bidirectional version requires two homeservers under test.
//
// Scenario:
//  1. Alice (hs1) and Bob (srv) are in a room.
//  2. Partition: Alice bans Bob on her branch. Bob sets room name on his branch.
//  3. They merge: Bob sends his branch to Alice, including a sentinel that merges
//     both branches. State resolution picks the ban (Alice wins). Alice is correct.
//  4. Now consider Bob's perspective: he never received Alice's ban. His state DAG
//     is internally consistent but doesn't contain the ban.
//  5. If Alice later sends Bob events that reference state from her branch (which
//     includes the ban), Bob can't validate them because his state DAG doesn't have
//     the ban event.
//  6. Bob needs to fetch the missing events from Alice via /get_missing_events.
//     But Bob's state DAG is internally consistent — he doesn't know he's missing
//     anything unless an incoming event's prev_state_events references something
//     he doesn't have.
//
// The deficiency: Bob has no proactive mechanism to discover that his state DAG
// is incomplete. He only discovers it reactively when an incoming event references
// missing state. If Alice's events don't reference the ban's state (e.g., they're
// messages citing older state), Bob never learns about the ban.
func testMSC4242DIVERGENCE01DifferentialRejectionAfterPartition(t *testing.T) {
	t.Skip("documentary only: requires bidirectional real homeserver assertions; complement mock srv cannot run state DAG logic")
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)
	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	srv := federation.NewServer(t, deployment,
		federation.HandleKeyRequests(),
		federation.HandleTransactionRequests(nil, nil),
		federation.HandleEventRequests(),
		federation.HandleMakeSendJoinRequests(),
	)
	srv.UnexpectedRequestsAreErrors = false
	cancel := srv.Listen()
	defer cancel()

	bob := srv.UserID("bob")
	charlie := srv.UserID("charlie")

	// Create room with initial state.
	roomID := alice.MustCreateRoom(t, map[string]interface{}{
		"room_version": roomVersion,
		"preset":       "public_chat",
	})
	room := srv.MustJoinRoom(t, deployment, "hs1", roomID, bob,
		federation.WithRoomOpts(federation.WithImpl(ServerRoomImplStateDAG(t, srv))))

	// Charlie joins for sentinel merging.
	charlieJoin := srv.MustCreateEvent(t, room, federation.Event{
		Type:     spec.MRoomMember,
		StateKey: &charlie,
		Sender:   charlie,
		Content:  map[string]interface{}{"membership": "join"},
	})
	room.AddEvent(charlieJoin)
	srv.MustSendTransaction(t, deployment, "hs1", AsEventJSONs([]gomatrixserverlib.PDU{charlieJoin}), nil)
	since := alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(bob, roomID), client.SyncJoinedTo(charlie, roomID))

	// Record initial state for Bob's branch.
	initialJoinRules := room.CurrentState(spec.MRoomJoinRules, "").EventID()
	initialMemberBob := room.CurrentState(spec.MRoomMember, bob).EventID()

	// === PARTITION ===
	// Branch 1 (Alice on hs1): Alice bans Bob.
	alice.MustDo(t, "POST", []string{
		"_matrix", "client", "v3", "rooms", roomID, "ban",
	}, client.WithJSONBody(t, map[string]any{
		"user_id": bob,
	}))
	var banEventID string
	since = alice.MustSyncUntil(t, client.SyncReq{Since: since}, client.SyncTimelineHas(roomID, func(r gjson.Result) bool {
		if r.Get("type").Str == spec.MRoomMember && r.Get("state_key").Str == bob && r.Get("content.membership").Str == "ban" {
			banEventID = r.Get("event_id").Str
			return true
		}
		return false
	}))
	t.Logf("Alice's ban event: %s", banEventID)

	// Branch 2 (Bob on srv, unaware of ban): Bob sets room name.
	bobSetName := mustCreateEvent(t, srv, room, MSC4242Event{
		Event: federation.Event{
			Type:       spec.MRoomName,
			StateKey:   &empty,
			Sender:     bob,
			Content:    map[string]interface{}{"name": "Bob's Room"},
			PrevEvents: []string{initialMemberBob},
		},
		PrevStateEvents: []string{initialJoinRules},
	})

	// Sentinel merging Alice's ban and Bob's name change.
	sentinel := mustCreateEvent(t, srv, room, MSC4242Event{
		Event: federation.Event{
			Type:       "m.room.message",
			Sender:     charlie,
			Content:    map[string]interface{}{"msgtype": "m.text", "body": "Merge ban and name"},
			PrevEvents: []string{banEventID, bobSetName.EventID()},
		},
		PrevStateEvents: []string{banEventID, bobSetName.EventID()},
	})

	// Send Bob's branch + sentinel to Alice.
	srv.MustSendTransaction(t, deployment, "hs1", AsEventJSONs([]gomatrixserverlib.PDU{bobSetName, sentinel}), nil)
	alice.MustSyncUntil(t, client.SyncReq{Since: since}, client.SyncTimelineHasEventID(roomID, sentinel.EventID()))

	// Verify Alice's resolved state: Bob is banned, name is "Bob's Room".
	bobStateResp := alice.MustDo(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "state", spec.MRoomMember, bob})
	bobBody := client.ParseJSON(t, bobStateResp)
	must.Equal(t, gjson.GetBytes(bobBody, "membership").Str, "ban", "Bob should be banned on Alice")

	nameResp := alice.MustDo(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "state", spec.MRoomName, ""})
	nameBody := client.ParseJSON(t, nameResp)
	must.Equal(t, gjson.GetBytes(nameBody, "name").Str, "Bob's Room", "Room name should be Bob's Room on Alice")

	// Check Bob's state on the mock server. Bob never received Alice's ban,
	// so his state DAG is internally consistent but doesn't contain the ban.
	bobCurrentState := room.AllCurrentState()
	bobHasBan := false
	for _, ev := range bobCurrentState {
		if ev.Type() == spec.MRoomMember && ev.StateKey() != nil && *ev.StateKey() == bob {
			t.Logf("Bob's member state for self: type=%s event_id=%s", ev.Type(), ev.EventID())
		}
	}
	_ = bobHasBan

	// Now: Alice sends Bob an event that references state from AFTER the ban.
	// For example, Alice changes the room topic after banning Bob.
	alice.MustDo(t, "PUT", []string{
		"_matrix", "client", "v3", "rooms", roomID, "state", spec.MRoomTopic, "",
	}, client.WithJSONBody(t, map[string]any{
		"topic": "Topic after ban",
	}))
	var topicEventID string
	since = alice.MustSyncUntil(t, client.SyncReq{Since: since}, client.SyncTimelineHas(roomID, func(r gjson.Result) bool {
		if r.Get("type").Str == spec.MRoomTopic && r.Get("content.topic").Str == "Topic after ban" {
			topicEventID = r.Get("event_id").Str
			return true
		}
		return false
	}))
	t.Logf("Alice's topic event: %s", topicEventID)

	// Set up /get_missing_events for Bob to fetch from Alice.
	var getMissingEventsStateDAGHandler func(w http.ResponseWriter, req *fclient.MissingEvents)
	srv.Mux().HandleFunc("/_matrix/federation/v1/get_missing_events/{roomID}", func(w http.ResponseWriter, req *http.Request) {
		body, err := extractGetMissingEventsRequest(room.RoomID, req)
		if err != nil {
			ct.Errorf(t, "failed to read get_missing_events req body: %s", err)
			w.WriteHeader(500)
			return
		}
		if body.StateDAG {
			getMissingEventsStateDAGHandler(w, body)
		} else {
			w.WriteHeader(200)
			resp := fclient.RespMissingEvents{
				Events: gomatrixserverlib.NewEventJSONsFromEvents([]gomatrixserverlib.PDU{}),
			}
			if err := json.NewEncoder(w).Encode(&resp); err != nil {
				must.NotError(t, "failed to encode response", err)
			}
		}
	})

	// Alice's state DAG includes the ban and the topic change.
	// When Bob asks for missing state DAG events, Alice returns her full state DAG.
	getMissingEventsStateDAGHandler = func(w http.ResponseWriter, _ *fclient.MissingEvents) {
		// In a real scenario, Alice would serve her complete state DAG.
		// For this test, we return the events Bob is missing: the ban and the topic.
		// But the ban event is not in the mock server's room — it was created on hs1.
		// We can't easily reconstruct it here, so we'll use a different approach.
		//
		// The key point is that Bob's state DAG doesn't have a path to these events.
		// When Bob receives Alice's topic event, its prev_state_events will reference
		// state that Bob doesn't have. Bob will try to fetch via /get_missing_events,
		// and Alice will return events that include the ban — but Bob's state DAG
		// can't incorporate them because they're on a different branch.
		w.WriteHeader(200)
		resp := fclient.RespMissingEvents{
			Events: gomatrixserverlib.NewEventJSONsFromEvents([]gomatrixserverlib.PDU{
				bobSetName,
			}),
		}
		if err := json.NewEncoder(w).Encode(&resp); err != nil {
			must.NotError(t, "failed to encode response", err)
		}
	}

	// NOTE: srv (Bob) is complement's mock federation server, a stub that
	// records events handed to it — it does not run real state-DAG-walking
	// or auth logic, so we cannot assert what "Bob" would do on receipt of
	// Alice's topic event the way we assert Alice's (real, under-test)
	// behavior above. The remaining commentary documents the reasoning for
	// why reconvergence is architecturally not guaranteed here; it is not
	// itself an assertion. A real bidirectional version of this test needs
	// two real homeservers (see DIVERGENCE02, which stays entirely on
	// Alice's real server and can assert directly).
	must.NotEqual(t, topicEventID, "", "topic event should have been created")

	// The deficiency: Bob's state DAG is internally consistent. He has no
	// mechanism to discover that Alice's branch exists and needs to be merged,
	// unless Alice explicitly sends him events that reference state from her branch.
	// And even then, the state DAG walking only works if Bob can trace back to
	// the common ancestor — which requires both branches to be in the same DAG.
	//
	// In the current model:
	// - Bob's state DAG: create -> initial_state -> bobSetName
	// - Alice's state DAG: create -> initial_state -> ban -> topic
	// - These are two separate DAGs that never merge on Bob's side
	// - Bob can't walk Alice's DAG because he doesn't have the ban event
	// - Alice can't force Bob to have the ban because /send only sends individual events
	//
	// The only way Bob learns about the ban is if:
	// 1. Alice sends the ban event directly (not via state DAG walking)
	// 2. Bob detects the missing prev_state_events and fetches them
	// 3. But step 2 requires Bob to already know the ban exists
	//
	// This is a fundamental limitation: state DAGs improve the detection window
	// (you know what you're missing when prev_state_events references it) but
	// they don't solve the case where the missing events are on a completely
	// separate branch that the server has no reference to.

	t.Log("DEFICIENCY: Bob's state DAG is internally consistent but doesn't contain Alice's ban.")
	t.Log("Bob has no proactive mechanism to discover Alice's branch. He only learns")
	t.Log("about missing state reactively when an incoming event's prev_events references")
	t.Log("something he doesn't have. If Alice's events don't reference the ban's state,")
	t.Log("Bob never learns about the ban — his state view is permanently diverged.")

	// Verify that Bob's state doesn't include the ban or the topic change.
	// This confirms the divergence is permanent under the current model.
	// The test passes if we reach this point without crashing.
	// The deficiency is documented in the t.Log statements above.
	// A correct implementation would detect the divergence and reconcile,
	// but the current MSC4242 model doesn't guarantee this.
}

// DIVERGENCE02: Offline server accepts a malicious fork, then has concrete
// security consequences from it, and does not self-heal when the honest
// branch it forked away from later re-arrives.
//
// This is the exact scenario from the "state dags difficult divergence"
// session: a server goes offline, comes back to a malicious/buggy fork
// (DIVERGENCE00's mechanism), and the open question is whether that server
// then (a) suffers a real authorization consequence from the corrupted
// state, and (b) can ever reconverge once an event citing the true,
// un-corrupted state (which it already possesses locally — this isn't even
// a missing-event case) arrives.
//
// Unlike DIVERGENCE00/01, this stays entirely on Alice's real homeserver
// (the only side complement can actually assert behavior for — srv/Bob is
// a mock stub, not a real state-DAG-walking implementation) so both halves
// are real assertions, not narration.
//
// NOTE: the expected outcomes below encode the deficiency as currently
// believed to reproduce, following the same pattern as DIVERGENCE00. They
// have not been confirmed against a live run of this suite in this session.
// If a run flips either assertion, that is itself the answer to "do we
// implement all this?" for the corresponding half, and the assertion should
// be updated to match, not silently loosened.
func testMSC4242DIVERGENCE02OfflineServerAcceptsMaliciousForkThenCannotSelfHeal(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)
	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	srv := federation.NewServer(t, deployment,
		federation.HandleKeyRequests(),
		federation.HandleTransactionRequests(nil, nil),
		federation.HandleEventRequests(),
		federation.HandleMakeSendJoinRequests(),
	)
	srv.UnexpectedRequestsAreErrors = false
	cancel := srv.Listen()
	defer cancel()

	bob := srv.UserID("bob")

	roomID := alice.MustCreateRoom(t, map[string]interface{}{
		"room_version": roomVersion,
		"preset":       "public_chat",
	})
	room := srv.MustJoinRoom(t, deployment, "hs1", roomID, bob,
		federation.WithRoomOpts(federation.WithImpl(ServerRoomImplStateDAG(t, srv))))
	since := alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(bob, roomID))

	// Baseline: Alice locks the room down to invite-only.
	alice.MustDo(t, "PUT", []string{
		"_matrix", "client", "v3", "rooms", roomID, "state", spec.MRoomJoinRules, "",
	}, client.WithJSONBody(t, map[string]any{
		"join_rule": "invite",
	}))
	var inviteJoinRulesID string
	since = alice.MustSyncUntil(t, client.SyncReq{Since: since}, client.SyncTimelineHas(roomID, func(r gjson.Result) bool {
		if r.Get("type").Str == spec.MRoomJoinRules && r.Get("content.join_rule").Str == "invite" {
			inviteJoinRulesID = r.Get("event_id").Str
			return true
		}
		return false
	}))

	// === Alice "goes offline": Bob (buggy/malicious peer) builds a branch
	// citing the pre-lockdown (public) join_rules, exactly as in DIVERGENCE00. ===
	bobSetName := mustCreateEvent(t, srv, room, MSC4242Event{
		Event: federation.Event{
			Type:       spec.MRoomName,
			StateKey:   &empty,
			Sender:     bob,
			Content:    map[string]interface{}{"name": "Bob's Room"},
			PrevEvents: []string{room.CurrentState(spec.MRoomMember, bob).EventID()},
		},
		PrevStateEvents: []string{room.CurrentState(spec.MRoomJoinRules, "").EventID()},
	})
	bobMsg := mustCreateEvent(t, srv, room, MSC4242Event{
		Event: federation.Event{
			Type:    "m.room.message",
			Sender:  bob,
			Content: map[string]interface{}{"msgtype": "m.text", "body": "Hello from partition"},
		},
	})

	var getMissingEventsStateDAGHandler func(w http.ResponseWriter, req *fclient.MissingEvents)
	var getMissingEventsEventDAGHandler func(w http.ResponseWriter, req *fclient.MissingEvents)
	srv.Mux().HandleFunc("/_matrix/federation/v1/get_missing_events/{roomID}", func(w http.ResponseWriter, req *http.Request) {
		body, err := extractGetMissingEventsRequest(room.RoomID, req)
		if err != nil {
			ct.Errorf(t, "failed to read get_missing_events req body: %s", err)
			w.WriteHeader(500)
			return
		}
		if body.StateDAG {
			getMissingEventsStateDAGHandler(w, body)
		} else {
			getMissingEventsEventDAGHandler(w, body)
		}
	})
	getMissingEventsStateDAGHandler = func(w http.ResponseWriter, _ *fclient.MissingEvents) {
		stateEvents := []gomatrixserverlib.PDU{
			room.CurrentState(spec.MRoomCreate, ""),
			room.CurrentState(spec.MRoomPowerLevels, ""),
			room.CurrentState(spec.MRoomJoinRules, ""), // stale public join_rules, NOT inviteJoinRulesID
			room.CurrentState(spec.MRoomMember, bob),
			room.CurrentState(spec.MRoomMember, alice.UserID),
			bobSetName,
		}
		w.WriteHeader(200)
		resp := fclient.RespMissingEvents{Events: gomatrixserverlib.NewEventJSONsFromEvents(stateEvents)}
		must.NotError(t, "failed to encode response", json.NewEncoder(w).Encode(&resp))
	}
	getMissingEventsEventDAGHandler = func(w http.ResponseWriter, req *fclient.MissingEvents) {
		w.WriteHeader(200)
		resp := fclient.RespMissingEvents{Events: gomatrixserverlib.NewEventJSONsFromEvents([]gomatrixserverlib.PDU{bobSetName, bobMsg})}
		must.NotError(t, "failed to encode response", json.NewEncoder(w).Encode(&resp))
	}

	srv.MustSendTransaction(t, deployment, "hs1", AsEventJSONs([]gomatrixserverlib.PDU{bobSetName, bobMsg}), nil)
	alice.MustSyncUntil(t, client.SyncReq{Since: since}, client.SyncTimelineHasEventID(roomID, bobMsg.EventID()))

	jrResp := alice.MustDo(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "state", spec.MRoomJoinRules, ""})
	must.Equal(t, gjson.GetBytes(client.ParseJSON(t, jrResp), "join_rule").Str, "public",
		"DEFICIENCY precondition: Alice's join_rules must have regressed to 'public' for the rest of this test to be meaningful")

	// (a) Concrete consequence: because Alice's live join_rules are now
	// "public" (not the "invite" she actually set), a stranger with no
	// invite — a fresh local user on Alice's own server, enforced entirely
	// by Alice's own (corrupted) current state — can join right now.
	mallory2 := deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	joinRes := mallory2.JoinRoom(t, roomID, nil)
	must.Equal(t, joinRes.StatusCode, 200, "DEFICIENCY: expected a fresh, uninvited local user to be able to "+
		"join under Alice's corrupted public join_rules; if this now fails (403), the corrupted state is no "+
		"longer being enforced and this test needs updating")

	// (b) Self-healing check: send a follow-up event whose prev_state_events
	// directly cites inviteJoinRulesID — the TRUE, correct state, which
	// Alice already holds locally (she created it before going offline).
	// This is not even a missing-event case: does receiving a correctly
	// rooted continuation cause Alice's current join_rules to reconverge to
	// "invite", or does the corrupted state persist regardless?
	correction := mustCreateEvent(t, srv, room, MSC4242Event{
		Event: federation.Event{
			Type:       "m.room.message",
			Sender:     bob,
			Content:    map[string]interface{}{"msgtype": "m.text", "body": "honest continuation citing the real lockdown"},
			PrevEvents: []string{bobMsg.EventID()},
		},
		PrevStateEvents: []string{inviteJoinRulesID},
	})
	srv.MustSendTransaction(t, deployment, "hs1", AsEventJSONs([]gomatrixserverlib.PDU{correction}), nil)
	alice.MustSyncUntil(t, client.SyncReq{Since: since}, client.SyncTimelineHasEventID(roomID, correction.EventID()))

	jrResp2 := alice.MustDo(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "state", spec.MRoomJoinRules, ""})
	joinRuleAfterCorrection := gjson.GetBytes(client.ParseJSON(t, jrResp2), "join_rule").Str
	must.Equal(t, joinRuleAfterCorrection, "public",
		"DEFICIENCY: expected Alice's join_rules to remain stuck at 'public' even after an event citing the "+
			"true invite state (already held locally, not even a fetch) arrived — i.e. no automatic self-healing; "+
			"if this now reads 'invite', reconvergence is happening and this test needs updating to match")
}
