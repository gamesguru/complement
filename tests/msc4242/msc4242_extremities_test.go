package tests

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/gjson"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/ct"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/runtime"
)

// maxPrevStateEvents is the MSC4242 cap on len(prev_state_events).
const maxPrevStateEvents = 20

// Test that an extremity which sorts late by event ID is eventually merged by honest events when the
// state DAG has more than 20 forward extremities.
//
// MSC4242 says events cite the current state DAG forward extremities, and also caps
// prev_state_events at 20 entries. It does not say which 20 to cite when there are more. If an
// implementation always cites the same subset (e.g. the 20 lowest event IDs) then an extremity
// outside that subset is never merged for as long as the room keeps more than 20 extremities. It
// stays concurrent with every later event, so a branch which was authorised by a stale view of the
// room is never causally dominated by any later state change.
//
// Event IDs are hashes so a sender can grind an event whose ID sorts last. Other senders can add
// extremities at the cost of one signed state event each. This test does both:
//
//	JOIN (alice joins; every event below cites it as its only prev_state_events)
//	 ├── TARGET  (m.room.topic, ID ground to sort after every other extremity)
//	 ├── FILLER_0 .. FILLER_21  (each round: 22 fresh concurrent state events)
//	 └── ... alice's displayname changes: one state event per round, which should merge
//	         up to 20 extremities
//
// Each round the Complement server adds 22 fresh extremities and then alice's homeserver emits a
// state event (a displayname change). Honest servers should merge TARGET within a few rounds.
//
// This test is EXPECTED TO FAIL on a homeserver which truncates by event ID (Synapse does today, see
// the FIXME in EventBuilder.build). The failure is the finding: the MSC needs a selection rule which
// guarantees every extremity is eventually cited.
func TestMSC4242LateSortingExtremityIsEventuallyMerged(t *testing.T) {
	// Deferred: Zendrite does not yet merge state DAGs correctly.
	runtime.SkipIf(t, runtime.Zendrite)
	// Known open finding (see above): Synapse and Sithnapse truncate
	// extremities by event ID, so this fails by design until the MSC specifies a
	// selection rule. Other implementations still run it.
	runtime.SkipIf(t, runtime.Synapse, runtime.Sithnapse)
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
	room := srv.MustMakeRoom(t, roomVersion,
		federation.InitialRoomEvents(roomVersion, bob),
		federation.WithImpl(ServerRoomImplStateDAG(t)),
	)

	alice.MustJoinRoom(t, room.RoomID, []spec.ServerName{srv.ServerName()})
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(alice.UserID, room.RoomID))
	join := awaitMembership(t, room, alice.UserID, "join")

	// Grind the target so its event ID sorts after everything else we create.
	target := mustGrindLateSortingEvent(t, srv, room, join.EventID(), bob)
	t.Logf("target %s (late-sorting ID)", target.EventID())

	const rounds = 6
	const fillersPerRound = 22 // > 20 on its own, so there are always more than 20 extremities
	var citedInRound = -1
	fillerCount := 0

	for round := 0; round < rounds && citedInRound < 0; round++ {
		pdus := []json.RawMessage{}
		wantInState := [][2]string{}
		if round == 0 {
			// Send the target first so "oldest first" policies see it first.
			pdus = append(pdus, target.JSON())
		}
		for i := 0; i < fillersPerRound; i++ {
			stateKey := fmt.Sprintf("filler-%d", fillerCount)
			fillerCount++
			var filler gomatrixserverlib.PDU
			// Re-roll until the filler sorts before the target: fillers must not outrank it.
			for attempt := 0; ; attempt++ {
				filler = mustCreateEvent(t, srv, room, MSC4242Event{
					Event: federation.Event{
						Type:       "org.example.fan",
						Sender:     bob,
						StateKey:   &stateKey,
						Content:    map[string]interface{}{"n": attempt},
						PrevEvents: []string{join.EventID()},
					},
					PrevStateEvents: []string{join.EventID()},
				})
				if filler.EventID() < target.EventID() {
					break
				}
			}
			pdus = append(pdus, filler.JSON())
			wantInState = append(wantInState, [2]string{"org.example.fan", stateKey})
		}
		srv.MustSendTransaction(t, deployment, "hs1", pdus, nil)

		// Wait until the homeserver has processed them all, so that they are extremities
		// before alice's homeserver builds its next event.
		mustEventually(t, 20*time.Second, fmt.Sprintf("round %d: fillers to reach alice's homeserver", round), func() bool {
			state := currentRoomState(t, alice, room.RoomID)
			for _, k := range wantInState {
				if _, ok := state[k]; !ok {
					return false
				}
			}
			return true
		})

		// alice's homeserver now builds a state event. It should cite up to 20 extremities.
		name := fmt.Sprintf("round %d", round)
		alice.MustDo(t, "PUT", []string{"_matrix", "client", "v3", "profile", alice.UserID, "displayname"},
			client.WithJSONBody(t, map[string]interface{}{"displayname": name}),
		)
		var aliceEvent gomatrixserverlib.PDU
		mustEventually(t, 20*time.Second, fmt.Sprintf("round %d: alice's displayname event to federate", round), func() bool {
			ev := room.CurrentState(spec.MRoomMember, alice.UserID)
			if ev != nil && gjson.GetBytes(ev.Content(), "displayname").Str == name {
				aliceEvent = ev
				return true
			}
			return false
		})
		cited := aliceEvent.PrevStateEventIDs()
		t.Logf("round %d: %s cites %d of the extremities, includes target=%v", round, aliceEvent.EventID(),
			len(cited), contains(cited, target.EventID()))
		if len(cited) > maxPrevStateEvents {
			ct.Fatalf(t, "round %d: %d prev_state_events exceeds the cap of %d", round, len(cited), maxPrevStateEvents)
		}
		if contains(cited, target.EventID()) {
			citedInRound = round
		}
	}

	// Observation: an unmerged extremity still participates in the resolved current state.
	topic := currentRoomState(t, alice, room.RoomID)[[2]string{spec.MRoomTopic, ""}]
	t.Logf("resolved m.room.topic: %s", topic.Raw)

	if citedInRound < 0 {
		ct.Fatalf(t, "extremity %s was never cited by alice's homeserver in %d rounds although it was an extremity "+
			"throughout (each round the room had >%d extremities). It stays concurrent with every later event: "+
			"the homeserver's choice of which %d extremities to cite is not fair",
			target.EventID(), rounds, maxPrevStateEvents, maxPrevStateEvents)
	}
}

// mustGrindLateSortingEvent creates a state event whose event ID has the prefix "$zz", which sorts
// after IDs starting with any other two characters of the URL-safe base64 alphabet except "zz"
// followed by a larger character. IDs are hashes so this takes about 4096 attempts on average.
func mustGrindLateSortingEvent(t *testing.T, srv *federation.Server, room *federation.ServerRoom, parent, sender string) gomatrixserverlib.PDU {
	t.Helper()
	for attempt := 0; attempt < 200000; attempt++ {
		ev := mustCreateEvent(t, srv, room, MSC4242Event{
			Event: federation.Event{
				Type:       spec.MRoomTopic,
				Sender:     sender,
				StateKey:   &empty,
				Content:    map[string]interface{}{"topic": "the starved branch", "n": attempt},
				PrevEvents: []string{parent},
			},
			PrevStateEvents: []string{parent},
		})
		if strings.HasPrefix(ev.EventID(), "$zz") {
			return ev
		}
	}
	ct.Fatalf(t, "failed to grind an event ID with prefix $zz")
	return nil
}

func contains(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// mustEventually polls cond until it returns true or the timeout elapses.
func mustEventually(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			ct.Fatalf(t, "timed out after %s waiting for: %s", timeout, what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
