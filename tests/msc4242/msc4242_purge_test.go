package tests

// PRIVATE until disclosure is agreed: do not push to a public remote.
//
// Purging history on one server must not change how it judges later events. A purge keeps old state
// events; a server which drops their state can no longer authorise events citing them in
// prev_state_events, and disagrees with a server which did not purge.
//
// The trigger is Synapse's admin history purge API, so these tests are opt-in:
//
//	COMPLEMENT_MSC4242_PURGE=1

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/gjson"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/ct"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
)

// A bans the sender of X on one branch, and X also cites a branch from before the ban. Both servers
// must reject X.
func TestMSC4242PurgeDoesNotAdmitBannedSender(t *testing.T) {
	runMSC4242PurgeScenario(t, false)
}

// A is the only record that the sender of X joined, and X also cites a branch without it. Both
// servers must accept X.
func TestMSC4242PurgeDoesNotRejectJoinedSender(t *testing.T) {
	runMSC4242PurgeScenario(t, true)
}

func runMSC4242PurgeScenario(t *testing.T, aIsJoin bool) {
	if os.Getenv("COMPLEMENT_MSC4242_PURGE") != "1" {
		t.Skip("set COMPLEMENT_MSC4242_PURGE=1 to run: needs the Synapse admin purge API")
	}
	t.Run("no purge (control)", func(t *testing.T) { msc4242PurgeScenario(t, aIsJoin, false) })
	t.Run("hs1 purges", func(t *testing.T) { msc4242PurgeScenario(t, aIsJoin, true) })
}

// The state DAG, where X is the disputed event:
//
//	base <- A <- TOPIC      TOPIC makes A a non-tip
//	   `--- FORK            FORK is from before A
//	X cites [A, FORK]
func msc4242PurgeScenario(t *testing.T, aIsJoin, purge bool) {
	deployment := complement.Deploy(t, 2)
	defer deployment.Destroy(t)
	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{IsAdmin: true})
	bob := deployment.Register(t, "hs2", helpers.RegistrationOpts{})

	srv := federation.NewServer(t, deployment,
		federation.HandleKeyRequests(),
		federation.HandleTransactionRequests(nil, nil),
		federation.HandleEventRequests(),
	)
	srv.UnexpectedRequestsAreErrors = false
	cancel := srv.Listen()
	defer cancel()

	roomID := alice.MustCreateRoom(t, map[string]interface{}{
		"preset":       "public_chat",
		"room_version": string(roomVersion),
		"power_level_content_override": map[string]interface{}{
			"events_default": 0,
			"state_default":  0,
			"events":         map[string]interface{}{},
		},
	})
	hs1Name := deployment.GetFullyQualifiedHomeserverName(t, "hs1")
	bob.MustJoinRoom(t, roomID, []spec.ServerName{hs1Name})

	// sees reports whether the client's server shows the event. Rejected events are not shown.
	sees := func(cli *client.CSAPI, eventID string, timeout time.Duration) bool {
		deadline := time.Now().Add(timeout)
		for {
			res := cli.Do(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "event", eventID})
			res.Body.Close()
			if res.StatusCode == 200 {
				return true
			}
			if time.Now().After(deadline) {
				return false
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	mustReachBoth := func(eventID, what string) {
		t.Helper()
		if !sees(alice, eventID, 20*time.Second) || !sees(bob, eventID, 20*time.Second) {
			ct.Fatalf(t, "setup: %s (%s) did not reach both homeservers", what, eventID)
		}
	}

	join := func(userID string) (*federation.ServerRoom, string) {
		room := srv.MustJoinRoom(t, deployment, hs1Name, roomID, userID,
			federation.WithRoomOpts(federation.WithImpl(ServerRoomImplStateDAG(t))),
		)
		ev := room.CurrentState(spec.MRoomMember, userID)
		if ev == nil {
			ct.Fatalf(t, "setup: no join event for %s", userID)
		}
		mustReachBoth(ev.EventID(), "join of "+userID)
		return room, ev.EventID()
	}
	carol, mallory, dave := srv.UserID("carol"), srv.UserID("mallory"), srv.UserID("dave")
	join(carol)
	room, base := join(mallory)

	sendState := func(evType string, stateKey string, content map[string]interface{}) string {
		res := alice.MustDo(t, "PUT",
			[]string{"_matrix", "client", "v3", "rooms", roomID, "state", evType, stateKey},
			client.WithJSONBody(t, content),
		)
		return gjson.ParseBytes(client.ParseJSON(t, res)).Get("event_id").Str
	}
	sendMessage := func(cli *client.CSAPI, body string) string {
		return cli.Unsafe_SendEventUnsynced(t, roomID, b.Event{
			Type:    "m.room.message",
			Content: map[string]interface{}{"msgtype": "m.text", "body": body},
		})
	}

	var a, subject string
	if aIsJoin {
		room, a = join(dave)
		subject = dave
	} else {
		a = sendState(spec.MRoomMember, mallory, map[string]interface{}{"membership": "ban"})
		mustReachBoth(a, "ban")
		subject = mallory
	}
	for _, body := range []string{"one", "two", "three"} {
		mustReachBoth(sendMessage(alice, body), "message")
	}
	cutoff := sendMessage(alice, "cutoff")
	mustReachBoth(cutoff, "cutoff message")
	topic := sendState(spec.MRoomTopic, "", map[string]interface{}{"topic": "after A"})
	mustReachBoth(topic, "topic")
	room.WaiterForEvent(topic).Waitf(t, 20*time.Second, "waiting for the topic to reach Complement")

	// craft makes an event and sends the identical bytes to both homeservers.
	craft := func(sender, evType string, stateKey *string, content map[string]interface{}, prevState []string) gomatrixserverlib.PDU {
		pdu := mustCreateEvent(t, srv, room, MSC4242Event{
			Event: federation.Event{
				Type: evType, Sender: sender, StateKey: stateKey, Content: content,
			},
			PrevStateEvents: prevState,
		})
		for _, hs := range []string{"hs1", "hs2"} {
			srv.MustSendTransaction(t, deployment,
				deployment.GetFullyQualifiedHomeserverName(t, hs), []json.RawMessage{pdu.JSON()}, nil)
		}
		return pdu
	}

	fork := craft(carol, "org.example.fork", &empty, map[string]interface{}{}, []string{base})
	mustReachBoth(fork.EventID(), "fork")

	if purge {
		res := alice.MustDo(t, "POST", []string{"_synapse", "admin", "v1", "purge_history", roomID},
			client.WithJSONBody(t, map[string]interface{}{
				"purge_up_to_event_id": cutoff,
				"delete_local_events":  true,
			}),
		)
		purgeID := gjson.ParseBytes(client.ParseJSON(t, res)).Get("purge_id").Str
		mustEventually(t, 60*time.Second, "history purge to complete", func() bool {
			status := alice.MustDo(t, "GET",
				[]string{"_synapse", "admin", "v1", "purge_history_status", purgeID})
			return gjson.ParseBytes(client.ParseJSON(t, status)).Get("status").Str == "complete"
		})
	}

	// Ordinary traffic citing only the surviving branch.
	warm := craft(carol, "m.room.message", nil,
		map[string]interface{}{"msgtype": "m.text", "body": "hi"}, []string{fork.EventID()})
	mustReachBoth(warm.EventID(), "message citing the fork")

	x := craft(subject, "org.example.disputed", &empty, map[string]interface{}{},
		[]string{a, fork.EventID()})
	onHS1, onHS2 := sees(alice, x.EventID(), 10*time.Second), sees(bob, x.EventID(), 10*time.Second)
	if onHS1 != aIsJoin || onHS2 != aIsJoin {
		t.Errorf("disputed event %s: want visible=%v on both, got hs1=%v hs2=%v",
			x.EventID(), aIsJoin, onHS1, onHS2)
	}

	// The room must stay usable in both directions, including after each side has sent more events.
	mustShare := func(to *client.CSAPI, eventID, what string) {
		t.Helper()
		if !sees(to, eventID, 10*time.Second) {
			t.Errorf("%s (%s) never became visible on the other homeserver: the room has split", what, eventID)
		}
	}
	mustShare(bob, sendState(spec.MRoomName, "", map[string]interface{}{"name": "one"}), "alice's state event")
	mustShare(alice, bob.SendEventSynced(t, roomID, b.Event{
		Type: "org.example.bob", StateKey: &empty, Content: map[string]interface{}{},
	}), "bob's state event")
	mustShare(bob, sendMessage(alice, "still there?"), "alice's later message")
	mustShare(alice, sendMessage(bob, "bob here"), "bob's later message")
}
