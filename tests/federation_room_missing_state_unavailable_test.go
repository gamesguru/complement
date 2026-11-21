package tests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/gomatrixserverlib/spec"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/must"
)

// TestMissingStateEventUnavailableDoesNotAcceptEvent covers a server that is
// pushed an event with a gap before it, fills the state at the gap via
// /state_ids, and then cannot fetch one of the listed state events because
// the remote server fails the /event request (as when it is backing off).
//
// The state before the pushed event is then unknown. The spec only lets an
// event in once it passes authorisation against the state before it, so the
// server must not accept the event against the state it did manage to fetch:
// doing so authorises it against the wrong state and can reset the room's
// state. The event must not reach clients.
func TestMissingStateEventUnavailableDoesNotAcceptEvent(t *testing.T) {
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

	// A member event for bob that hs1 never receives and cannot fetch.
	unreachable := srv.MustCreateEvent(t, srvRoom, federation.Event{
		Type:     spec.MRoomMember,
		Sender:   bob,
		StateKey: &bob,
		Content: map[string]interface{}{
			"membership":  "join",
			"displayname": "unreachable",
		},
	})
	srvRoom.AddEvent(unreachable)
	stateIDsEvent := srv.MustCreateEvent(t, srvRoom, federation.Event{
		Type:    "m.room.message",
		Sender:  bob,
		Content: map[string]interface{}{"msgtype": "m.text", "body": "for /state_ids"},
	})
	srvRoom.AddEvent(stateIDsEvent)
	gmeEvent := srv.MustCreateEvent(t, srvRoom, federation.Event{
		Type:    "m.room.message",
		Sender:  bob,
		Content: map[string]interface{}{"msgtype": "m.text", "body": "for /get_missing_events"},
	})
	srvRoom.AddEvent(gmeEvent)
	sendTxnEvent := srv.MustCreateEvent(t, srvRoom, federation.Event{
		Type:    "m.room.message",
		Sender:  bob,
		Content: map[string]interface{}{"msgtype": "m.text", "body": "for /send"},
	})
	srvRoom.AddEvent(sendTxnEvent)
	t.Logf("unreachable state event: %s", unreachable.EventID())
	t.Logf("event for /send: %s", sendTxnEvent.EventID())

	// /get_missing_events returns only gmeEvent, which leaves a gap before it.
	srv.Mux().HandleFunc("/_matrix/federation/v1/get_missing_events/{roomID}", func(w http.ResponseWriter, req *http.Request) {
		res, err := json.Marshal(struct {
			Events []gomatrixserverlib.PDU `json:"events"`
		}{Events: []gomatrixserverlib.PDU{gmeEvent}})
		must.NotError(t, "failed to marshal response", err)
		w.WriteHeader(200)
		w.Write(res)
	})

	// /state_ids lists the current state, including the unreachable event.
	stateIDsWaiter := helpers.NewWaiter()
	srv.Mux().HandleFunc("/_matrix/federation/v1/state_ids/{roomID}", func(w http.ResponseWriter, req *http.Request) {
		t.Logf("/state_ids req for room %s => %s", mux.Vars(req)["roomID"], req.URL.Query().Encode())
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
		must.NotError(t, "failed to marshal response", err)
		w.WriteHeader(200)
		w.Write(res)
		stateIDsWaiter.Finish()
	})

	// /event serves every event except the unreachable one, which fails with
	// a transient error.
	unreachableWaiter := helpers.NewWaiter()
	srv.Mux().Handle("/_matrix/federation/v1/event/{eventID}", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		eventID := mux.Vars(req)["eventID"]
		if eventID == unreachable.EventID() {
			t.Logf("/event returning 502 for the unreachable event")
			w.WriteHeader(502)
			unreachableWaiter.Finish()
			return
		}
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
		res, err := json.Marshal(gomatrixserverlib.Transaction{
			Origin:         spec.ServerName(srv.ServerName()),
			OriginServerTS: spec.AsTimestamp(time.Now()),
			PDUs:           []json.RawMessage{event.JSON()},
		})
		must.NotError(t, "failed to marshal response", err)
		w.WriteHeader(200)
		w.Write(res)
	}))

	srv.MustSendTransaction(t, deployment, "hs1", []json.RawMessage{sendTxnEvent.JSON()}, nil)
	stateIDsWaiter.Wait(t, 10*time.Second)
	unreachableWaiter.Wait(t, 10*time.Second)

	// A sentinel built on bob's original join, which hs1 knows, tells us when
	// hs1 has finished with sendTxnEvent.
	sentinel := srv.MustCreateEvent(t, srvRoom, federation.Event{
		Type:       "m.room.message",
		Sender:     bob,
		Content:    map[string]interface{}{"msgtype": "m.text", "body": "finished"},
		PrevEvents: []string{bobJoinEvent.EventID()},
		AuthEvents: []string{createEvent.EventID(), plEvent.EventID(), bobJoinEvent.EventID()},
	})
	srv.MustSendTransaction(t, deployment, "hs1", []json.RawMessage{sentinel.JSON()}, nil)
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, sentinel.EventID()))

	res := alice.Do(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "event", sendTxnEvent.EventID()})
	must.Equal(t, res.StatusCode, 404, "the event was accepted although the state before it could not be fetched")

	content := alice.MustGetStateEventContent(t, roomID, spec.MRoomMember, bob)
	must.Equal(t, content.Get("displayname").Str, "", "bob's membership changed to the unreachable event")
}
