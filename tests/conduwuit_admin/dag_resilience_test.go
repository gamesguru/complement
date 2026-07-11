package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/gomatrixserverlib/spec"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/match"
	"github.com/matrix-org/complement/must"
	"github.com/matrix-org/complement/runtime"
)

// TestDAGPathologyAndFederationResilience tests conduwuit's ability to handle complex DAG structures,
// import them, reorder timelines, and remain responsive to federation traffic without splintering.
func TestDAGPathologyAndFederationResilience(t *testing.T) {
	if runtime.Homeserver != runtime.Continuwuity {
		t.Skip("Skipping conduwuit-specific DAG resilience test on non-conduwuit homeserver")
	}

	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	// Phase 1: Base Import & Initial Load
	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	fixturePath := "/complement/tests/fixtures/pathology_fruitless_search.jsonl"
	if _, err := os.Stat("fixtures/pathology_fruitless_search.jsonl"); err == nil {
		fixturePath = "fixtures/pathology_fruitless_search.jsonl"
	}

	roomID := alice.MustCreateRoom(t, map[string]interface{}{
		"preset": "public_chat",
	})

	// Inject the fixture.
	adminRoom := helpers.CreateConduwuitAdminRoom(t, alice)
	helpers.SendConduwuitAdminCommand(t, alice, adminRoom, fmt.Sprintf("yolo import-pdus %s %s", roomID, fixturePath))

	srv := federation.NewServer(t, deployment,
		federation.HandleKeyRequests(),
		federation.HandleEventRequests(),
	)
	srv.UnexpectedRequestsAreErrors = false
	cancel := srv.Listen()
	defer cancel()

	bob := srv.UserID("bob")
	serverRoom := srv.MustJoinRoom(t, deployment, "hs1", roomID, bob)

	srv.Mux().HandleFunc("/_matrix/federation/v1/get_missing_events/{roomID}", func(w http.ResponseWriter, req *http.Request) {
		var events []json.RawMessage
		for _, ev := range serverRoom.Timeline {
			events = append(events, ev.JSON())
		}
		res := struct {
			Events []json.RawMessage `json:"events"`
		}{
			Events: events,
		}
		resBytes, _ := json.Marshal(&res)
		w.WriteHeader(200)
		w.Write(resBytes)
	})

	srv.Mux().HandleFunc("/_matrix/federation/v1/state_ids/{roomID}", func(w http.ResponseWriter, req *http.Request) {
		var authChainIDs []string
		var pduIDs []string
		for _, ev := range serverRoom.AllCurrentState() {
			pduIDs = append(pduIDs, ev.EventID())
			authChainIDs = append(authChainIDs, ev.EventID())
		}
		res := struct {
			AuthChainIDs []string `json:"auth_chain_ids"`
			PDUIDs       []string `json:"pdu_ids"`
		}{
			AuthChainIDs: authChainIDs,
			PDUIDs:       pduIDs,
		}
		resBytes, _ := json.Marshal(&res)
		w.WriteHeader(200)
		w.Write(resBytes)
	})

	t.Log("Sending initial backlog")
	var backlogEvents []gomatrixserverlib.PDU
	var backlogPDUs []json.RawMessage
	for i := 0; i < 50; i++ {
		msg := srv.MustCreateEvent(t, serverRoom, federation.Event{
			Type:   "m.room.message",
			Sender: bob,
			Content: map[string]interface{}{
				"msgtype": "m.text",
				"body":    fmt.Sprintf("backlog %03d", i),
			},
		})
		serverRoom.AddEvent(msg)
		backlogEvents = append(backlogEvents, msg)
		backlogPDUs = append(backlogPDUs, msg.JSON())
	}
	sendPDUBatches(t, srv, deployment, "hs1", backlogPDUs, 25)

	// Ensure hs1 has processed the backlog
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, backlogEvents[len(backlogEvents)-1].EventID()))

	localTip := alice.SendEventSynced(t, roomID, b.Event{
		Type: "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "local tip before fork",
		},
	})

	// Phase 2: Intentional DAG Forking
	t.Log("Generating intentional DAG fork")
	forkBase := backlogEvents[20]
	var forkPDUs []json.RawMessage
	var forkTip gomatrixserverlib.PDU

	for i := 0; i < 10; i++ {
		prevEvents := []string{forkBase.EventID()}
		if forkTip != nil {
			prevEvents = []string{forkTip.EventID()}
		}
		forkTip = srv.MustCreateEvent(t, serverRoom, federation.Event{
			Type:       "m.room.message",
			Sender:     bob,
			PrevEvents: prevEvents,
			Content: map[string]interface{}{
				"msgtype": "m.text",
				"body":    fmt.Sprintf("fork event %02d", i),
			},
		})
		serverRoom.AddEvent(forkTip)
		forkPDUs = append(forkPDUs, forkTip.JSON())
	}

	// Phase 3: State Event Complexities in the Fork
	t.Log("Injecting state complexities into the fork")
	stateForkEvent1 := srv.MustCreateEvent(t, serverRoom, federation.Event{
		Type:       "m.room.member",
		StateKey:   b.Ptr(bob),
		Sender:     bob,
		PrevEvents: []string{forkTip.EventID()},
		Content: map[string]interface{}{
			"membership":  "join",
			"displayname": "Bob The Builder",
			"avatar_url":  "mxc://hs2/avatar_fork",
		},
	})
	serverRoom.AddEvent(stateForkEvent1)
	forkPDUs = append(forkPDUs, stateForkEvent1.JSON())
	forkTip = stateForkEvent1

	stateForkEvent2 := srv.MustCreateEvent(t, serverRoom, federation.Event{
		Type:       "m.room.message",
		Sender:     bob,
		PrevEvents: []string{forkTip.EventID()},
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "Another event in the fork",
		},
	})
	serverRoom.AddEvent(stateForkEvent2)
	forkPDUs = append(forkPDUs, stateForkEvent2.JSON())
	forkTip = stateForkEvent2

	// Fire yolo command to crunch the graph concurrently
	t.Log("Triggering yolo reorder-timeline")
	helpers.SendConduwuitAdminCommand(t, alice, adminRoom, fmt.Sprintf("yolo reorder-timeline %s", roomID))

	sendPDUBatches(t, srv, deployment, "hs1", forkPDUs, 10)

	// Phase 4: Merging and Outliers
	t.Log("Merging fork and local tip")
	mergeTip := srv.MustCreateEvent(t, serverRoom, federation.Event{
		Type:       "m.room.message",
		Sender:     bob,
		PrevEvents: []string{forkTip.EventID(), localTip},
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "merge event",
		},
	})
	serverRoom.AddEvent(mergeTip)
	srv.MustSendTransaction(t, deployment, "hs1", []json.RawMessage{mergeTip.JSON()}, nil)

	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, mergeTip.EventID()))

	t.Log("Triggering yolo force-set-state")
	helpers.SendConduwuitAdminCommand(t, alice, adminRoom, fmt.Sprintf("yolo force-set-state %s hs2", roomID))

	t.Log("Sending outlier event")
	outlierChild := srv.MustCreateEvent(t, serverRoom, federation.Event{
		Type:   "m.room.message",
		Sender: bob,
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "outlier child",
		},
		PrevEvents: []string{mergeTip.EventID()},
		AuthEvents: []interface{}{
			serverRoom.CurrentState("m.room.create", "").EventID(),
			serverRoom.CurrentState("m.room.join_rules", "").EventID(),
			serverRoom.CurrentState("m.room.power_levels", "").EventID(),
			serverRoom.CurrentState("m.room.member", bob).EventID(),
		},
	})
	serverRoom.TimelineMutex.Lock()
	serverRoom.Timeline = append(serverRoom.Timeline, outlierChild)
	serverRoom.TimelineMutex.Unlock()

	carrier := srv.MustCreateEvent(t, serverRoom, federation.Event{
		Type:   "m.room.message",
		Sender: bob,
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "carrier for outlier",
		},
		PrevEvents: []string{outlierChild.EventID()}, // Creates the gap
		AuthEvents: []interface{}{
			serverRoom.CurrentState("m.room.create", "").EventID(),
			serverRoom.CurrentState("m.room.join_rules", "").EventID(),
			serverRoom.CurrentState("m.room.power_levels", "").EventID(),
			serverRoom.CurrentState("m.room.member", bob).EventID(),
		},
	})
	srv.MustSendTransaction(t, deployment, "hs1", []json.RawMessage{carrier.JSON()}, nil)

	// Phase 5: Backfill Validation
	t.Log("Validating /backfill over the complex DAG")
	fedClient := srv.FederationClient(deployment)
	backfillResp, err := fedClient.Backfill(context.Background(), srv.ServerName(), "hs1", roomID, 10, []string{mergeTip.EventID()})
	must.NotError(t, "failed to backfill from hs1", err)
	if len(backfillResp.PDUs) == 0 {
		t.Fatalf("expected PDUs from backfill, got none")
	}

	// Phase 6: Final State Assertion
	t.Log("Validating final local state assertion")
	localAfterOutlier := alice.SendEventSynced(t, roomID, b.Event{
		Type: "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "after outlier",
		},
	})

	res := alice.MustDo(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "event", localAfterOutlier})
	must.MatchResponse(t, res, match.HTTPResponse{
		StatusCode: http.StatusOK,
	})

	t.Log("Validating DAG via get-room-dag yolo command")
	helpers.SendConduwuitAdminCommand(t, alice, adminRoom, fmt.Sprintf("yolo get-room-dag %s", roomID))
}

func sendPDUBatches(t *testing.T, srv *federation.Server, deployment complement.Deployment, destination spec.ServerName, pdus []json.RawMessage, batchSize int) {
	t.Helper()
	for start := 0; start < len(pdus); start += batchSize {
		end := start + batchSize
		if end > len(pdus) {
			end = len(pdus)
		}
		srv.MustSendTransaction(t, deployment, destination, pdus[start:end], nil)
	}
}
