package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/must"
	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/gjson"
)

func TestForwardExtremitySurvivesOutlierChild(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	srv := federation.NewServer(t, deployment,
		federation.HandleKeyRequests(),
		federation.HandleMakeSendJoinRequests(),
		federation.HandleEventRequests(),
		federation.HandleTransactionRequests(nil, nil),
	)
	srv.UnexpectedRequestsAreErrors = false
	cancel := srv.Listen()
	defer cancel()

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	bob := srv.UserID("bob")
	ver := alice.GetDefaultRoomVersion(t)
	room := srv.MustMakeRoom(t, ver, federation.InitialRoomEvents(ver, bob))

	alice.MustJoinRoom(t, room.RoomID, []spec.ServerName{srv.ServerName()})
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(alice.UserID, room.RoomID))

	destination := deployment.GetFullyQualifiedHomeserverName(t, "hs1")
	remoteMembers := make([]string, 20)
	memberEvents := make([]gomatrixserverlib.PDU, 0, len(remoteMembers))
	memberPDUs := make([]json.RawMessage, 0, len(remoteMembers))
	for i := range remoteMembers {
		userID := srv.UserID(fmt.Sprintf("remote-%02d", i))
		remoteMembers[i] = userID
		memberEvent := srv.MustCreateEvent(t, room, federation.Event{
			Type:     "m.room.member",
			StateKey: &userID,
			Sender:   userID,
			Content: map[string]interface{}{
				"membership": "join",
			},
		})
		room.AddEvent(memberEvent)
		memberEvents = append(memberEvents, memberEvent)
		memberPDUs = append(memberPDUs, memberEvent.JSON())
	}
	sendPDUBatches(t, srv, deployment, destination, memberPDUs, 20)
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(room.RoomID, memberEvents[len(memberEvents)-1].EventID()))

	backlogPDUs := make([]json.RawMessage, 0, 120)
	backlogEvents := make([]gomatrixserverlib.PDU, 0, 120)
	for i := 0; i < 120; i++ {
		sender := remoteMembers[i%len(remoteMembers)]
		msg := srv.MustCreateEvent(t, room, federation.Event{
			Type:   "m.room.message",
			Sender: sender,
			Content: map[string]interface{}{
				"msgtype": "m.text",
				"body":    fmt.Sprintf("accepted backlog %03d", i),
			},
		})
		room.AddEvent(msg)
		backlogEvents = append(backlogEvents, msg)
		backlogPDUs = append(backlogPDUs, msg.JSON())
	}
	sendPDUBatches(t, srv, deployment, destination, backlogPDUs, 25)
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(room.RoomID, backlogEvents[len(backlogEvents)-1].EventID()))

	localTip := alice.SendEventSynced(t, room.RoomID, b.Event{
		Type: "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "accepted tip",
		},
	})
	room.WaiterForEvent(localTip).Waitf(t, 5*time.Second, "remote server did not receive accepted tip %s", localTip)

	forkBase := backlogEvents[70]
	forkPDUs := make([]json.RawMessage, 0, 12)
	var forkTip gomatrixserverlib.PDU
	for i := 0; i < 12; i++ {
		prevEvents := []string{forkBase.EventID()}
		if forkTip != nil {
			prevEvents = []string{forkTip.EventID()}
		}
		forkTip = srv.MustCreateEvent(t, room, federation.Event{
			Type:       "m.room.message",
			Sender:     remoteMembers[(i+3)%len(remoteMembers)],
			PrevEvents: prevEvents,
			Content: map[string]interface{}{
				"msgtype": "m.text",
				"body":    fmt.Sprintf("older fork %02d", i),
			},
		})
		room.AddEvent(forkTip)
		forkPDUs = append(forkPDUs, forkTip.JSON())
	}
	sendPDUBatches(t, srv, deployment, destination, forkPDUs, 12)
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(room.RoomID, forkTip.EventID()))

	mergeTip := srv.MustCreateEvent(t, room, federation.Event{
		Type:       "m.room.message",
		Sender:     remoteMembers[0],
		PrevEvents: []string{forkTip.EventID(), localTip},
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "accepted merge",
		},
	})
	room.AddEvent(mergeTip)
	srv.MustSendTransaction(t, deployment, destination, []json.RawMessage{mergeTip.JSON()}, nil)
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(room.RoomID, mergeTip.EventID()))

	rejectedEvent := srv.MustCreateEvent(t, room, federation.Event{
		Type:     "m.room.power_levels",
		StateKey: b.Ptr(""),
		Sender:   remoteMembers[1],
		Content: map[string]interface{}{
			"users": map[string]interface{}{},
		},
	})
	fedClient := srv.FederationClient(deployment)
	resp, err := fedClient.SendTransaction(context.Background(), gomatrixserverlib.Transaction{
		TransactionID:  "rejected-auth-event",
		Origin:         srv.ServerName(),
		Destination:    destination,
		OriginServerTS: spec.AsTimestamp(time.Now()),
		PDUs: []json.RawMessage{
			rejectedEvent.JSON(),
		},
	})
	must.NotError(t, "failed to send rejected auth event", err)
	if result := resp.PDUs[rejectedEvent.EventID()]; result.Error == "" {
		t.Fatalf("expected rejected auth event %s to be rejected", rejectedEvent.EventID())
	}

	outlierChild := srv.MustCreateEvent(t, room, federation.Event{
		Type:   "m.room.message",
		Sender: remoteMembers[2],
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "outlier child",
		},
		PrevEvents: []string{mergeTip.EventID()},
		AuthEvents: []interface{}{
			room.CurrentState("m.room.create", "").EventID(),
			room.CurrentState("m.room.join_rules", "").EventID(),
			rejectedEvent.EventID(),
			room.CurrentState("m.room.member", remoteMembers[2]).EventID(),
		},
	})
	room.TimelineMutex.Lock()
	room.Timeline = append(room.Timeline, outlierChild)
	room.TimelineMutex.Unlock()

	carrier := srv.MustCreateEvent(t, room, federation.Event{
		Type:   "m.room.message",
		Sender: remoteMembers[3],
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "carrier",
		},
		AuthEvents: []interface{}{
			room.CurrentState("m.room.create", "").EventID(),
			room.CurrentState("m.room.join_rules", "").EventID(),
			room.CurrentState("m.room.power_levels", "").EventID(),
			room.CurrentState("m.room.member", remoteMembers[3]).EventID(),
			outlierChild.EventID(),
		},
	})
	resp, err = fedClient.SendTransaction(context.Background(), gomatrixserverlib.Transaction{
		TransactionID:  "pull-outlier-child",
		Origin:         srv.ServerName(),
		Destination:    destination,
		OriginServerTS: spec.AsTimestamp(time.Now()),
		PDUs: []json.RawMessage{
			carrier.JSON(),
		},
	})
	must.NotError(t, "failed to send carrier event", err)
	if result, ok := resp.PDUs[carrier.EventID()]; !ok || result.Error == "" {
		t.Fatalf("expected carrier event %s to be processed and rejected, got %v", carrier.EventID(), resp.PDUs)
	}

	localAfterOutlier := alice.SendEventSynced(t, room.RoomID, b.Event{
		Type: "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "after outlier",
		},
	})
	room.WaiterForEvent(localAfterOutlier).Waitf(t, 5*time.Second, "remote server did not receive follow-up event %s", localAfterOutlier)

	received, ok := room.GetEventInTimeline(localAfterOutlier)
	if !ok {
		t.Fatalf("follow-up event %s was not stored on remote test server", localAfterOutlier)
	}
	prevEvents := gjson.ParseBytes(received.JSON()).Get("prev_events").Array()
	for _, prev := range prevEvents {
		if prev.Str == mergeTip.EventID() {
			return
		}
	}
	t.Fatalf(
		"follow-up event %s did not retain accepted tip %s as a prev_event after learning outlier child %s; prev_events=%v",
		localAfterOutlier,
		mergeTip.EventID(),
		outlierChild.EventID(),
		prevEvents,
	)
}

func sendPDUBatches(t *testing.T, srv *federation.Server, deployment federation.FederationDeployment, destination spec.ServerName, pdus []json.RawMessage, batchSize int) {
	t.Helper()
	for start := 0; start < len(pdus); start += batchSize {
		end := start + batchSize
		if end > len(pdus) {
			end = len(pdus)
		}
		srv.MustSendTransaction(t, deployment, destination, pdus[start:end], nil)
	}
}
