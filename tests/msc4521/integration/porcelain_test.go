//go:build !dendrite_blacklist && !venator_blacklist

// Venator does not yet implement federation.

package integration

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/url"
	"slices"
	"testing"

	"github.com/Wombat-Foundation/gomatrixcrypto/reconcile"
	"github.com/matrix-org/gomatrixserverlib/fclient"
	"github.com/tidwall/gjson"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/must"
)

// TestMSC4521HomeserverPorcelain runs the scenarios of the library-level
// Porcelain vectors (tests/msc4521) against a real homeserver: a remote
// federation server holds one side of the set, hs1 holds the other, and the
// difference is recovered over /room_digest and /room_diff.
func TestMSC4521HomeserverPorcelain(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	srv := federation.NewServer(t, deployment,
		federation.HandleKeyRequests(),
		federation.HandleMakeSendJoinRequests(),
		federation.HandleTransactionRequests(nil, nil),
	)
	cancel := srv.Listen()
	defer cancel()

	roomID := alice.MustCreateRoom(t, map[string]interface{}{"preset": "public_chat"})
	charlie := srv.UserID("charlie")
	serverRoom := srv.MustJoinRoom(t, deployment, deployment.GetFullyQualifiedHomeserverName(t, "hs1"), roomID, charlie)

	t.Run("IdenticalSets", func(t *testing.T) {
		body, status := getRoomDigest(t, srv, deployment, roomID, "")
		must.Equal(t, status, 200, "room digest status")
		digest := gjson.ParseBytes(body)

		local := kernelOf(t, serverRoom)
		must.Equal(t, local.Accumulator().Count, uint64(digest.Get("known_event_count").Uint()),
			"identical sets must agree on count")
		must.Equal(t, local.Accumulator().EncodeDigest(), digest.Get("digest").Str,
			"identical sets must agree on digest")

		// With nothing to reconcile the homeserver reports no difference.
		response := requestRoomDiff(t, srv, deployment, roomID, local, serverRoom, 2)
		must.Equal(t, len(response.Get("missing_event_ids").Array()), 0, "no events missing from requester")
		must.Equal(t, len(response.Get("requester_only_short_ids").Array()), 0, "no requester-only events")
	})

	t.Run("HomeserverOnly", func(t *testing.T) {
		// The remote server ignores transactions, so this event stays unknown to it.
		eventID := alice.SendEventSynced(t, roomID, b.Event{
			Type:    "m.room.message",
			Content: map[string]interface{}{"msgtype": "m.text", "body": "homeserver-only MSC4521 event"},
		})

		local := kernelOf(t, serverRoom)
		response := requestRoomDiff(t, srv, deployment, roomID, local, serverRoom, 2)
		missing := stringsOf(response.Get("missing_event_ids"))
		must.Equal(t, slices.Contains(missing, eventID), true, "homeserver event is reported missing from the requester")
		must.Equal(t, len(response.Get("requester_only_short_ids").Array()), 0, "no requester-only events")
	})

	t.Run("SymmetricDifference", func(t *testing.T) {
		extra := srv.MustCreateEvent(t, serverRoom, federation.Event{
			Sender:  charlie,
			Type:    "m.room.message",
			Content: map[string]interface{}{"body": "remote-only MSC4521 event"},
		})
		serverRoom.AddEvent(extra)

		local := kernelOf(t, serverRoom)
		response := requestRoomDiff(t, srv, deployment, roomID, local, serverRoom, 8)
		must.Equal(t, len(response.Get("missing_event_ids").Array()) > 0, true, "homeserver-only events are reported")
		wantShort := shortID(reconcileHash(t, extra.EventID()))
		must.Equal(t, slices.Contains(stringsOf(response.Get("requester_only_short_ids")), wantShort), true,
			"requester-only event is reported by short ID")
	})

	t.Run("MalformedInputs", func(t *testing.T) {
		local := kernelOf(t, serverRoom)
		valid := roomDiffBody(t, loadFrame(t, srv, deployment, roomID), local, serverRoom, 2)

		for name, mutate := range map[string]func(map[string]interface{}){
			"UnknownDigestType": func(b map[string]interface{}) { b["digest_type"] = "nope" },
			"UndecodableSketch": func(b map[string]interface{}) { b["local_sketches"] = []string{"!!not-base64!!"} },
			"ZeroCapacity": func(b map[string]interface{}) {
				b["requests"] = []map[string]interface{}{{"depth": 0, "prefix": 0, "capacity": 0}}
			},
			"UnknownFrame":         func(b map[string]interface{}) { b["frame_id"] = "not-a-frame" },
			"MalformedFrameAnchor": func(b map[string]interface{}) { b["frame_event_ids"] = []string{"not-an-event-id"} },
		} {
			t.Run(name, func(t *testing.T) {
				body := map[string]interface{}{}
				for k, v := range valid {
					body[k] = v
				}
				mutate(body)
				_, status := doRoomDiff(t, srv, deployment, roomID, body)
				// A malformed request is the requester's fault: a client error,
				// never a success and never a server error.
				must.Equal(t, status >= 400 && status < 500, true, "malformed room_diff must be a 4xx")
			})
		}
	})
}

// kernelOf builds the requester's view of the set from its own timeline.
func kernelOf(t *testing.T, room *federation.ServerRoom) reconcile.ResidentKernel {
	t.Helper()
	kernel := reconcile.NewResidentKernel()
	for _, event := range room.Timeline {
		hash, err := reconcile.FromMatrixEventID(event.EventID(), reconcile.V4Plus)
		must.NotError(t, "hash event ID", err)
		must.NotError(t, "insert event ID", kernel.Insert(hash))
	}
	return kernel
}

// roomDiffBody builds a sketch-mode room_diff request from the requester's set.
func roomDiffBody(t *testing.T, f frame, local reconcile.ResidentKernel, room *federation.ServerRoom, capacity int) map[string]interface{} {
	t.Helper()
	sketch, err := reconcile.NewSyndromeSketch(capacity)
	must.NotError(t, "new root sketch", err)
	for _, event := range room.Timeline {
		must.NotError(t, "toggle event ID", sketch.Toggle(reconcileHash(t, event.EventID())))
	}
	return map[string]interface{}{
		"mode":                    "sketch",
		"frame_id":                f.id,
		"local_digest":            local.Accumulator().EncodeDigest(),
		"digest_type":             "algebraic_v1",
		"local_known_event_count": local.Accumulator().Count,
		"frame_event_ids":         f.anchors,
		"estimated_delta":         capacity,
		"requests":                []map[string]interface{}{{"depth": 0, "prefix": 0, "capacity": capacity}},
		"local_sketches":          []string{sketch.Encode()},
		"limit":                   100,
	}
}

func requestRoomDiff(t *testing.T, srv *federation.Server, deployment complement.Deployment, roomID string, local reconcile.ResidentKernel, room *federation.ServerRoom, capacity int) gjson.Result {
	t.Helper()
	f := loadFrame(t, srv, deployment, roomID)
	body, status := doRoomDiff(t, srv, deployment, roomID, roomDiffBody(t, f, local, room, capacity))
	must.Equal(t, status, 200, "room diff status")
	return gjson.ParseBytes(body)
}

func doRoomDiff(t *testing.T, srv *federation.Server, deployment complement.Deployment, roomID string, body map[string]interface{}) ([]byte, int) {
	t.Helper()
	requestBody, err := json.Marshal(body)
	must.NotError(t, "encode room_diff request", err)
	path := msc4521Prefix + "room_diff/" + url.PathEscape(roomID)
	req := fclient.NewFederationRequest("POST", srv.ServerName(), deployment.GetFullyQualifiedHomeserverName(t, "hs1"), path)
	must.NotError(t, "set room_diff request", req.SetContent(requestBody))
	res, err := srv.DoFederationRequest(context.Background(), t, deployment, req)
	must.NotError(t, "POST "+path, err)
	defer res.Body.Close()
	out, err := io.ReadAll(res.Body)
	must.NotError(t, "read room_diff response", err)
	return out, res.StatusCode
}

// frame is the frame the homeserver reports; room_diff requests are bound to it.
type frame struct {
	id      string
	anchors []string
}

func loadFrame(t *testing.T, srv *federation.Server, deployment complement.Deployment, roomID string) frame {
	t.Helper()
	body, status := getRoomDigest(t, srv, deployment, roomID, "/strata")
	must.Equal(t, status, 200, "room digest strata status")
	digest := gjson.ParseBytes(body)
	return frame{id: digest.Get("frame_id").Str, anchors: stringsOf(digest.Get("frame_event_ids"))}
}

func stringsOf(result gjson.Result) []string {
	var out []string
	for _, v := range result.Array() {
		out = append(out, v.Str)
	}
	return out
}

func shortID(hash uint64) string {
	raw := make([]byte, 8)
	binary.BigEndian.PutUint64(raw, hash)
	return base64.RawURLEncoding.EncodeToString(raw)
}
