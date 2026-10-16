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
	"os"
	"slices"
	"testing"

	"github.com/Wombat-Foundation/gomatrixcrypto/reconcile"
	"github.com/matrix-org/gomatrixserverlib/fclient"
	"github.com/tidwall/gjson"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/must"
)

// homeserverSide is the real-homeserver half of TestMSC4521SetReconciliation:
// a remote federation server holds one side of the set, hs1 holds the other,
// and the difference is recovered over /room_digest and /room_diff. A nil
// *homeserverSide means no Complement runner is configured, and every method is
// then a no-op so the test degrades to the plain library checks.
type homeserverSide struct {
	deployment complement.Deployment
	alice      *client.CSAPI
	srv        *federation.Server
	roomID     string
	charlie    string
	serverRoom *federation.ServerRoom
}

func newHomeserverSide(t *testing.T) *homeserverSide {
	t.Helper()
	if os.Getenv("COMPLEMENT_BASE_IMAGE") == "" {
		t.Log("no Complement runner: running the library checks only")
		return nil
	}
	deployment := complement.Deploy(t, 1)
	t.Cleanup(func() { deployment.Destroy(t) })

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	srv := federation.NewServer(t, deployment,
		federation.HandleKeyRequests(),
		federation.HandleMakeSendJoinRequests(),
		federation.HandleTransactionRequests(nil, nil),
	)
	t.Cleanup(srv.Listen())

	roomID := alice.MustCreateRoom(t, map[string]interface{}{"preset": "public_chat"})
	charlie := srv.UserID("charlie")
	serverRoom := srv.MustJoinRoom(t, deployment, deployment.GetFullyQualifiedHomeserverName(t, "hs1"), roomID, charlie)
	return &homeserverSide{deployment, alice, srv, roomID, charlie, serverRoom}
}

// identicalSets: with nothing to reconcile both sides agree on count and
// digest, and the homeserver reports no difference.
func (h *homeserverSide) identicalSets(t *testing.T) {
	if h == nil {
		return
	}
	t.Helper()
	body, status := getRoomDigest(t, h.srv, h.deployment, h.roomID, "")
	must.Equal(t, status, 200, "room digest status")
	digest := gjson.ParseBytes(body)

	local := kernelOf(t, h.serverRoom)
	must.Equal(t, local.Accumulator().Count, digest.Get("known_event_count").Uint(),
		"identical sets must agree on count")
	must.Equal(t, local.Accumulator().EncodeDigest(), digest.Get("digest").Str,
		"identical sets must agree on digest")

	response := h.diff(t, local, 2)
	must.Equal(t, len(response.Get("missing_event_ids").Array()), 0, "no events missing from requester")
	must.Equal(t, len(response.Get("requester_only_short_ids").Array()), 0, "no requester-only events")
}

// homeserverOnly: an event only hs1 has is reported as missing from the
// requester (the remote server ignores transactions, so it never sees it).
func (h *homeserverSide) homeserverOnly(t *testing.T) {
	if h == nil {
		return
	}
	t.Helper()
	eventID := h.alice.SendEventSynced(t, h.roomID, b.Event{
		Type:    "m.room.message",
		Content: map[string]interface{}{"msgtype": "m.text", "body": "homeserver-only MSC4521 event"},
	})
	response := h.diff(t, kernelOf(t, h.serverRoom), 2)
	missing := stringsOf(response.Get("missing_event_ids"))
	must.Equal(t, slices.Contains(missing, eventID), true, "homeserver event is reported missing from the requester")
	must.Equal(t, len(response.Get("requester_only_short_ids").Array()), 0, "no requester-only events")
}

// symmetricDifference: each side has an event the other lacks, and both are
// recovered.
func (h *homeserverSide) symmetricDifference(t *testing.T) {
	if h == nil {
		return
	}
	t.Helper()
	extra := h.srv.MustCreateEvent(t, h.serverRoom, federation.Event{
		Sender:  h.charlie,
		Type:    "m.room.message",
		Content: map[string]interface{}{"body": "remote-only MSC4521 event"},
	})
	h.serverRoom.AddEvent(extra)

	response := h.diff(t, kernelOf(t, h.serverRoom), 8)
	must.Equal(t, len(response.Get("missing_event_ids").Array()) > 0, true, "homeserver-only events are reported")
	wantShort := shortID(reconcileHash(t, extra.EventID()))
	must.Equal(t, slices.Contains(stringsOf(response.Get("requester_only_short_ids")), wantShort), true,
		"requester-only event is reported by short ID")
}

// malformedInputs: a malformed room_diff is the requester's fault, so it must
// be a 4xx other than "route not found".
func (h *homeserverSide) malformedInputs(t *testing.T) {
	if h == nil {
		return
	}
	t.Helper()
	valid := roomDiffBody(t, h.loadFrame(t), kernelOf(t, h.serverRoom), h.serverRoom, 2)
	// Sanity: the unmodified request must be accepted, otherwise every 4xx
	// below could just be the route being missing.
	_, status := doRoomDiff(t, h.srv, h.deployment, h.roomID, valid)
	must.Equal(t, status, 200, "unmodified room_diff request")

	cases := map[string]func(map[string]interface{}){
		"UnknownDigestType": func(b map[string]interface{}) { b["digest_type"] = "nope" },
		"UndecodableSketch": func(b map[string]interface{}) { b["local_sketches"] = []string{"!!not-base64!!"} },
		"ZeroCapacity": func(b map[string]interface{}) {
			b["requests"] = []map[string]interface{}{{"depth": 0, "prefix": 0, "capacity": 0}}
		},
		"UnknownFrame":         func(b map[string]interface{}) { b["frame_id"] = "not-a-frame" },
		"MalformedFrameAnchor": func(b map[string]interface{}) { b["frame_event_ids"] = []string{"not-an-event-id"} },
	}
	for name, mutate := range cases {
		t.Run("Homeserver/"+name, func(t *testing.T) {
			body := map[string]interface{}{}
			for k, v := range valid {
				body[k] = v
			}
			mutate(body)
			_, status := doRoomDiff(t, h.srv, h.deployment, h.roomID, body)
			must.Equal(t, status >= 400 && status < 500 && status != 404, true,
				"malformed room_diff must be a client error, not success, 404 or 5xx")
		})
	}
}

func (h *homeserverSide) loadFrame(t *testing.T) frame {
	t.Helper()
	return loadFrame(t, h.srv, h.deployment, h.roomID)
}

func (h *homeserverSide) diff(t *testing.T, local reconcile.ResidentKernel, capacity int) gjson.Result {
	t.Helper()
	body, status := doRoomDiff(t, h.srv, h.deployment, h.roomID, roomDiffBody(t, h.loadFrame(t), local, h.serverRoom, capacity))
	must.Equal(t, status, 200, "room diff status")
	return gjson.ParseBytes(body)
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
