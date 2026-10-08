//go:build !dendrite_blacklist && !venator_blacklist

// Venator does not yet implement federation.

package activeedurecon

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/url"
	"testing"

	"github.com/Wombat-Foundation/gomatrixcrypto/reconcile"
	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/must"
	"github.com/matrix-org/gomatrixserverlib/fclient"
	"github.com/tidwall/gjson"
)

// TestMSC4521ActiveRoomReconciliation verifies the first real wire-level
// operation in the MSC0501 consumer flow for MSC4521. A remote federation
// server queries the homeserver under test for a frame-bound digest and strata
// estimator before opening a symmetric-difference sketch exchange.
//
// This is deliberately an integration test: the reconciliation library tests
// cannot prove that a homeserver stores, authorizes, scopes, and serves EDU
// state correctly.
func TestMSC4521ActiveRoomReconciliation(t *testing.T) {
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
	var frameID string
	var frameEventIDs []string

	t.Run("Digest", func(t *testing.T) {
		body, status := getRoomDigest(t, srv, deployment, roomID, "")
		t.Logf("/room_digest/{roomID} response: %s", body)
		must.Equal(t, status, 200, "MSC0501 room digest status")

		digest := gjson.ParseBytes(body)
		must.Equal(t, digest.Get("digest_type").Str, "algebraic_v1", "digest type")
		must.Equal(t, digest.Get("digest").Str != "", true, "digest")
		frameID = digest.Get("frame_id").Str
		must.Equal(t, frameID != "", true, "frame id")
		must.Equal(t, digest.Get("known_event_count").Int() > 0, true, "known event count")
		must.Equal(t, len(digest.Get("strata").Array()), 0, "base digest must not include strata")
	})

	t.Run("Strata", func(t *testing.T) {
		body, status := getRoomDigest(t, srv, deployment, roomID, "/strata")
		t.Logf("/room_digest/{roomID}/strata response: %s", body)
		must.Equal(t, status, 200, "MSC0501 room digest strata status")

		digest := gjson.ParseBytes(body)
		must.Equal(t, digest.Get("digest_type").Str, "algebraic_v1", "digest type")
		must.Equal(t, digest.Get("digest").Str != "", true, "digest")
		must.Equal(t, digest.Get("frame_id").Str, frameID, "frame id")
		must.Equal(t, digest.Get("known_event_count").Int() > 0, true, "known event count")
		must.Equal(t, len(digest.Get("strata").Array()), 32, "strata count")
		for _, eventID := range digest.Get("frame_event_ids").Array() {
			frameEventIDs = append(frameEventIDs, eventID.Str)
		}
		must.Equal(t, len(frameEventIDs) > 0, true, "frame anchors")
	})

	t.Run("SketchDiff", func(t *testing.T) {
		extra := srv.MustCreateEvent(t, serverRoom, federation.Event{
			Sender:  charlie,
			Type:    "m.room.message",
			Content: map[string]interface{}{"body": "remote-only MSC4521 event"},
		})
		serverRoom.AddEvent(extra)

		var local reconcile.ResidentKernel
		for _, event := range serverRoom.Timeline {
			hash, err := reconcile.FromMatrixEventID(event.EventID(), reconcile.V4Plus)
			must.NotError(t, "hash remote event ID", err)
			must.NotError(t, "insert remote event ID", local.Insert(hash))
		}

		sketch, err := reconcile.NewSyndromeSketch(2)
		must.NotError(t, "new root sketch", err)
		for _, event := range serverRoom.Timeline {
			hash, err := reconcile.FromMatrixEventID(event.EventID(), reconcile.V4Plus)
			must.NotError(t, "hash remote event ID for sketch", err)
			must.NotError(t, "toggle remote event ID", sketch.Toggle(hash.H64))
		}

		requestBody, err := json.Marshal(map[string]interface{}{
			"mode":                    "sketch",
			"frame_id":                frameID,
			"local_digest":            local.Accumulator().EncodeDigest(),
			"digest_type":             "algebraic_v1",
			"local_known_event_count": local.Accumulator().Count,
			"frame_event_ids":         frameEventIDs,
			"estimated_delta":         1,
			"requests":                []map[string]interface{}{{"depth": 0, "prefix": 0, "capacity": 2}},
			"local_sketches":          []string{sketch.Encode()},
			"limit":                   100,
		})
		must.NotError(t, "encode room_diff request", err)

		path := "/_matrix/federation/unstable/tk.nutra.msc0501/room_diff/" + url.PathEscape(roomID)
		req := fclient.NewFederationRequest("POST", srv.ServerName(), deployment.GetFullyQualifiedHomeserverName(t, "hs1"), path)
		must.NotError(t, "set room_diff request", req.SetContent(requestBody))
		res, err := srv.DoFederationRequest(context.Background(), t, deployment, req)
		must.NotError(t, "POST /room_diff/{roomID}", err)
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		must.NotError(t, "read room_diff response", err)
		t.Logf("/room_diff/{roomID} response: %s", body)
		must.Equal(t, res.StatusCode, 200, "MSC0501 room diff status")

		response := gjson.ParseBytes(body)
		must.Equal(t, response.Get("digest_type").Str, "algebraic_v1", "room diff digest type")
		must.Equal(t, response.Get("frame_id").Str, frameID, "room diff frame")
		must.Equal(t, len(response.Get("missing_event_ids").Array()), 0, "homeserver has no event absent from inspector")
		hash := reconcileHash(t, extra.EventID())
		shortID := make([]byte, 8)
		binary.BigEndian.PutUint64(shortID, hash)
		wantShortID := base64.RawURLEncoding.EncodeToString(shortID)
		must.Equal(t, response.Get("requester_only_short_ids.0").Str, wantShortID, "requester-only short ID")
	})
}

func reconcileHash(t *testing.T, eventID string) uint64 {
	t.Helper()
	hash, err := reconcile.FromMatrixEventID(eventID, reconcile.V4Plus)
	must.NotError(t, "hash event ID", err)
	return hash.H64
}

func getRoomDigest(t *testing.T, srv *federation.Server, deployment complement.Deployment, roomID, suffix string) ([]byte, int) {
	t.Helper()
	path := "/_matrix/federation/unstable/tk.nutra.msc0501/room_digest/" + url.PathEscape(roomID) + suffix
	req := fclient.NewFederationRequest(
		"GET",
		srv.ServerName(),
		deployment.GetFullyQualifiedHomeserverName(t, "hs1"),
		path,
	)
	res, err := srv.DoFederationRequest(context.Background(), t, deployment, req)
	must.NotError(t, "GET "+path, err)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	must.NotError(t, "read "+path+" response", err)
	return body, res.StatusCode
}
