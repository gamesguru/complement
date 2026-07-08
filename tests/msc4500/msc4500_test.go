package msc4500

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"testing"
	"time"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/match"
	"github.com/matrix-org/complement/must"
	"github.com/matrix-org/gomatrixserverlib/fclient"
	"github.com/tidwall/gjson"
	"golang.org/x/crypto/blake2b"
)

// TestMSC4500StateAccumulator verifies that the state_accumulator endpoint
// returns a valid 2048-byte base64url encoded lattice and the matching BLAKE2b-256 digest.
func TestMSC4500StateAccumulator(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	roomID := alice.MustCreateRoom(t, map[string]interface{}{
		"preset": "public_chat",
	})

	token := alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(alice.UserID, roomID))

	// Get the last event ID from the sync
	res := alice.MustDo(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "messages"}, client.WithQueries(url.Values{
		"dir":   {"b"},
		"limit": {"1"},
		"from":  {token},
	}))
	body := must.ParseJSON(t, res.Body)
	eventID := body.Get("chunk.0.event_id").Str

	must.NotEqual(t, eventID, "", "Failed to find event ID")

	// Call the federation endpoint using alice's homeserver
	fedRes := deployment.UnauthenticatedClient(t, "hs1").MustDo(t, "GET", []string{"_matrix", "federation", "unstable", "tk.nutra.msc4500", "state_accumulator", roomID}, client.WithQueries(url.Values{
		"event_id": {eventID},
	}))

	fedBody := must.ParseJSON(t, fedRes.Body)

	must.MatchGJSON(t, fedBody, match.JSONKeyEqual("event_id", eventID))
	must.MatchGJSON(t, fedBody, match.JSONKeyEqual("algorithm", "lthash16"))

	latticeB64 := fedBody.Get("lattice").Str
	digestHex := fedBody.Get("digest").Str

	must.NotEqual(t, latticeB64, "", "Lattice is empty")
	must.Equal(t, len(digestHex), 64, "Digest is not 64 hex characters")

	// Verify the digest matches the lattice
	latticeBytes, err := base64.RawURLEncoding.DecodeString(latticeB64)
	must.NotError(t, "base64 decode", err)
	must.Equal(t, len(latticeBytes), 2048, "Lattice is not 2048 bytes")

	hash := blake2b.Sum256(latticeBytes)
	expectedDigestHex := hex.EncodeToString(hash[:])

	must.Equal(t, digestHex, expectedDigestHex, "Digest does not match BLAKE2b-256 of lattice")
}

func TestMSC4500StateHashMismatch(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	// Create a remote homeserver
	srv := federation.NewServer(t, deployment,
		federation.HandleKeyRequests(),
		federation.HandleMakeSendJoinRequests(),
		federation.HandleTransactionRequests(nil, nil),
	)
	cancel := srv.Listen()
	defer cancel()

	// Alice creates a public room
	roomID := alice.MustCreateRoom(t, map[string]interface{}{
		"preset": "public_chat",
	})

	charlie := srv.UserID("charlie")
	serverRoom := srv.MustJoinRoom(t, deployment, "hs1", roomID, charlie)

	badEvent := srv.MustCreateEvent(t, serverRoom, federation.Event{
		Sender: charlie,
		Type:   "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "Bad state hash event",
		},
	})

	pdus := []json.RawMessage{badEvent.JSON()}
	txnJSON := map[string]interface{}{
		"origin":           srv.ServerName(),
		"origin_server_ts": time.Now().UnixNano() / 1000000,
		"pdus":             pdus,
		"state_hashes": map[string]interface{}{
			badEvent.EventID(): map[string]interface{}{
				"after": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
			},
		},
	}

	txnBody, err := json.Marshal(txnJSON)
	must.NotError(t, "json marshal txn", err)

	txnID := fmt.Sprintf("txn-%d", time.Now().UnixNano())
	reqURI := fmt.Sprintf("/_matrix/federation/v1/send/%s", txnID)

	req := fclient.NewFederationRequest("PUT", srv.ServerName(), deployment.GetFullyQualifiedHomeserverName(t, "hs1"), reqURI)
	err = req.SetContent(json.RawMessage(txnBody))
	must.NotError(t, "set content", err)

	res, err := srv.DoFederationRequest(context.Background(), t, deployment, req)
	must.NotError(t, "do federation request", err)

	resBody, err := io.ReadAll(res.Body)
	must.NotError(t, "read res body", err)

	t.Logf("Response: %s", string(resBody))

	// Verify the response contains state_hash_mismatch for the event
	parsedRes := gjson.ParseBytes(resBody)
	mismatchObj := parsedRes.Get(fmt.Sprintf("pdus.%s.state_hash_mismatch", badEvent.EventID()))
	must.Equal(t, mismatchObj.Exists(), true, "state_hash_mismatch not found in response")
	must.Equal(t, mismatchObj.Get("algorithm").Str, "lthash16", "mismatch algorithm wrong")
}
