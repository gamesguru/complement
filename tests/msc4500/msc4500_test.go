package msc4500

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/match"
	"github.com/matrix-org/complement/must"
	"github.com/matrix-org/gomatrixserverlib/fclient"
	"github.com/tidwall/gjson"
	"golang.org/x/crypto/blake2b"
)

// TestMSC4500State exercises the MSC4500 state_accumulator endpoint and the
// outbound state_hashes extension on /send transactions.
func TestMSC4500State(t *testing.T) {
	t.Run("Accumulator", testMSC4500StateAccumulator)
	t.Run("HashMismatch", testMSC4500StateHashMismatch)
	t.Run("Outbound", testMSC4500StateOutbound)
}

// testMSC4500StateAccumulator verifies that the state_accumulator endpoint
// returns a valid 2048-byte base64url encoded lattice and the matching BLAKE2b-256 digest.
func testMSC4500StateAccumulator(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	// Create a remote homeserver to make authenticated federation requests
	srv := federation.NewServer(t, deployment,
		federation.HandleKeyRequests(),
		federation.HandleMakeSendJoinRequests(),
		federation.HandleTransactionRequests(nil, nil),
	)
	cancel := srv.Listen()
	defer cancel()

	roomID := alice.MustCreateRoom(t, map[string]interface{}{
		"preset": "public_chat",
	})

	charlie := srv.UserID("charlie")
	_ = srv.MustJoinRoom(t, deployment, "hs1", roomID, charlie)

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

	// Call the federation endpoint using signed federation request from srv
	reqURI := fmt.Sprintf("/_matrix/federation/unstable/tk.nutra.msc4500/state_accumulator/%s?event_id=%s", roomID, eventID)
	req := fclient.NewFederationRequest("GET", srv.ServerName(), deployment.GetFullyQualifiedHomeserverName(t, "hs1"), reqURI)

	fedRes, err := srv.DoFederationRequest(context.Background(), t, deployment, req)
	must.NotError(t, "do federation request", err)

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

func testMSC4500StateHashMismatch(t *testing.T) {
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
		"tk.nutra.msc4500.state_hashes": map[string]interface{}{
			badEvent.EventID(): map[string]interface{}{
				"algorithm": "lthash16",
				"after":     "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
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
	must.NotError(t, "close res body", res.Body.Close())

	t.Logf("Response: %s", string(resBody))

	// Verify the response contains state_hash_mismatch for the event
	parsedRes := gjson.ParseBytes(resBody)
	mismatchObj := gjson.Result{}
	parsedRes.Get("pdus").ForEach(func(key, value gjson.Result) bool {
		if key.Str == badEvent.EventID() {
			mismatchObj = value.Get("state_hash_mismatch")
			return false
		}
		return true
	})
	must.Equal(t, mismatchObj.Exists(), true, "state_hash_mismatch not found in response")
	must.Equal(t, mismatchObj.Get("algorithm").Str, "lthash16", "mismatch algorithm wrong")
}

// testMSC4500StateOutbound verifies that outbound /send transactions carry the
// MSC4500 state_hashes extension (tk.nutra.msc4500.state_hashes), so that remote
// servers can validate state equivalence across the wire.
func testMSC4500StateOutbound(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	// Remote homeserver that captures raw /send transaction bodies. We parse the
	// raw body (rather than gomatrixserverlib.Transaction) because the custom
	// tk.nutra.msc4500.state_hashes field would otherwise be dropped.
	found := helpers.NewWaiter()

	srv := federation.NewServer(t, deployment,
		federation.HandleKeyRequests(),
		federation.HandleMakeSendJoinRequests(),
	)
	srv.Mux().HandleFunc("/_matrix/federation/v1/send/{transactionID}", func(w http.ResponseWriter, req *http.Request) {
		fedReq, errResp := fclient.VerifyHTTPRequest(req, time.Now(), srv.ServerName(), nil, nil)
		if fedReq == nil {
			w.WriteHeader(errResp.Code)
			b, _ := json.Marshal(errResp.JSON)
			w.Write(b)
			return
		}
		defer func() {
			// Check the transaction for the state_hashes extension after reading it.
			checkMSC4500Outbound(fedReq.Content(), found)
		}()
		w.WriteHeader(200)
		w.Write([]byte(`{"pdus":{}}`))
	}).Methods("PUT")

	cancel := srv.Listen()
	defer cancel()

	roomID := alice.MustCreateRoom(t, map[string]interface{}{
		"preset": "public_chat",
	})

	charlie := srv.UserID("charlie")
	_ = srv.MustJoinRoom(t, deployment, "hs1", roomID, charlie)

	// Trigger an outbound transaction by having alice send a message and syncing
	// until it is present (which forces the homeserver to forward it to charlie).
	alice.SendEventSynced(t, roomID, b.Event{
		Type: "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "hello",
		},
	})

	found.Waitf(t, 30*time.Second, "timed out waiting for outbound tk.nutra.msc4500.state_hashes on /send")
}

// checkMSC4500Outbound inspects a raw /send transaction body and finishes the
// waiter if it carries a valid tk.nutra.msc4500.state_hashes extension.
func checkMSC4500Outbound(raw json.RawMessage, found *helpers.Waiter) {
	var body map[string]interface{}
	if err := json.Unmarshal(raw, &body); err != nil {
		return
	}
	stateHashes, ok := body["tk.nutra.msc4500.state_hashes"]
	if !ok {
		return
	}
	sh, ok := stateHashes.(map[string]interface{})
	if !ok || len(sh) == 0 {
		return
	}
	for _, v := range sh {
		entry, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		algo, _ := entry["algorithm"].(string)
		after, _ := entry["after"].(string)
		if algo == "lthash16" && len(after) == 64 {
			found.Finish()
			return
		}
	}
}
