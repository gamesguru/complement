package tests

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/gjson"

	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/must"
)

type MockKeyServer struct {
	serverName spec.ServerName
	keyID      gomatrixserverlib.KeyID
	privKey    ed25519.PrivateKey
	pubKey     ed25519.PublicKey

	mu            sync.Mutex
	verifyKeys    map[gomatrixserverlib.KeyID]ed25519.PublicKey
	oldVerifyKeys map[gomatrixserverlib.KeyID]gomatrixserverlib.OldVerifyKey
	validUntil    time.Time
	shouldCollide bool

	// Advanced test controls
	delay        time.Duration
	requestCount int32
	shouldFail   bool
}

func (m *MockKeyServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")

	// Atomically increment request counter
	m.requestCount++

	if m.shouldFail {
		w.WriteHeader(500)
		w.Write([]byte(`{"error": "Simulated connection or server failure"}`))
		return
	}

	if m.delay > 0 {
		time.Sleep(m.delay)
	}

	if m.shouldCollide {
		colPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
			return
		}

		rawJSON := fmt.Sprintf(`{
			"server_name": "%s",
			"valid_until_ts": %d,
			"verify_keys": {
				"%s": {
					"key": "%s"
				}
			},
			"old_verify_keys": {
				"%s": {
					"key": "%s",
					"expired_ts": %d
				}
			}
		}`, m.serverName, time.Now().Add(24*time.Hour).UnixMilli(), m.keyID,
			base64.RawStdEncoding.EncodeToString(m.pubKey),
			m.keyID,
			base64.RawStdEncoding.EncodeToString(colPub),
			time.Now().Add(-24*time.Hour).UnixMilli())

		signedJSON, err := gomatrixserverlib.SignJSON(string(m.serverName), m.keyID, m.privKey, []byte(rawJSON))
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
			return
		}
		w.WriteHeader(200)
		w.Write(signedJSON)
		return
	}

	k := gomatrixserverlib.ServerKeys{}
	k.ServerName = m.serverName
	k.VerifyKeys = map[gomatrixserverlib.KeyID]gomatrixserverlib.VerifyKey{}
	for id, pub := range m.verifyKeys {
		k.VerifyKeys[id] = gomatrixserverlib.VerifyKey{
			Key: spec.Base64Bytes(pub),
		}
	}
	k.OldVerifyKeys = m.oldVerifyKeys
	k.ValidUntilTS = spec.AsTimestamp(m.validUntil)

	toSign, err := json.Marshal(k.ServerKeyFields)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
		return
	}

	k.Raw, err = gomatrixserverlib.SignJSON(string(m.serverName), m.keyID, m.privKey, toSign)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
		return
	}

	w.WriteHeader(200)
	w.Write(k.Raw)
}

func queryNotary(t *testing.T, clientObj *http.Client, hsURL string, serverName string, keyID string, minValidTS int64, expectedKeyBase64 string) {
	reqBody := map[string]interface{}{
		"server_keys": map[string]interface{}{
			serverName: map[string]interface{}{
				keyID: map[string]interface{}{
					"minimum_valid_until_ts": minValidTS,
				},
			},
		},
	}
	bodyBytes, err := json.Marshal(reqBody)
	must.NotError(t, "failed to marshal notary query", err)

	resp, err := clientObj.Post(hsURL+"/_matrix/key/v2/query", "application/json", bytes.NewReader(bodyBytes))
	must.NotError(t, "failed to POST notary query", err)
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	must.NotError(t, "failed to read notary query response", err)

	must.Equal(t, resp.StatusCode, 200, "notary query status code mismatch")

	result := gjson.ParseBytes(respBytes)

	serverKeys := result.Get("server_keys").Array()
	var foundKey string
	for _, sk := range serverKeys {
		if sk.Get("server_name").Str == serverName {
			foundKey = sk.Get("verify_keys." + client.GjsonEscape(keyID) + ".key").Str
		}
	}

	must.Equal(t, foundKey, expectedKeyBase64, fmt.Sprintf("Expected cached/authoritative key %s, but got %s", expectedKeyBase64, foundKey))
}

// queryNotaryRaw queries the notary and returns the key found for the given server/keyID,
// or empty string if the server was omitted or the key was absent. Does not assert on
// the key value, allowing callers to apply custom assertion logic.
func queryNotaryRaw(t *testing.T, clientObj *http.Client, hsURL string, serverName string, keyID string, minValidTS int64) string {
	t.Helper()
	reqBody := map[string]interface{}{
		"server_keys": map[string]interface{}{
			serverName: map[string]interface{}{
				keyID: map[string]interface{}{
					"minimum_valid_until_ts": minValidTS,
				},
			},
		},
	}
	bodyBytes, err := json.Marshal(reqBody)
	must.NotError(t, "failed to marshal notary query", err)

	resp, err := clientObj.Post(hsURL+"/_matrix/key/v2/query", "application/json", bytes.NewReader(bodyBytes))
	must.NotError(t, "failed to POST notary query", err)
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	must.NotError(t, "failed to read notary query response", err)

	must.Equal(t, resp.StatusCode, 200, "notary query status code mismatch")

	result := gjson.ParseBytes(respBytes)
	serverKeys := result.Get("server_keys").Array()
	var foundKey string
	for _, sk := range serverKeys {
		if sk.Get("server_name").Str == serverName {
			foundKey = sk.Get("verify_keys." + client.GjsonEscape(keyID) + ".key").Str
		}
	}
	return foundKey
}

// Test that a homeserver strictly follows "First Seen Wins" for a unique (server_name, key_id).
func TestKeyIDFirstSeenWinsDirect(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	fedClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: deployment.RoundTripper(),
	}

	srv := federation.NewServer(t, deployment)
	cancel := srv.Listen()
	defer cancel()

	originName := srv.ServerName()

	pubKeyA, privKeyA, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate key A", err)

	keyID := gomatrixserverlib.KeyID("ed25519:msc4499_key")

	mockKeyServer := &MockKeyServer{
		serverName: originName,
		keyID:      keyID,
		privKey:    privKeyA,
		pubKey:     pubKeyA,
		verifyKeys: map[gomatrixserverlib.KeyID]ed25519.PublicKey{
			keyID: pubKeyA,
		},
		oldVerifyKeys: map[gomatrixserverlib.KeyID]gomatrixserverlib.OldVerifyKey{},
		validUntil:    time.Now().Add(24 * time.Hour),
	}

	srv.Mux().Handle("/_matrix/key/v2/server", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/{keyID}", mockKeyServer).Methods("GET")

	// Phase 1: Query notary -> hs1 fetches, caches Keypair A
	queryNotary(t, fedClient, "https://hs1", string(originName), string(keyID), 0, base64.RawStdEncoding.EncodeToString(pubKeyA))

	// Phase 2: Change mock key server to serve Keypair B for the exact same key ID
	pubKeyB, privKeyB, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate key B", err)

	mockKeyServer.mu.Lock()
	mockKeyServer.privKey = privKeyB
	mockKeyServer.pubKey = pubKeyB
	mockKeyServer.verifyKeys[keyID] = pubKeyB
	mockKeyServer.mu.Unlock()

	// Query notary again with minimum_valid_until_ts beyond the cached valid_until_ts to force a re-fetch.
	// The MSC's invariant is: "key B is NEVER returned and NEVER cached."
	// Two compliant behaviors exist:
	//   1. Return pinned key A (even though it may not satisfy minimum_valid_until_ts)
	//   2. Return 200 with the server omitted (key A can't satisfy the time constraint, key B is rejected)
	// Both are acceptable. The invariant we assert is: key B must NOT appear.
	pubKeyBBase64 := base64.RawStdEncoding.EncodeToString(pubKeyB)
	minValidUntil := mockKeyServer.validUntil.Add(time.Hour).UnixMilli()
	foundKey := queryNotaryRaw(t, fedClient, "https://hs1", string(originName), string(keyID), minValidUntil)

	if foundKey == pubKeyBBase64 {
		t.Fatalf("hs1 returned colliding Keypair B after re-fetch — First Seen Wins was not enforced")
	}

	// Follow-up: query with minimum_valid_until_ts: 0 to prove the cache still has key A
	// (i.e., the cache was not poisoned by the colliding key B).
	queryNotary(t, fedClient, "https://hs1", string(originName), string(keyID), 0, base64.RawStdEncoding.EncodeToString(pubKeyA))
}

// Test that First Seen Wins is enforced at the event verification level, not just the notary endpoint.
// An event signed by a colliding key B (different material for a previously-seen key ID)
// MUST be rejected when sent via federation transaction.
func TestFirstSeenWinsEventPath(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	srv := federation.NewServer(t, deployment,
		federation.HandleMakeSendJoinRequests(),
		federation.HandleTransactionRequests(nil, nil),
	)
	srv.UnexpectedRequestsAreErrors = false
	cancel := srv.Listen()
	defer cancel()

	// Generate key A — this will be the "first seen" key
	pubKeyA, privKeyA, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate key A", err)

	keyID := gomatrixserverlib.KeyID("ed25519:msc4499_fsw_event")

	// Set srv's signing identity to key A
	srv.KeyID = keyID
	srv.Priv = privKeyA

	// Mock key server serves key A
	mockKeyServer := &MockKeyServer{
		serverName: srv.ServerName(),
		keyID:      keyID,
		privKey:    privKeyA,
		pubKey:     pubKeyA,
		verifyKeys: map[gomatrixserverlib.KeyID]ed25519.PublicKey{
			keyID: pubKeyA,
		},
		oldVerifyKeys: map[gomatrixserverlib.KeyID]gomatrixserverlib.OldVerifyKey{},
		validUntil:    time.Now().Add(24 * time.Hour),
	}

	srv.Mux().Handle("/_matrix/key/v2/server", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/{keyID}", mockKeyServer).Methods("GET")

	// Create room and join hs1 — this pins key A via the room creation events
	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	ver := alice.GetDefaultRoomVersion(t)
	charlie := srv.UserID("charlie")
	serverRoom := srv.MustMakeRoom(t, ver, federation.InitialRoomEvents(ver, charlie))
	roomAlias := srv.MakeAliasMapping("fsw_event_test", serverRoom.RoomID)
	alice.MustJoinRoom(t, roomAlias, []spec.ServerName{srv.ServerName()})

	// Phase 1: Send a valid event signed by key A — hs1 accepts and caches key A
	eventValid := srv.MustCreateEvent(t, serverRoom, federation.Event{
		Sender: charlie,
		Type:   "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "Signed by key A (first seen)",
		},
	})
	serverRoom.AddEvent(eventValid)

	fedClient := srv.FederationClient(deployment)
	ctx, cancelCtx := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelCtx()

	resp, err := fedClient.SendTransaction(ctx, gomatrixserverlib.Transaction{
		TransactionID: gomatrixserverlib.TransactionID(fmt.Sprintf("msc4499-fsw-valid-%d", time.Now().UnixNano())),
		Origin:        spec.ServerName(srv.ServerName()),
		Destination:   "hs1",
		PDUs:          []json.RawMessage{eventValid.JSON()},
	})
	must.NotError(t, "SendTransaction failed for valid event", err)
	for eventID, pduResp := range resp.PDUs {
		if pduResp.Error != "" {
			t.Fatalf("hs1 rejected valid event %s signed by key A: %s", eventID, pduResp.Error)
		}
	}

	// Get sync token after valid event
	_, since := alice.MustSync(t, client.SyncReq{})

	// Phase 2: Generate key B (different material, same key ID) and sign an event with it
	_, privKeyB, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate key B", err)

	srv.KeyID = keyID
	srv.Priv = privKeyB // sign with key B

	eventPoisoned := srv.MustCreateEvent(t, serverRoom, federation.Event{
		Sender: charlie,
		Type:   "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "Signed by key B (colliding — should be rejected)",
		},
	})
	serverRoom.AddEvent(eventPoisoned)

	// Restore identity to key A
	srv.KeyID = keyID
	srv.Priv = privKeyA

	// Send the poisoned event — hs1 MUST reject it because the signature was made by key B,
	// but the only cached key body for this key ID is key A.
	ctx2, cancelCtx2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelCtx2()

	resp2, err := fedClient.SendTransaction(ctx2, gomatrixserverlib.Transaction{
		TransactionID: gomatrixserverlib.TransactionID(fmt.Sprintf("msc4499-fsw-poisoned-%d", time.Now().UnixNano())),
		Origin:        spec.ServerName(srv.ServerName()),
		Destination:   "hs1",
		PDUs:          []json.RawMessage{eventPoisoned.JSON()},
	})

	rejected := false
	if err != nil {
		rejected = true
	} else {
		for _, pduResp := range resp2.PDUs {
			if pduResp.Error != "" {
				rejected = true
				break
			}
		}
	}

	if !rejected {
		// If no explicit rejection, check sync to see if Alice received the poisoned event
		time.Sleep(500 * time.Millisecond)
		syncResp, _ := alice.MustSync(t, client.SyncReq{Since: since, TimeoutMillis: "0"})
		events := syncResp.Get("rooms.join." + client.GjsonEscape(serverRoom.RoomID) + ".timeline.events").Array()
		for _, ev := range events {
			if ev.Get("event_id").Str == eventPoisoned.EventID() {
				t.Fatalf("hs1 accepted event %s signed by colliding key B — First Seen Wins not enforced at event verification level", eventPoisoned.EventID())
			}
		}
	}
}

// Test standard key rotation where old keys are retired and new keys have unique IDs.
func TestKeyRotation(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	fedClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: deployment.RoundTripper(),
	}

	srv := federation.NewServer(t, deployment)
	cancel := srv.Listen()
	defer cancel()

	originName := srv.ServerName()

	pubKeyA, privKeyA, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate key A", err)

	keyIDA := gomatrixserverlib.KeyID("ed25519:msc4499_key1")

	mockKeyServer := &MockKeyServer{
		serverName: originName,
		keyID:      keyIDA,
		privKey:    privKeyA,
		pubKey:     pubKeyA,
		verifyKeys: map[gomatrixserverlib.KeyID]ed25519.PublicKey{
			keyIDA: pubKeyA,
		},
		oldVerifyKeys: map[gomatrixserverlib.KeyID]gomatrixserverlib.OldVerifyKey{},
		validUntil:    time.Now().Add(24 * time.Hour),
	}

	srv.Mux().Handle("/_matrix/key/v2/server", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/{keyID}", mockKeyServer).Methods("GET")

	// Phase 1: Cache key A
	queryNotary(t, fedClient, "https://hs1", string(originName), string(keyIDA), 0, base64.RawStdEncoding.EncodeToString(pubKeyA))

	// Phase 2: Rotate key
	pubKeyB, privKeyB, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate key B", err)

	keyIDB := gomatrixserverlib.KeyID("ed25519:msc4499_key2")

	mockKeyServer.mu.Lock()
	mockKeyServer.keyID = keyIDB
	mockKeyServer.privKey = privKeyB
	mockKeyServer.pubKey = pubKeyB
	mockKeyServer.verifyKeys = map[gomatrixserverlib.KeyID]ed25519.PublicKey{
		keyIDB: pubKeyB,
	}
	mockKeyServer.oldVerifyKeys = map[gomatrixserverlib.KeyID]gomatrixserverlib.OldVerifyKey{
		keyIDA: {
			VerifyKey: gomatrixserverlib.VerifyKey{
				Key: spec.Base64Bytes(pubKeyA),
			},
			ExpiredTS: spec.AsTimestamp(time.Now()),
		},
	}
	mockKeyServer.mu.Unlock()

	// Query for key B (new key ID) -> should succeed
	queryNotary(t, fedClient, "https://hs1", string(originName), string(keyIDB), 0, base64.RawStdEncoding.EncodeToString(pubKeyB))
}

// Test that key ID collisions in a single payload are strictly rejected.
// A collision is when the same key ID appears in both verify_keys and old_verify_keys
// with DIFFERENT key material. MSC4499 requires the entire response to be rejected
// as malformed, and the notary to omit the affected server from server_keys (HTTP 200).
func TestIntraPayloadRejection(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	fedClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: deployment.RoundTripper(),
	}

	srv := federation.NewServer(t, deployment)
	cancel := srv.Listen()
	defer cancel()

	originName := srv.ServerName()

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate key", err)

	controlKeyID := gomatrixserverlib.KeyID("ed25519:msc4499_control")

	mockKeyServer := &MockKeyServer{
		serverName: originName,
		keyID:      controlKeyID,
		privKey:    privKey,
		pubKey:     pubKey,
		verifyKeys: map[gomatrixserverlib.KeyID]ed25519.PublicKey{
			controlKeyID: pubKey,
		},
		oldVerifyKeys: map[gomatrixserverlib.KeyID]gomatrixserverlib.OldVerifyKey{},
		validUntil:    time.Now().Add(24 * time.Hour),
		shouldCollide: false,
	}

	srv.Mux().Handle("/_matrix/key/v2/server", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/{keyID}", mockKeyServer).Methods("GET")

	// Control Case: Well-formed, non-colliding payload. This MUST succeed with 200 OK.
	queryNotary(t, fedClient, "https://hs1", string(originName), string(controlKeyID), 0,
		base64.RawStdEncoding.EncodeToString(pubKey))

	// Collision Case: Use a FRESH key ID so the notary cache cannot satisfy the query
	// and the homeserver MUST re-fetch from our mock, hitting the collision code path.
	collideKeyID := gomatrixserverlib.KeyID("ed25519:msc4499_collide")
	colPub, colPriv, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate collision key", err)

	mockKeyServer.mu.Lock()
	mockKeyServer.keyID = collideKeyID
	mockKeyServer.privKey = colPriv
	mockKeyServer.pubKey = colPub
	mockKeyServer.verifyKeys = map[gomatrixserverlib.KeyID]ed25519.PublicKey{
		collideKeyID: colPub,
	}
	mockKeyServer.shouldCollide = true
	mockKeyServer.requestCount = 0
	mockKeyServer.mu.Unlock()

	reqBody := map[string]interface{}{
		"server_keys": map[string]interface{}{
			string(originName): map[string]interface{}{
				string(collideKeyID): map[string]interface{}{
					"minimum_valid_until_ts": 0,
				},
			},
		},
	}
	bodyBytes, err := json.Marshal(reqBody)
	must.NotError(t, "failed to marshal notary query", err)

	resp, err := fedClient.Post("https://hs1/_matrix/key/v2/query", "application/json", bytes.NewReader(bodyBytes))
	must.NotError(t, "failed to POST notary query", err)
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	must.NotError(t, "failed to read notary response", err)

	// Verify the mock was actually consulted (not served from cache).
	mockKeyServer.mu.Lock()
	reqCount := mockKeyServer.requestCount
	mockKeyServer.mu.Unlock()
	if reqCount == 0 {
		t.Fatalf("Mock key server was never consulted — collision code path was not exercised (cache satisfied the query)")
	}

	// Per MSC4499: "the affected server MUST be omitted from the server_keys array
	// in the notary's response (HTTP 200 with the key absent)."
	must.Equal(t, resp.StatusCode, 200, "notary must return 200 even when upstream payload is malformed")

	result := gjson.ParseBytes(respBytes)
	serverKeys := result.Get("server_keys").Array()
	for _, sk := range serverKeys {
		if sk.Get("server_name").Str == string(originName) {
			t.Fatalf("hs1 included %s in server_keys; MSC4499 requires malformed upstream responses to be omitted from server_keys", originName)
		}
	}
}

// Test that identical key material appearing in both verify_keys and old_verify_keys
// under the same key ID is accepted. MSC4499 explicitly states: "The same key body
// appearing under one key ID in both verify_keys and old_verify_keys is legal."
// This is a common benign artifact during key rotation grace periods and MUST be accepted.
func TestIdenticalCrossMapKeyIsLegal(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	fedClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: deployment.RoundTripper(),
	}

	srv := federation.NewServer(t, deployment)
	cancel := srv.Listen()
	defer cancel()

	originName := srv.ServerName()

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate key", err)

	keyID := gomatrixserverlib.KeyID("ed25519:msc4499_crossmap")
	pubKeyBase64 := base64.RawStdEncoding.EncodeToString(pubKey)

	// Serve a payload where the same key ID has IDENTICAL key material
	// in both verify_keys and old_verify_keys. This is explicitly legal.
	mockKeyServer := &MockKeyServer{
		serverName: originName,
		keyID:      keyID,
		privKey:    privKey,
		pubKey:     pubKey,
		verifyKeys: map[gomatrixserverlib.KeyID]ed25519.PublicKey{
			keyID: pubKey,
		},
		oldVerifyKeys: map[gomatrixserverlib.KeyID]gomatrixserverlib.OldVerifyKey{
			keyID: {
				VerifyKey: gomatrixserverlib.VerifyKey{
					Key: spec.Base64Bytes(pubKey),
				},
				ExpiredTS: spec.AsTimestamp(time.Now().Add(-1 * time.Hour)),
			},
		},
		validUntil: time.Now().Add(24 * time.Hour),
	}

	srv.Mux().Handle("/_matrix/key/v2/server", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/{keyID}", mockKeyServer).Methods("GET")

	// Query the notary — this MUST succeed. The identical cross-map key is legal.
	queryNotary(t, fedClient, "https://hs1", string(originName), string(keyID), 0, pubKeyBase64)
}

// Test that concurrent outgoing key queries are coalesced into a single fetch.
func TestKeyFetchCoalescing(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	fedClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: deployment.RoundTripper(),
	}

	srv := federation.NewServer(t, deployment)
	cancel := srv.Listen()
	defer cancel()

	originName := srv.ServerName()

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate key", err)

	keyID := gomatrixserverlib.KeyID("ed25519:msc4499_coalesce")

	mockKeyServer := &MockKeyServer{
		serverName: originName,
		keyID:      keyID,
		privKey:    privKey,
		pubKey:     pubKey,
		verifyKeys: map[gomatrixserverlib.KeyID]ed25519.PublicKey{
			keyID: pubKey,
		},
		oldVerifyKeys: map[gomatrixserverlib.KeyID]gomatrixserverlib.OldVerifyKey{},
		validUntil:    time.Now().Add(24 * time.Hour),
		delay:         500 * time.Millisecond, // slow fetch
	}

	srv.Mux().Handle("/_matrix/key/v2/server", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/{keyID}", mockKeyServer).Methods("GET")

	// Query notary endpoint concurrently 10 times
	concurrency := 10
	errCh := make(chan error, concurrency)
	var wg sync.WaitGroup
	wg.Add(concurrency)

	wantKey := base64.RawStdEncoding.EncodeToString(pubKey)
	bodyBytes, err := json.Marshal(map[string]any{
		"server_keys": map[string]any{
			string(originName): map[string]any{
				string(keyID): map[string]any{"minimum_valid_until_ts": int64(0)},
			},
		},
	})
	must.NotError(t, "failed to marshal notary query", err)

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			resp, err := fedClient.Post("https://hs1/_matrix/key/v2/query", "application/json", bytes.NewReader(bodyBytes))
			if err != nil {
				errCh <- err
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				errCh <- fmt.Errorf("unexpected status code: %d", resp.StatusCode)
				return
			}
			respBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				errCh <- err
				return
			}
			result := gjson.ParseBytes(respBytes)
			serverKeys := result.Get("server_keys").Array()
			var foundKey string
			for _, sk := range serverKeys {
				if sk.Get("server_name").Str == string(originName) {
					foundKey = sk.Get("verify_keys." + client.GjsonEscape(string(keyID)) + ".key").Str
				}
			}
			if foundKey != wantKey {
				errCh <- fmt.Errorf("unexpected key: got %q want %q", foundKey, wantKey)
			}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent notary query failed: %v", err)
		}
	}
	mockKeyServer.mu.Lock()
	reqCount := mockKeyServer.requestCount
	mockKeyServer.mu.Unlock()

	// Since they ran concurrently while the first fetch was slow,
	// hs1 MUST coalesce these requests. The requestCount should be exactly 1 (or very small).
	if reqCount > 2 {
		t.Fatalf("Expected hs1 to coalesce the concurrent outgoing key fetches, but got %d fetches", reqCount)
	}
}

// Test that failed key fetches are cached and subject to negative caching / backoff.
func TestNegativeCachingAndBackoff(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	fedClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: deployment.RoundTripper(),
	}

	srv := federation.NewServer(t, deployment)
	cancel := srv.Listen()
	defer cancel()

	originName := srv.ServerName()

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate key", err)

	keyID := gomatrixserverlib.KeyID("ed25519:msc4499_negative")

	mockKeyServer := &MockKeyServer{
		serverName: originName,
		keyID:      keyID,
		privKey:    privKey,
		pubKey:     pubKey,
		verifyKeys: map[gomatrixserverlib.KeyID]ed25519.PublicKey{
			keyID: pubKey,
		},
		oldVerifyKeys: map[gomatrixserverlib.KeyID]gomatrixserverlib.OldVerifyKey{},
		validUntil:    time.Now().Add(24 * time.Hour),
		shouldFail:    true, // return 500
	}

	srv.Mux().Handle("/_matrix/key/v2/server", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/{keyID}", mockKeyServer).Methods("GET")

	// Call notary -> must fail
	reqBody := map[string]interface{}{
		"server_keys": map[string]interface{}{
			string(originName): map[string]interface{}{
				string(keyID): map[string]interface{}{
					"minimum_valid_until_ts": 0,
				},
			},
		},
	}
	bodyBytes, err := json.Marshal(reqBody)
	must.NotError(t, "failed to marshal notary query", err)

	resp, err := fedClient.Post("https://hs1/_matrix/key/v2/query", "application/json", bytes.NewReader(bodyBytes))
	must.NotError(t, "failed to POST notary query", err)
	defer resp.Body.Close()

	mockKeyServer.mu.Lock()
	initialReqCount := mockKeyServer.requestCount
	mockKeyServer.mu.Unlock()
	if initialReqCount == 0 {
		t.Fatalf("Mock key server was never consulted — negative caching/backoff code path was not exercised")
	}

	// Wait for any deferred retries or background tasks from the first query to settle (quiescence)
	time.Sleep(100 * time.Millisecond)

	// Verify Phase 1 actually hit the mock (if it didn't, the backoff assertion is vacuous)
	mockKeyServer.mu.Lock()
	if mockKeyServer.requestCount == 0 {
		mockKeyServer.mu.Unlock()
		t.Fatalf("Phase 1: mock key server was never consulted — test precondition failed")
	}

	// Unblock mock key server and reset counter for Phase 2
	mockKeyServer.shouldFail = false
	mockKeyServer.requestCount = 0 // reset
	mockKeyServer.mu.Unlock()

	// Instantly call notary again
	resp2, err := fedClient.Post("https://hs1/_matrix/key/v2/query", "application/json", bytes.NewReader(bodyBytes))
	must.NotError(t, "failed to POST notary query", err)
	defer resp2.Body.Close()

	// Allow a small window for any asynchronous/racy network requests to land
	time.Sleep(100 * time.Millisecond)

	mockKeyServer.mu.Lock()
	reqCount := mockKeyServer.requestCount
	mockKeyServer.mu.Unlock()

	// Due to negative caching/backoff, hs1 MUST NOT make another HTTP request to mockKeyServer yet!
	if reqCount > 0 {
		t.Fatalf("hs1 did not implement negative caching / backoff: it made a network request on consecutive failure query")
	}
}

// Test that event signature validation respects the key's validity window (expired_ts).
func TestHistoricalEventVerification(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	// Create a remote homeserver with standard federation handlers
	srv := federation.NewServer(t, deployment,
		federation.HandleMakeSendJoinRequests(),
		federation.HandleTransactionRequests(nil, nil),
	)
	srv.UnexpectedRequestsAreErrors = false
	cancel := srv.Listen()
	defer cancel()

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	// Generate key pairs
	pubKeyActive, privKeyActive, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate active key", err)

	pubKeyExpired, privKeyExpired, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate expired key", err)

	keyIDActive := gomatrixserverlib.KeyID("ed25519:msc4499_active")
	keyIDExpired := gomatrixserverlib.KeyID("ed25519:msc4499_expired")

	// Set srv active identity before creating the room so that room events are signed by our active key ID
	srv.KeyID = keyIDActive
	srv.Priv = privKeyActive

	// Create our custom MockKeyServer that serves both KeyActive and KeyExpired
	// as active keys in verify_keys. In Phase 2 we'll rotate KeyExpired into
	// old_verify_keys with a past expired_ts.
	// NOTE: We do NOT put KeyExpired in old_verify_keys with a future expired_ts,
	// because MSC4499 says a future expired_ts MUST be treated as malformed.
	mockKeyServer := &MockKeyServer{
		serverName: srv.ServerName(),
		keyID:      keyIDActive,
		privKey:    privKeyActive,
		pubKey:     pubKeyActive,
		verifyKeys: map[gomatrixserverlib.KeyID]ed25519.PublicKey{
			keyIDActive:  pubKeyActive,
			keyIDExpired: pubKeyExpired, // both keys are active in Phase 1
		},
		oldVerifyKeys: map[gomatrixserverlib.KeyID]gomatrixserverlib.OldVerifyKey{},
		validUntil:    time.Now().Add(24 * time.Hour),
	}

	// Register our custom key server on srv's Mux
	srv.Mux().Handle("/_matrix/key/v2/server", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/{keyID}", mockKeyServer).Methods("GET")

	// Create a public room on srv
	ver := alice.GetDefaultRoomVersion(t)
	charlie := srv.UserID("charlie")
	serverRoom := srv.MustMakeRoom(t, ver, federation.InitialRoomEvents(ver, charlie))
	roomAlias := srv.MakeAliasMapping("historical_test", serverRoom.RoomID)

	// Join hs1 to the room
	alice.MustJoinRoom(t, roomAlias, []spec.ServerName{srv.ServerName()})

	// Phase 1: Send a message signed by KeyExpired while it is still active (in verify_keys).
	// Temporarily set srv identity to KeyExpired so MustCreateEvent signs with it.
	srv.KeyID = keyIDExpired
	srv.Priv = privKeyExpired

	eventValid := srv.MustCreateEvent(t, serverRoom, federation.Event{
		Sender: charlie,
		Type:   "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "Signed by key before it expired",
		},
	})
	serverRoom.AddEvent(eventValid)

	// Restore srv active identity
	srv.KeyID = keyIDActive
	srv.Priv = privKeyActive

	// Send valid event. The key is currently active in verify_keys, so hs1 MUST accept it.
	fedClient := srv.FederationClient(deployment)
	ctx, cancelCtx := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelCtx()

	resp, err := fedClient.SendTransaction(ctx, gomatrixserverlib.Transaction{
		TransactionID: gomatrixserverlib.TransactionID(fmt.Sprintf("msc4499-valid-%d", time.Now().UnixNano())),
		Origin:        spec.ServerName(srv.ServerName()),
		Destination:   "hs1",
		PDUs:          []json.RawMessage{eventValid.JSON()},
	})
	must.NotError(t, "SendTransaction failed for valid event", err)
	for eventID, pduResp := range resp.PDUs {
		if pduResp.Error != "" {
			t.Fatalf("hs1 rejected valid historical event %s: %s", eventID, pduResp.Error)
		}
	}

	// Get since token after valid event is processed
	_, since := alice.MustSync(t, client.SyncReq{})

	// Phase 2: Rotate KeyExpired out of verify_keys and into old_verify_keys
	// with an expired_ts in the past (now - 10m). This simulates a key rotation.
	mockKeyServer.mu.Lock()
	delete(mockKeyServer.verifyKeys, keyIDExpired)
	mockKeyServer.oldVerifyKeys[keyIDExpired] = gomatrixserverlib.OldVerifyKey{
		VerifyKey: gomatrixserverlib.VerifyKey{
			Key: spec.Base64Bytes(pubKeyExpired),
		},
		ExpiredTS: spec.AsTimestamp(time.Now().Add(-10 * time.Minute)), // expired (past)
	}
	mockKeyServer.mu.Unlock()

	// Clear hs1's key cache for KeyExpired so it re-fetches the updated expired_ts.
	// Since Synapse/Dendrite might have already cached the old keys, we force a re-fetch by signing with the expired key again.
	// Sign a new event with KeyExpired
	srv.KeyID = keyIDExpired
	srv.Priv = privKeyExpired

	eventInvalid := srv.MustCreateEvent(t, serverRoom, federation.Event{
		Sender: charlie,
		Type:   "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "Signed by key after it expired",
		},
	})
	serverRoom.AddEvent(eventInvalid)

	// Restore srv active identity
	srv.KeyID = keyIDActive
	srv.Priv = privKeyActive

	// Send invalid event. Since event.origin_server_ts (approx now) > expired_ts (now - 10m), hs1 MUST reject it!
	ctx2, cancelCtx2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelCtx2()

	resp2, err := fedClient.SendTransaction(ctx2, gomatrixserverlib.Transaction{
		TransactionID: gomatrixserverlib.TransactionID(fmt.Sprintf("msc4499-invalid-%d", time.Now().UnixNano())),
		Origin:        spec.ServerName(srv.ServerName()),
		Destination:   "hs1",
		PDUs:          []json.RawMessage{eventInvalid.JSON()},
	})

	rejected := false
	if err != nil {
		rejected = true
	} else {
		for _, pduResp := range resp2.PDUs {
			if pduResp.Error != "" {
				rejected = true
				break
			}
		}
	}

	if !rejected {
		// Wait a bit and check if Alice gets the invalid event in sync. If she did, it's a failure.
		time.Sleep(500 * time.Millisecond)
		syncResp, _ := alice.MustSync(t, client.SyncReq{Since: since, TimeoutMillis: "0"})
		events := syncResp.Get("rooms.join." + client.GjsonEscape(serverRoom.RoomID) + ".timeline.events").Array()
		for _, ev := range events {
			if ev.Get("event_id").Str == eventInvalid.EventID() {
				t.Fatalf("hs1 accepted invalid historical event %s signed by expired key", eventInvalid.EventID())
			}
		}
	}
}
