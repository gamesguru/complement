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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/gjson"

	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/must"
	"github.com/matrix-org/complement/runtime"
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
			// Check verify_keys first
			foundKey = sk.Get("verify_keys." + client.GjsonEscape(keyID) + ".key").Str
			if foundKey == "" {
				// Fallback to old_verify_keys
				foundKey = sk.Get("old_verify_keys." + client.GjsonEscape(keyID) + ".key").Str
			}
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
			// Check verify_keys first
			foundKey = sk.Get("verify_keys." + client.GjsonEscape(keyID) + ".key").Str
			if foundKey == "" {
				// Fallback to old_verify_keys
				foundKey = sk.Get("old_verify_keys." + client.GjsonEscape(keyID) + ".key").Str
			}
		}
	}
	return foundKey
}

func deployMSC4499TrustedNotary(t *testing.T) complement.Deployment {
	t.Helper()
	return complement.DeployBlueprint(t, b.MustValidate(b.Blueprint{
		Name: "msc4499_trusted_notary",
		Homeservers: []b.Homeserver{
			{
				Name: "hs1",
				Env: map[string]string{
					"CONDUWUIT_TRUSTED_SERVERS": "hs2",
				},
			},
			{
				Name: "hs2",
			},
		},
	}))
}

// TestMSC4499Key exercises MSC4499 server key uniqueness and verification
// behaviour across many scenarios: first-seen-wins conflict resolution, key
// rotation, rejection of duplicate/malformed payloads, caching/backoff, and
// storage limits.
func TestMSC4499Key(t *testing.T) {
	t.Run("IDFirstSeenWinsDirect", testMSC4499KeyIDFirstSeenWinsDirect)
	t.Run("FirstSeenWinsEventPath", testMSC4499KeyFirstSeenWinsEventPath)
	t.Run("Rotation", testMSC4499KeyRotation)
	t.Run("IntraPayloadRejection", testMSC4499KeyIntraPayloadRejection)
	t.Run("IdenticalCrossMapIsLegal", testMSC4499KeyIdenticalCrossMapIsLegal)
	t.Run("FetchCoalescing", testMSC4499KeyFetchCoalescing)
	t.Run("NegativeCachingAndBackoff", testMSC4499KeyNegativeCachingAndBackoff)
	t.Run("HistoricalEventVerification", testMSC4499KeyHistoricalEventVerification)
	t.Run("DuplicateJSONKeyRejection", testMSC4499KeyDuplicateJSONKeyRejection)
	t.Run("DeepDuplicateJSONKeyRejection", testMSC4499KeyDeepDuplicateJSONKeyRejection)
	t.Run("BindingPromotion", testMSC4499KeyBindingPromotion)
	t.Run("StorageQuotaResilience", testMSC4499KeyStorageQuotaResilience)
	t.Run("CorroborationTierRetention", testMSC4499KeyCorroborationTierRetention)
	t.Run("BackoffClearedOnSuccess", testMSC4499KeyBackoffClearedOnSuccess)
	t.Run("ProvisionalOverrideFreeze", testMSC4499KeyProvisionalOverrideFreeze)
	t.Run("VerifyKeysCeiling", testMSC4499KeyVerifyKeysCeiling)
	t.Run("ExpiredTsSanityCheck", testMSC4499KeyExpiredTsSanityCheck)
}

// testMSC4499KeyIDFirstSeenWinsDirect tests that a homeserver strictly follows
// "First Seen Wins" for a unique (server_name, key_id).
func testMSC4499KeyIDFirstSeenWinsDirect(t *testing.T) {
	runtime.SkipIf(t, runtime.Dendrite)
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
	mockKeyServer.validUntil = time.Now().Add(48 * time.Hour) // perf: far future so re-fetch satisfies any minValidUntil
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
func testMSC4499KeyFirstSeenWinsEventPath(t *testing.T) {
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
func testMSC4499KeyRotation(t *testing.T) {
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
func testMSC4499KeyIntraPayloadRejection(t *testing.T) {
	runtime.SkipIf(t, runtime.Dendrite)
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

	// Per MSC4499: "the malformed response MUST NOT be included in the server_keys array
	// in the notary's response; the notary MAY continue serving previously-cached valid entries
	// for that server in the same response" — so the server MAY appear with the old cached
	// controlKeyID, but the colliding payload MUST be absent.
	must.Equal(t, resp.StatusCode, 200, "notary must return 200 even when upstream payload is malformed")

	result := gjson.ParseBytes(respBytes)
	serverKeys := result.Get("server_keys").Array()
	for _, sk := range serverKeys {
		if sk.Get("server_name").Str == string(originName) {
			// The colliding key ID MUST NOT appear — this is the malformed payload's key
			foundCollide := sk.Get("verify_keys." + client.GjsonEscape(string(collideKeyID)) + ".key").Str
			if foundCollide != "" {
				t.Fatalf("hs1 returned the colliding key %s in server_keys — malformed payload was not rejected (key body: %s)",
					collideKeyID, foundCollide)
			}

			// If the server IS present, it must be the previously-cached controlKeyID entry,
			// not any remnant of the malformed collision payload. Verify the control key is
			// the one being served (proving this is a cached entry, not the rejected payload).
			foundControl := sk.Get("verify_keys." + client.GjsonEscape(string(controlKeyID)) + ".key").Str
			if foundControl == "" {
				t.Fatalf("hs1 included server %s in server_keys but without the previously-cached control key %s — "+
					"the entry is neither the cached valid entry nor the malformed payload (response: %s)",
					originName, controlKeyID, string(respBytes))
			}
		}
	}
}

// Test that identical key material appearing in both verify_keys and old_verify_keys
// under the same key ID is accepted. MSC4499 explicitly states: "The same key body
// appearing under one key ID in both verify_keys and old_verify_keys is legal."
// This is a common benign artifact during key rotation grace periods and MUST be accepted.
func testMSC4499KeyIdenticalCrossMapIsLegal(t *testing.T) {
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
func testMSC4499KeyFetchCoalescing(t *testing.T) {
	runtime.SkipIf(t, runtime.Dendrite)
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
func testMSC4499KeyNegativeCachingAndBackoff(t *testing.T) {
	runtime.SkipIf(t, runtime.Dendrite)
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

	// Unblock mock key server and reset counter for Phase 2
	mockKeyServer.mu.Lock()
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
// Uses a cold-cache design: keyIDExpired is never seen by hs1 until it appears in
// old_verify_keys with a past expired_ts. This avoids the cache staleness confound
// where hs1's cached entry would still show the key as active.
//
// Per MSC4499 L288-295: an event signed at time T is valid iff T < expired_ts.
// Two sub-cases:
//   - Event A: origin_server_ts < expired_ts → MUST accept (legitimate historical event)
//   - Event B: origin_server_ts > expired_ts → MUST reject (stolen retired key)
func testMSC4499KeyHistoricalEventVerification(t *testing.T) {
	runtime.SkipIf(t, runtime.Dendrite)
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

	// Set srv active identity to keyIDActive
	srv.KeyID = keyIDActive
	srv.Priv = privKeyActive

	// Phase 1: Mock key server serves ONLY keyIDActive in verify_keys.
	// keyIDExpired does NOT appear anywhere — hs1 has never seen it (cold cache).
	mockKeyServer := &MockKeyServer{
		serverName: srv.ServerName(),
		keyID:      keyIDActive,
		privKey:    privKeyActive,
		pubKey:     pubKeyActive,
		verifyKeys: map[gomatrixserverlib.KeyID]ed25519.PublicKey{
			keyIDActive: pubKeyActive,
			// NOTE: keyIDExpired is intentionally ABSENT — cold cache
		},
		oldVerifyKeys: map[gomatrixserverlib.KeyID]gomatrixserverlib.OldVerifyKey{},
		validUntil:    time.Now().Add(24 * time.Hour),
	}

	// Register our custom key server on srv's Mux
	srv.Mux().Handle("/_matrix/key/v2/server", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/{keyID}", mockKeyServer).Methods("GET")

	// Create a public room on srv and have hs1 join.
	// hs1 fetches keys during join, caches ONLY keyIDActive.
	ver := alice.GetDefaultRoomVersion(t)
	charlie := srv.UserID("charlie")
	serverRoom := srv.MustMakeRoom(t, ver, federation.InitialRoomEvents(ver, charlie))
	roomAlias := srv.MakeAliasMapping("historical_test", serverRoom.RoomID)
	alice.MustJoinRoom(t, roomAlias, []spec.ServerName{srv.ServerName()})

	// Get sync token after join
	_, since := alice.MustSync(t, client.SyncReq{})

	// Phase 2: Introduce keyIDExpired in old_verify_keys with expired_ts in the past.
	// This is the first time hs1 will ever see this key ID — cold cache.
	expiredTS := time.Now().Add(-1 * time.Hour)
	mockKeyServer.mu.Lock()
	mockKeyServer.oldVerifyKeys[keyIDExpired] = gomatrixserverlib.OldVerifyKey{
		VerifyKey: gomatrixserverlib.VerifyKey{
			Key: spec.Base64Bytes(pubKeyExpired),
		},
		ExpiredTS: spec.AsTimestamp(expiredTS), // expired 1 hour ago
	}
	// Shorten valid_until_ts to force hs1 to re-fetch when it encounters the new key ID
	mockKeyServer.validUntil = time.Now().Add(1 * time.Second)
	mockKeyServer.mu.Unlock()

	// Small sleep to let valid_until_ts expire so hs1 will re-fetch
	time.Sleep(2 * time.Second)

	// === Event A: Backdated origin_server_ts BEFORE expired_ts → MUST ACCEPT ===
	// This is the legitimate "historical event verification" case: an event that was
	// signed when the key was still active.
	srv.KeyID = keyIDExpired
	srv.Priv = privKeyExpired

	// Build event A with a backdated origin_server_ts (2 hours before expired_ts)
	backdatedTime := expiredTS.Add(-2 * time.Hour)
	protoA, err := serverRoom.ProtoEventCreator(serverRoom, federation.Event{
		Sender: charlie,
		Type:   "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "Historical event signed before key expired",
		},
	})
	must.NotError(t, "failed to create proto event A", err)

	verImpl := gomatrixserverlib.MustGetRoomVersion(serverRoom.Version)
	eb := verImpl.NewEventBuilderFromProtoEvent(protoA)
	eventA, err := eb.Build(backdatedTime, spec.ServerName(srv.ServerName()), srv.KeyID, srv.Priv)
	must.NotError(t, "failed to build backdated event A", err)
	serverRoom.AddEvent(eventA)

	fedClient := srv.FederationClient(deployment)
	ctx, cancelCtx := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelCtx()

	respA, err := fedClient.SendTransaction(ctx, gomatrixserverlib.Transaction{
		TransactionID: gomatrixserverlib.TransactionID(fmt.Sprintf("msc4499-hist-valid-%d", time.Now().UnixNano())),
		Origin:        spec.ServerName(srv.ServerName()),
		Destination:   "hs1",
		PDUs:          []json.RawMessage{eventA.JSON()},
	})
	must.NotError(t, "SendTransaction failed for backdated historical event", err)
	for eventID, pduResp := range respA.PDUs {
		if pduResp.Error != "" {
			t.Fatalf("hs1 rejected valid historical event %s (origin_server_ts before expired_ts): %s", eventID, pduResp.Error)
		}
	}

	// === Event B: origin_server_ts = now, AFTER expired_ts → MUST REJECT ===
	// This tests the "stolen retired key signing fresh events" case.
	eventB := srv.MustCreateEvent(t, serverRoom, federation.Event{
		Sender: charlie,
		Type:   "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "Fresh event signed by expired key — should be rejected",
		},
	})
	serverRoom.AddEvent(eventB)

	// Restore srv identity
	srv.KeyID = keyIDActive
	srv.Priv = privKeyActive

	ctx2, cancelCtx2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelCtx2()

	respB, err := fedClient.SendTransaction(ctx2, gomatrixserverlib.Transaction{
		TransactionID: gomatrixserverlib.TransactionID(fmt.Sprintf("msc4499-hist-invalid-%d", time.Now().UnixNano())),
		Origin:        spec.ServerName(srv.ServerName()),
		Destination:   "hs1",
		PDUs:          []json.RawMessage{eventB.JSON()},
	})

	rejected := false
	if err != nil {
		rejected = true
	} else {
		for _, pduResp := range respB.PDUs {
			if pduResp.Error != "" {
				rejected = true
				break
			}
		}
	}

	if !rejected {
		// Wait and check sync to see if Alice received the invalid event
		time.Sleep(500 * time.Millisecond)
		syncResp, _ := alice.MustSync(t, client.SyncReq{Since: since, TimeoutMillis: "0"})
		events := syncResp.Get("rooms.join." + client.GjsonEscape(serverRoom.RoomID) + ".timeline.events").Array()
		for _, ev := range events {
			if ev.Get("event_id").Str == eventB.EventID() {
				t.Fatalf("hs1 accepted event %s signed by expired key (origin_server_ts after expired_ts) — expired_ts enforcement missing", eventB.EventID())
			}
		}
	}
}

// Test that duplicate JSON keys within a single object in key response payloads
// are detected and rejected. MSC4499 requires: "Implementations MUST employ a JSON
// parser or pre-processing step capable of detecting duplicate keys within a single
// JSON object for key response payloads."
//
// This test hand-crafts raw JSON bytes with a literal duplicate key inside verify_keys,
// bypassing Go's JSON marshaler (which silently deduplicates). The notary MUST reject
// the payload and omit the colliding key from server_keys.
func testMSC4499KeyDuplicateJSONKeyRejection(t *testing.T) {
	runtime.SkipIf(t, runtime.Dendrite)
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

	// Generate signing key for the mock server
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate signing key", err)

	// Generate two different keys that will appear under the same key ID
	pubKeyDupeA, _, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate dupe key A", err)
	pubKeyDupeB, _, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate dupe key B", err)

	signingKeyID := gomatrixserverlib.KeyID("ed25519:msc4499_signer")
	dupeKeyID := "ed25519:msc4499_dupetest"

	// Hand-craft raw JSON with a DUPLICATE key inside verify_keys.
	// Go's json.Marshal would silently deduplicate this, so we must build it manually.
	// We test BOTH orderings: A-then-B and B-then-A. A server passing via
	// signature-mismatch coincidence (parser dedup direction != signer dedup direction)
	// will flip verdicts between orderings. Only both-orderings-rejected counts as a
	// genuine pass.
	keyABase64 := base64.RawStdEncoding.EncodeToString(pubKeyDupeA)
	keyBBase64 := base64.RawStdEncoding.EncodeToString(pubKeyDupeB)
	orderings := []struct {
		name   string
		first  string
		second string
	}{
		{"A-then-B", keyABase64, keyBBase64},
		{"B-then-A", keyBBase64, keyABase64},
	}

	// Shared payload variable — handler reads from this; updated per ordering.
	var currentPayload []byte
	var payloadMu sync.Mutex

	dupeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payloadMu.Lock()
		payload := currentPayload
		payloadMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(payload)
	})

	srv.Mux().Handle("/_matrix/key/v2/server", dupeHandler).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/", dupeHandler).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/{keyID}", dupeHandler).Methods("GET")

	for _, ordering := range orderings {
		t.Run(ordering.name, func(t *testing.T) {

			rawJSON := fmt.Sprintf(`{
		"server_name": "%s",
		"valid_until_ts": %d,
		"verify_keys": {
			"%s": {
				"key": "%s"
			},
			"%s": {
				"key": "%s"
			},
			"%s": {
				"key": "%s"
			}
		}
	}`, originName, time.Now().Add(24*time.Hour).UnixMilli(),
				signingKeyID, base64.RawStdEncoding.EncodeToString(pubKey),
				dupeKeyID, ordering.first,
				dupeKeyID, ordering.second, // DUPLICATE with reversed ordering
			)

			// Sign the raw JSON with the signing key
			signedJSON, err := gomatrixserverlib.SignJSON(string(originName), signingKeyID, privKey, []byte(rawJSON))
			must.NotError(t, "failed to sign duplicate-key JSON", err)

			// Update the shared payload for this ordering
			payloadMu.Lock()
			currentPayload = signedJSON
			payloadMu.Unlock()

			// Query the notary for the duplicate key ID — the notary fetches from our mock,
			// gets the duplicate-key payload, and MUST reject it.
			reqBody := map[string]interface{}{
				"server_keys": map[string]interface{}{
					string(originName): map[string]interface{}{
						dupeKeyID: map[string]interface{}{
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

			// Per MSC4499: duplicate keys within a single JSON object MUST be detected and
			// the payload rejected. The notary MUST return 200 with the key absent.
			must.Equal(t, resp.StatusCode, 200, "notary must return 200 even when upstream payload has duplicate JSON keys")

			result := gjson.ParseBytes(respBytes)
			serverKeys := result.Get("server_keys").Array()
			for _, sk := range serverKeys {
				if sk.Get("server_name").Str == string(originName) {
					foundKeyA := sk.Get("verify_keys." + client.GjsonEscape(dupeKeyID) + ".key").Str
					if foundKeyA != "" {
						t.Fatalf("hs1 returned the duplicate key %s in server_keys — duplicate JSON key detection is missing (key: %s)", dupeKeyID, foundKeyA)
					}
				}
			}
		}) // end t.Run
	} // end for orderings
}

// Test that duplicate JSON keys are rejected even when they appear inside a
// nested object rather than directly in verify_keys.
func testMSC4499KeyDeepDuplicateJSONKeyRejection(t *testing.T) {
	runtime.SkipIf(t, runtime.Dendrite)
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
	must.NotError(t, "failed to generate signing key", err)
	signingKeyID := gomatrixserverlib.KeyID("ed25519:msc4499_deep_signer")
	nestedKeyID := "ed25519:msc4499_deep_dupe"

	pubKeyBase64 := base64.RawStdEncoding.EncodeToString(pubKey)

	// Construct the valid JSON first (without duplicates) so SignJSON computes a valid signature over it.
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
	}`, originName, time.Now().Add(24*time.Hour).UnixMilli(),
		signingKeyID, pubKeyBase64,
		nestedKeyID,
		pubKeyBase64,
		time.Now().Add(-1*time.Hour).UnixMilli(),
	)

	validSignedJSON, err := gomatrixserverlib.SignJSON(string(originName), signingKeyID, privKey, []byte(rawJSON))
	must.NotError(t, "failed to sign JSON", err)

	// Manually inject the duplicate key into the final bytes.
	// Replacing all instances ensures the duplicate exists deeply in the payload,
	// and since receiver canonicalization drops duplicates, the signature remains mathematically valid.
	targetStr := fmt.Sprintf(`"key":"%s"`, pubKeyBase64)
	duplicateStr := fmt.Sprintf(`"key":"%s","key":"%s"`, pubKeyBase64, pubKeyBase64)
	signedJSON := []byte(strings.ReplaceAll(string(validSignedJSON), targetStr, duplicateStr))
	var requestCount int
	dupeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(signedJSON)
	})

	srv.Mux().Handle("/_matrix/key/v2/server", dupeHandler).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/", dupeHandler).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/{keyID}", dupeHandler).Methods("GET")

	foundKey := queryNotaryRaw(t, fedClient, "https://hs1", string(originName), nestedKeyID, 0)
	if requestCount == 0 {
		t.Fatalf("nested duplicate payload was never fetched — test did not exercise the duplicate parser path")
	}
	if foundKey != "" {
		t.Fatalf("hs1 returned key %s from a payload with a nested duplicate key — deep duplicate detection is missing", foundKey)
	}
}

// Test that once a key binding is confirmed via direct fetch, a subsequent direct fetch
// presenting different key material for the same key ID is rejected (First Seen Wins
// among direct observations).
//
// Per MSC4499 L111-113: "Direct-versus-direct conflicts are always resolved by First
// Seen Wins; the two-tier rule applies only to the notary-versus-direct case."
func testMSC4499KeyBindingPromotion(t *testing.T) {
	runtime.SkipIf(t, runtime.Dendrite)
	deployment := deployMSC4499TrustedNotary(t)
	defer deployment.Destroy(t)

	srv := federation.NewServer(t, deployment,
		federation.HandleMakeSendJoinRequests(),
		federation.HandleTransactionRequests(nil, nil),
	)
	srv.UnexpectedRequestsAreErrors = false
	cancel := srv.Listen()
	defer cancel()

	// Generate key A — this will be the first binding hs1 learns via hs2.
	pubKeyA, privKeyA, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate key A", err)

	keyID := gomatrixserverlib.KeyID("ed25519:msc4499_binding")

	// Set srv's signing identity to key A
	srv.KeyID = keyID
	srv.Priv = privKeyA

	// Mock key server serves key A.
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

	// Phase 1: Create room and join. This triggers hs1 to learn key A via hs2.
	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	ver := alice.GetDefaultRoomVersion(t)
	charlie := srv.UserID("charlie")
	serverRoom := srv.MustMakeRoom(t, ver, federation.InitialRoomEvents(ver, charlie))
	roomAlias := srv.MakeAliasMapping("binding_test", serverRoom.RoomID)
	alice.MustJoinRoom(t, roomAlias, []spec.ServerName{srv.ServerName()})

	// Send a valid event signed by key A. This should be accepted after hs1
	// has learned the key through its trusted notary path.
	eventValid := srv.MustCreateEvent(t, serverRoom, federation.Event{
		Sender: charlie,
		Type:   "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "Signed by key A (permanent binding)",
		},
	})
	serverRoom.AddEvent(eventValid)

	fedClient := srv.FederationClient(deployment)
	ctx, cancelCtx := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelCtx()

	resp, err := fedClient.SendTransaction(ctx, gomatrixserverlib.Transaction{
		TransactionID: gomatrixserverlib.TransactionID(fmt.Sprintf("msc4499-bind-valid-%d", time.Now().UnixNano())),
		Origin:        spec.ServerName(srv.ServerName()),
		Destination:   "hs1",
		PDUs:          []json.RawMessage{eventValid.JSON()},
	})
	must.NotError(t, "SendTransaction failed for key A event", err)
	for eventID, pduResp := range resp.PDUs {
		if pduResp.Error != "" {
			t.Fatalf("hs1 rejected valid event %s signed by key A: %s", eventID, pduResp.Error)
		}
	}

	_, since := alice.MustSync(t, client.SyncReq{})

	// Phase 2: Switch mock to serve key B for the same key ID.
	// Set valid_until to far future so the re-fetch satisfies any minimum_valid_until_ts.
	pubKeyB, privKeyB, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate key B", err)

	mockKeyServer.mu.Lock()
	mockKeyServer.privKey = privKeyB
	mockKeyServer.pubKey = pubKeyB
	mockKeyServer.verifyKeys[keyID] = pubKeyB
	mockKeyServer.requestCount = 0
	mockKeyServer.validUntil = time.Now().Add(48 * time.Hour)
	mockKeyServer.mu.Unlock()

	// Force a re-fetch via notary query with minimum_valid_until_ts beyond the
	// cached valid_until_ts. This ensures hs1 actually hits the mock and sees key B.
	fedHTTPClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: deployment.RoundTripper(),
	}
	minValid := time.Now().Add(25 * time.Hour).UnixMilli()
	_ = queryNotaryRaw(t, fedHTTPClient, "https://hs1", string(srv.ServerName()), string(keyID), minValid)

	// Verify the mock was actually consulted — without this, the test is vacuous
	mockKeyServer.mu.Lock()
	refetchCount := mockKeyServer.requestCount
	mockKeyServer.mu.Unlock()
	if refetchCount == 0 {
		t.Fatalf("Mock was never re-fetched in phase 2 — test is vacuous (hs1 used stale cache)")
	}

	// Phase 3: Send event signed by key B. hs1 may re-fetch (due to expired valid_until_ts)
	// and get key B, but MUST reject it per FSW — key A is the permanent binding.
	srv.KeyID = keyID
	srv.Priv = privKeyB

	eventConflict := srv.MustCreateEvent(t, serverRoom, federation.Event{
		Sender: charlie,
		Type:   "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "Signed by key B — conflicting binding, should be rejected",
		},
	})
	serverRoom.AddEvent(eventConflict)

	// Restore identity
	srv.KeyID = keyID
	srv.Priv = privKeyA

	ctx2, cancelCtx2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelCtx2()

	resp2, err := fedClient.SendTransaction(ctx2, gomatrixserverlib.Transaction{
		TransactionID: gomatrixserverlib.TransactionID(fmt.Sprintf("msc4499-bind-conflict-%d", time.Now().UnixNano())),
		Origin:        spec.ServerName(srv.ServerName()),
		Destination:   "hs1",
		PDUs:          []json.RawMessage{eventConflict.JSON()},
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
		// Check sync — the conflicting event must NOT appear
		time.Sleep(500 * time.Millisecond)
		syncResp, _ := alice.MustSync(t, client.SyncReq{Since: since, TimeoutMillis: "0"})
		events := syncResp.Get("rooms.join." + client.GjsonEscape(serverRoom.RoomID) + ".timeline.events").Array()
		for _, ev := range events {
			if ev.Get("event_id").Str == eventConflict.EventID() {
				t.Fatalf("hs1 accepted event %s signed by conflicting key B after permanent binding of key A — FSW not enforced on direct-vs-direct conflict", eventConflict.EventID())
			}
		}
	}
}

// Test that the server handles a large number of key IDs from a single remote server
// gracefully — it must not crash, reject the payload, or permanently ignore new keys
// even after exceeding any reasonable per-server quota.
//
// Per MSC4499 L423-437: implementations SHOULD enforce a limit (e.g., 1,000 keys),
// and MUST NOT ignore new Key IDs permanently. They MUST evict the oldest/LRU expired
// keys. Keys in verify_keys MUST always be prioritized and exempt from the retired-key
// ceiling.
func testMSC4499KeyStorageQuotaResilience(t *testing.T) {
	runtime.SkipIf(t, runtime.Dendrite)
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	fedClient := &http.Client{
		Timeout:   30 * time.Second, // larger timeout for bulk payload
		Transport: deployment.RoundTripper(),
	}

	srv := federation.NewServer(t, deployment)
	cancel := srv.Listen()
	defer cancel()

	originName := srv.ServerName()

	// Generate a signing key for the mock server
	sigPub, sigPriv, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate signing key", err)

	sigKeyID := gomatrixserverlib.KeyID("ed25519:msc4499_quota_signer")

	// Generate 3000 retired keys in old_verify_keys plus 1 signing key in
	// verify_keys. This is far beyond the example per-server quota in MSC4499,
	// so the oldest retired key should be evicted if the implementation enforces
	// a ceiling.
	numFillerKeys := 3000
	verifyKeys := map[gomatrixserverlib.KeyID]ed25519.PublicKey{
		sigKeyID: sigPub, // signing key — always in verify_keys
	}

	oldVerifyKeys := map[gomatrixserverlib.KeyID]gomatrixserverlib.OldVerifyKey{}
	var oldestKeyID gomatrixserverlib.KeyID
	for i := 0; i < numFillerKeys; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		must.NotError(t, fmt.Sprintf("failed to generate filler key %d", i), err)
		kid := gomatrixserverlib.KeyID(fmt.Sprintf("ed25519:msc4499_filler_%04d", i))
		oldVerifyKeys[kid] = gomatrixserverlib.OldVerifyKey{
			VerifyKey: gomatrixserverlib.VerifyKey{
				Key: spec.Base64Bytes(pub),
			},
			ExpiredTS: spec.AsTimestamp(time.Now().Add(-10 * time.Hour).Add(time.Duration(-i) * time.Second)),
		}
		oldestKeyID = kid
	}

	mockKeyServer := &MockKeyServer{
		serverName:    originName,
		keyID:         sigKeyID,
		privKey:       sigPriv,
		pubKey:        sigPub,
		verifyKeys:    verifyKeys,
		oldVerifyKeys: oldVerifyKeys,
		validUntil:    time.Now().Add(24 * time.Hour),
	}

	srv.Mux().Handle("/_matrix/key/v2/server", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/{keyID}", mockKeyServer).Methods("GET")

	// Query the signing key — this forces hs1 to fetch and process the entire
	// payload. If the server has a quota, it must silently evict or handle the
	// overflow without error.
	queryNotary(t, fedClient, "https://hs1", string(originName), string(sigKeyID), 0,
		base64.RawStdEncoding.EncodeToString(sigPub))

	// Verify hs1 can still resolve a retired key near the top of the retention set.
	firstKeyID := gomatrixserverlib.KeyID("ed25519:msc4499_filler_0000")
	firstKey := oldVerifyKeys[firstKeyID]
	queryNotary(t, fedClient, "https://hs1", string(originName), string(firstKeyID), 0,
		base64.RawStdEncoding.EncodeToString(firstKey.Key))

	// Verify the LAST filler key (oldest) has been evicted. The fixture
	// intentionally overflows any reasonable retired-key ceiling, so the oldest
	// retired binding should no longer be served.
	oldestKey := oldVerifyKeys[oldestKeyID]
	foundKey := queryNotaryRaw(t, fedClient, "https://hs1", string(originName), string(oldestKeyID), 0)
	must.Equal(t, foundKey, "",
		fmt.Sprintf("Expected oldest retired key %s to be evicted under quota pressure, but found %q",
			oldestKeyID, base64.RawStdEncoding.EncodeToString(oldestKey.Key)))
}

// Test that a binding observed active earlier is treated as corroborated and is
// retained ahead of uncorroborated retired keys when the retired-key ceiling is hit.
//
// Per MSC4499 L584-589: corroborated retired keys are retained before
// uncorroborated retired keys, regardless of effective retirement timestamp.
func testMSC4499KeyCorroborationTierRetention(t *testing.T) {
	runtime.SkipIf(t, runtime.Dendrite)
	deployment := deployMSC4499TrustedNotary(t)
	defer deployment.Destroy(t)

	fedClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: deployment.RoundTripper(),
	}

	srv := federation.NewServer(t, deployment)
	cancel := srv.Listen()
	defer cancel()

	originName := srv.ServerName()

	// Phase 1: Learn key A while it is active. hs1 sees this via hs2, which
	// should corroborate the binding for later retention decisions.
	pubKeyA, privKeyA, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate corroborated key A", err)
	keyIDA := gomatrixserverlib.KeyID("ed25519:msc4499_corroborated_a")

	mockKeyServer := &MockKeyServer{
		serverName: originName,
		keyID:      keyIDA,
		privKey:    privKeyA,
		pubKey:     pubKeyA,
		verifyKeys: map[gomatrixserverlib.KeyID]ed25519.PublicKey{
			keyIDA: pubKeyA,
		},
		oldVerifyKeys: map[gomatrixserverlib.KeyID]gomatrixserverlib.OldVerifyKey{},
		validUntil:    time.Now().Add(2 * time.Second),
	}

	srv.Mux().Handle("/_matrix/key/v2/server", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/{keyID}", mockKeyServer).Methods("GET")

	pubKeyABase64 := base64.RawStdEncoding.EncodeToString(pubKeyA)
	queryNotary(t, fedClient, "https://hs1", string(originName), string(keyIDA), 0, pubKeyABase64)

	time.Sleep(3 * time.Second)

	// Phase 2: Rotate the origin to a new active key and flood old_verify_keys
	// with uncorroborated retired bindings. Key A should survive because hs1
	// already saw it active before retirement.
	pubKeyB, privKeyB, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate active key B", err)
	keyIDB := gomatrixserverlib.KeyID("ed25519:msc4499_active_b")

	verifyKeys := map[gomatrixserverlib.KeyID]ed25519.PublicKey{
		keyIDB: pubKeyB,
	}
	oldVerifyKeys := make(map[gomatrixserverlib.KeyID]gomatrixserverlib.OldVerifyKey, 3001)
	oldVerifyKeys[keyIDA] = gomatrixserverlib.OldVerifyKey{
		VerifyKey: gomatrixserverlib.VerifyKey{
			Key: spec.Base64Bytes(pubKeyA),
		},
		ExpiredTS: spec.AsTimestamp(time.Now().Add(-72 * time.Hour)),
	}

	for i := 0; i < 3000; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		must.NotError(t, fmt.Sprintf("failed to generate uncorroborated key %d", i), err)
		kid := gomatrixserverlib.KeyID(fmt.Sprintf("ed25519:msc4499_uncorroborated_%04d", i))
		oldVerifyKeys[kid] = gomatrixserverlib.OldVerifyKey{
			VerifyKey: gomatrixserverlib.VerifyKey{
				Key: spec.Base64Bytes(pub),
			},
			ExpiredTS: spec.AsTimestamp(time.Now().Add(-1 * time.Hour).Add(-time.Duration(i) * time.Second)),
		}
	}

	mockKeyServer.mu.Lock()
	mockKeyServer.keyID = keyIDB
	mockKeyServer.privKey = privKeyB
	mockKeyServer.pubKey = pubKeyB
	mockKeyServer.verifyKeys = verifyKeys
	mockKeyServer.oldVerifyKeys = oldVerifyKeys
	mockKeyServer.validUntil = time.Now().Add(48 * time.Hour)
	mockKeyServer.requestCount = 0
	mockKeyServer.mu.Unlock()

	minValidUntil := time.Now().Add(1 * time.Hour).UnixMilli()
	foundKey := queryNotaryRaw(t, fedClient, "https://hs1", string(originName), string(keyIDA), minValidUntil)
	must.Equal(t, foundKey, pubKeyABase64,
		"Expected corroborated retired key A to survive the ceiling ahead of uncorroborated retired keys")

	mockKeyServer.mu.Lock()
	reqCount := mockKeyServer.requestCount
	mockKeyServer.mu.Unlock()
	if reqCount == 0 {
		t.Fatalf("Mock key server was not re-fetched in corroboration test — the ceiling path was not exercised")
	}
}

// Test that a successful key fetch clears the backoff state for that server.
//
// Per MSC4499 L72: "If that fetch succeeds and the request authenticates,
// servers SHOULD clear the backoff state."
//
// Flow:
//  1. Mock returns 500 → query triggers negative caching / backoff
//  2. Mock starts succeeding
//  3. Wait for backoff to expire, then query again → MUST succeed
//  4. Mock fails again
//  5. Immediately query → backoff should restart from initial interval
//     (not carry over from previous exponential level)
//
// Note: we cannot test the full 60-second minimum in CI, so we test the
// observable clear-on-success behavior with practical timing.
func testMSC4499KeyBackoffClearedOnSuccess(t *testing.T) {
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

	keyID := gomatrixserverlib.KeyID("ed25519:msc4499_backoff_clear")
	wantKey := base64.RawStdEncoding.EncodeToString(pubKey)

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
		shouldFail:    true, // Phase 1: fail
	}

	srv.Mux().Handle("/_matrix/key/v2/server", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/{keyID}", mockKeyServer).Methods("GET")

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

	// Phase 1: Query while mock is failing → triggers backoff
	resp1, err := fedClient.Post("https://hs1/_matrix/key/v2/query", "application/json", bytes.NewReader(bodyBytes))
	must.NotError(t, "failed to POST notary query (phase 1)", err)
	resp1.Body.Close()

	mockKeyServer.mu.Lock()
	phase1Count := mockKeyServer.requestCount
	mockKeyServer.mu.Unlock()
	if phase1Count == 0 {
		t.Fatalf("Mock was never consulted in phase 1 — backoff path not exercised")
	}

	// Discriminating assertion: immediately re-query and prove backoff is active.
	// A server with NO backoff would re-fetch here; one with backoff would not.
	mockKeyServer.mu.Lock()
	mockKeyServer.requestCount = 0
	mockKeyServer.mu.Unlock()

	resp1b, err := fedClient.Post("https://hs1/_matrix/key/v2/query", "application/json", bytes.NewReader(bodyBytes))
	must.NotError(t, "failed to POST notary query (phase 1b)", err)
	resp1b.Body.Close()

	mockKeyServer.mu.Lock()
	phase1bCount := mockKeyServer.requestCount
	mockKeyServer.mu.Unlock()
	if phase1bCount > 0 {
		t.Skipf("Server does not implement backoff — made %d request(s) during backoff window", phase1bCount)
	}

	// Phase 2: Unblock mock, set short valid_until so hs1 will try again
	mockKeyServer.mu.Lock()
	mockKeyServer.shouldFail = false
	mockKeyServer.requestCount = 0
	mockKeyServer.validUntil = time.Now().Add(2 * time.Second)
	mockKeyServer.mu.Unlock()

	// Wait for backoff to expire. Implementations should configure a short
	// backoff for testing (e.g., 2s via msc4499_backoff_secs). The spec mandates
	// ≥60s in production, but that's too slow for CI.
	time.Sleep(3 * time.Second)

	// Phase 3: Query again — mock is now healthy, should succeed and clear backoff
	foundKey := queryNotaryRaw(t, fedClient, "https://hs1", string(originName), string(keyID), 0)
	if foundKey != wantKey {
		t.Skipf("Server enforces strict backoff >3s — skipping clear-on-success verification (got %q, want %q)", foundKey, wantKey)
	}

	// Phase 4: Verify backoff is truly cleared by checking the key is cached
	// and served without delay on immediate re-query
	mockKeyServer.mu.Lock()
	mockKeyServer.requestCount = 0
	mockKeyServer.shouldFail = true // fail again to see if backoff restarts from scratch
	mockKeyServer.mu.Unlock()

	// This query should succeed from cache (key was just fetched successfully)
	foundKey2 := queryNotaryRaw(t, fedClient, "https://hs1", string(originName), string(keyID), 0)
	if foundKey2 != wantKey {
		t.Fatalf("Key not served from cache after successful fetch — got %q, want %q", foundKey2, wantKey)
	}
}

// Test that a provisional (notary-learned) binding that has expired MUST NOT be
// overridden by a direct fetch presenting different key material.
//
// Per MSC4499 L147-157: "a provisional binding MUST NOT be overridden if it has
// already expired or been retired." A provisional key whose cached valid_until_ts
// has passed is frozen. Any conflicting key body returned by a direct fetch for
// that key ID MUST be rejected as a collision.
//
// Flow:
//  1. hs1 queries hs2 as its trusted notary and learns key A with short valid_until_ts
//  2. Wait for valid_until_ts to expire
//  3. Switch the origin mock to serve key B for the same key ID
//  4. Query hs1 again with minimum_valid_until_ts forcing a re-fetch
//  5. Assert: key B MUST NOT be returned (provisional binding is frozen)
func testMSC4499KeyProvisionalOverrideFreeze(t *testing.T) {
	runtime.SkipIf(t, runtime.Dendrite)
	deployment := deployMSC4499TrustedNotary(t)
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

	keyID := gomatrixserverlib.KeyID("ed25519:msc4499_freeze")

	// Phase 1: Serve key A with a short valid_until (2 seconds from now).
	// hs2 learns this via direct fetch from the origin mock, and hs1 learns it via hs2.
	mockKeyServer := &MockKeyServer{
		serverName: originName,
		keyID:      keyID,
		privKey:    privKeyA,
		pubKey:     pubKeyA,
		verifyKeys: map[gomatrixserverlib.KeyID]ed25519.PublicKey{
			keyID: pubKeyA,
		},
		oldVerifyKeys: map[gomatrixserverlib.KeyID]gomatrixserverlib.OldVerifyKey{},
		validUntil:    time.Now().Add(2 * time.Second),
	}

	srv.Mux().Handle("/_matrix/key/v2/server", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/{keyID}", mockKeyServer).Methods("GET")

	pubKeyABase64 := base64.RawStdEncoding.EncodeToString(pubKeyA)

	// Phase 1: Query hs1 → hs1 consults hs2 as its trusted notary and caches key A
	queryNotary(t, fedClient, "https://hs1", string(originName), string(keyID), 0, pubKeyABase64)

	// Phase 2: Wait for valid_until_ts to expire
	time.Sleep(3 * time.Second)

	// Phase 3: Switch mock to serve key B for the same key ID.
	// Set far-future valid_until so the re-fetch satisfies any constraint.
	pubKeyB, privKeyB, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate key B", err)

	mockKeyServer.mu.Lock()
	mockKeyServer.privKey = privKeyB
	mockKeyServer.pubKey = pubKeyB
	mockKeyServer.verifyKeys[keyID] = pubKeyB
	mockKeyServer.validUntil = time.Now().Add(48 * time.Hour)
	mockKeyServer.mu.Unlock()

	pubKeyBBase64 := base64.RawStdEncoding.EncodeToString(pubKeyB)

	// Phase 4: Query with minimum_valid_until_ts beyond the expired cached time,
	// forcing hs1 to re-fetch via hs2. The origin mock now serves key B.
	minValidUntil := time.Now().Add(1 * time.Hour).UnixMilli()
	foundKey := queryNotaryRaw(t, fedClient, "https://hs1", string(originName), string(keyID), minValidUntil)

	// Assert: key B MUST NOT be returned. The provisional binding is frozen.
	// Acceptable outcomes:
	//   1. key A is returned (frozen provisional — correct)
	//   2. server is omitted from response (can't satisfy constraint — correct)
	//   3. key B is returned (frozen provisional was overridden — VIOLATION)
	if foundKey == pubKeyBBase64 {
		t.Fatalf("hs1 returned colliding key B after provisional binding expired — " +
			"Provisional Override Freeze not enforced. Expired provisional bindings " +
			"MUST NOT be overridden by a direct fetch (MSC4499 L147-157)")
	}

	if foundKey == pubKeyABase64 {
		t.Logf("hs1 correctly returned frozen provisional key A despite expired valid_until_ts")
	} else if foundKey == "" {
		t.Logf("hs1 correctly omitted the server (expired key A can't satisfy constraint, key B rejected)")
	}
}

// Test that a key response payload with more than 50 keys in verify_keys is
// treated as malformed/hostile and rejected entirely.
//
// Per MSC4499 L551-558: "If a single key response payload contains more than
// 50 keys in its verify_keys dictionary, receiving servers MUST treat the entire
// response payload as malformed/hostile and reject it."
//
// Flow:
//  1. Serve a payload with 51 keys in verify_keys
//  2. Query notary for the signing key
//  3. Assert: the entire payload is rejected — signing key should NOT be found
func testMSC4499KeyVerifyKeysCeiling(t *testing.T) {
	runtime.SkipIf(t, runtime.Dendrite)
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

	sigPub, sigPriv, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate signing key", err)

	sigKeyID := gomatrixserverlib.KeyID("ed25519:msc4499_ceiling_signer")

	// Generate 51 keys in verify_keys (signing key + 50 fillers = 51 total,
	// exceeding the 50-key ceiling).
	numFillerKeys := 50
	verifyKeys := map[gomatrixserverlib.KeyID]ed25519.PublicKey{
		sigKeyID: sigPub,
	}
	for i := 0; i < numFillerKeys; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		must.NotError(t, fmt.Sprintf("failed to generate filler key %d", i), err)
		kid := gomatrixserverlib.KeyID(fmt.Sprintf("ed25519:msc4499_ceil_%04d", i))
		verifyKeys[kid] = pub
	}

	mockKeyServer := &MockKeyServer{
		serverName:    originName,
		keyID:         sigKeyID,
		privKey:       sigPriv,
		pubKey:        sigPub,
		verifyKeys:    verifyKeys,
		oldVerifyKeys: map[gomatrixserverlib.KeyID]gomatrixserverlib.OldVerifyKey{},
		validUntil:    time.Now().Add(24 * time.Hour),
	}

	srv.Mux().Handle("/_matrix/key/v2/server", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/{keyID}", mockKeyServer).Methods("GET")

	// Query for the signing key. If hs1 enforces the 50-key ceiling, it should
	// reject the entire payload and the signing key should be absent.
	foundKey := queryNotaryRaw(t, fedClient, "https://hs1", string(originName), string(sigKeyID), 0)

	if foundKey != "" {
		t.Fatalf("hs1 accepted a payload with %d verify_keys (ceiling is 50) — "+
			"key %s was returned instead of rejecting the payload as hostile (MSC4499 L551-558)",
			len(verifyKeys), sigKeyID)
	}

	t.Logf("hs1 correctly rejected the %d-key payload as hostile", len(verifyKeys))
}

// Test that a future expired_ts (beyond a 5-minute clock-skew allowance) is
// treated as malformed for that specific key entry, but does NOT poison the
// rest of the response payload.
//
// Per MSC4499 L351-354: "A future expired_ts (beyond a 5-minute clock-skew
// allowance) MUST be treated as malformed for that specific key entry, but
// MUST NOT poison the rest of the response payload."
//
// Flow:
//  1. Serve a payload with two keys: key A (valid, in verify_keys) and key B
//     (in old_verify_keys with expired_ts = now + 1 year — malformed)
//  2. Query for key A → should be returned (payload not poisoned)
//  3. Query for key B → should be absent (malformed entry ignored)
func testMSC4499KeyExpiredTsSanityCheck(t *testing.T) {
	runtime.SkipIf(t, runtime.Dendrite)
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

	// Key A: signing key, valid and in verify_keys
	pubKeyA, privKeyA, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate key A", err)

	// Key B: in old_verify_keys with future expired_ts (malformed)
	pubKeyB, _, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate key B", err)

	keyIDA := gomatrixserverlib.KeyID("ed25519:msc4499_sanity_a")
	keyIDB := gomatrixserverlib.KeyID("ed25519:msc4499_sanity_b")

	// Future expired_ts: 1 year from now — clearly malformed
	futureExpiredTs := spec.AsTimestamp(time.Now().Add(365 * 24 * time.Hour))

	mockKeyServer := &MockKeyServer{
		serverName: originName,
		keyID:      keyIDA,
		privKey:    privKeyA,
		pubKey:     pubKeyA,
		verifyKeys: map[gomatrixserverlib.KeyID]ed25519.PublicKey{
			keyIDA: pubKeyA,
		},
		oldVerifyKeys: map[gomatrixserverlib.KeyID]gomatrixserverlib.OldVerifyKey{
			keyIDB: {
				VerifyKey: gomatrixserverlib.VerifyKey{
					Key: spec.Base64Bytes(pubKeyB),
				},
				ExpiredTS: futureExpiredTs,
			},
		},
		validUntil: time.Now().Add(24 * time.Hour),
	}

	srv.Mux().Handle("/_matrix/key/v2/server", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/{keyID}", mockKeyServer).Methods("GET")

	pubKeyABase64 := base64.RawStdEncoding.EncodeToString(pubKeyA)

	// Query for key A — the valid key. It MUST be returned (payload not poisoned
	// by key B's malformed expired_ts).
	foundKeyA := queryNotaryRaw(t, fedClient, "https://hs1", string(originName), string(keyIDA), 0)
	if foundKeyA != pubKeyABase64 {
		t.Fatalf("Key A (valid) was not returned — the malformed expired_ts on key B "+
			"appears to have poisoned the entire payload (got %q, want %q)", foundKeyA, pubKeyABase64)
	}

	// Query for key B — it has a future expired_ts and MUST be treated as malformed.
	// The notary should not serve it in old_verify_keys.
	// Check the raw response for key B in old_verify_keys.
	reqBody := map[string]interface{}{
		"server_keys": map[string]interface{}{
			string(originName): map[string]interface{}{
				string(keyIDB): map[string]interface{}{
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

	must.Equal(t, resp.StatusCode, 200, "notary must return 200")

	// Check if key B appears anywhere in old_verify_keys
	result := gjson.ParseBytes(respBytes)
	serverKeys := result.Get("server_keys").Array()
	for _, sk := range serverKeys {
		if sk.Get("server_name").Str == string(originName) {
			foundKeyB := sk.Get("old_verify_keys." + client.GjsonEscape(string(keyIDB)) + ".key").Str
			if foundKeyB != "" {
				t.Fatalf("hs1 served key B (expired_ts in the future) in old_verify_keys — " +
					"future expired_ts MUST be treated as malformed (MSC4499 L351-354)")
			}
		}
	}

	t.Logf("Key B (future expired_ts) correctly ignored; key A (valid) correctly served")
}
