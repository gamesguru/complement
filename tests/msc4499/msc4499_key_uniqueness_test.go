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

	// Query notary again with minimum_valid_until_ts greater than the cached valid_until_ts to force a re-fetch.
	// Even on re-fetch, hs1 MUST reject the colliding Keypair B and stick to the first seen Keypair A.
	minValidUntil := mockKeyServer.validUntil.Add(time.Hour).UnixMilli()
	queryNotary(t, fedClient, "https://hs1", string(originName), string(keyID), minValidUntil, base64.RawStdEncoding.EncodeToString(pubKeyA))
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

	keyID := gomatrixserverlib.KeyID("ed25519:msc4499_key")

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
		shouldCollide: true,
	}

	srv.Mux().Handle("/_matrix/key/v2/server", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/{keyID}", mockKeyServer).Methods("GET")

	// Since the key response payload contains duplicate/conflicting key bodies under the same key ID,
	// hs1 MUST reject the entire payload as malformed, so the query must fail or not return any valid keys.
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

	// Since the fetched key response payload is rejected as malformed due to collisions,
	// hs1 MUST fail the notary query with a non-200 status code (e.g. 502 Bad Gateway / 500 Internal Error).
	if resp.StatusCode == 200 {
		t.Fatalf("hs1 returned 200 OK for a query where the fetched key payload was malformed/colliding")
	}
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
	var wg sync.WaitGroup
	concurrency := 10
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			queryNotary(t, fedClient, "https://hs1", string(originName), string(keyID), 0, base64.RawStdEncoding.EncodeToString(pubKey))
		}()
	}

	wg.Wait()

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

	// Unblock mock key server
	mockKeyServer.mu.Lock()
	mockKeyServer.shouldFail = false
	mockKeyServer.requestCount = 0 // reset
	mockKeyServer.mu.Unlock()

	// Instantly call notary again
	resp2, err := fedClient.Post("https://hs1/_matrix/key/v2/query", "application/json", bytes.NewReader(bodyBytes))
	must.NotError(t, "failed to POST notary query", err)
	defer resp2.Body.Close()

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
		federation.HandleKeyRequests(),
		federation.HandleMakeSendJoinRequests(),
		federation.HandleTransactionRequests(nil, nil),
	)
	srv.UnexpectedRequestsAreErrors = false
	cancel := srv.Listen()
	defer cancel()

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	// Create a public room on srv
	ver := alice.GetDefaultRoomVersion(t)
	charlie := srv.UserID("charlie")
	serverRoom := srv.MustMakeRoom(t, ver, federation.InitialRoomEvents(ver, charlie))
	roomAlias := srv.MakeAliasMapping("historical_test", serverRoom.RoomID)

	// Join hs1 to the room
	alice.MustJoinRoom(t, roomAlias, []spec.ServerName{srv.ServerName()})

	// Generate key pairs
	pubKeyActive, privKeyActive, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate active key", err)

	pubKeyExpired, privKeyExpired, err := ed25519.GenerateKey(rand.Reader)
	must.NotError(t, "failed to generate expired key", err)

	keyIDActive := gomatrixserverlib.KeyID("ed25519:msc4499_active")
	keyIDExpired := gomatrixserverlib.KeyID("ed25519:msc4499_expired")

	// Create our custom MockKeyServer that serves KeyActive,
	// and KeyExpired under old_verify_keys with a dynamic expired_ts.
	mockKeyServer := &MockKeyServer{
		serverName: srv.ServerName(),
		keyID:      keyIDActive,
		privKey:    privKeyActive,
		pubKey:     pubKeyActive,
		verifyKeys: map[gomatrixserverlib.KeyID]ed25519.PublicKey{
			keyIDActive: pubKeyActive,
		},
		oldVerifyKeys: map[gomatrixserverlib.KeyID]gomatrixserverlib.OldVerifyKey{
			keyIDExpired: {
				VerifyKey: gomatrixserverlib.VerifyKey{
					Key: spec.Base64Bytes(pubKeyExpired),
				},
				ExpiredTS: spec.AsTimestamp(time.Now().Add(10 * time.Minute)), // initially valid (future expired_ts)
			},
		},
		validUntil: time.Now().Add(24 * time.Hour),
	}

	// Register our custom key server on srv's Mux
	srv.Mux().Handle("/_matrix/key/v2/server", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/", mockKeyServer).Methods("GET")
	srv.Mux().Handle("/_matrix/key/v2/server/{keyID}", mockKeyServer).Methods("GET")

	// Phase 1: Send a message signed by KeyExpired while it is still valid (expired_ts in the future)
	// Temporarily set srv identity to KeyExpired so MustCreateEvent signs with it
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

	// Send valid event. Since event.origin_server_ts (approx now) < expired_ts (now + 10m), hs1 MUST accept it!
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

	// Phase 2: Now expire KeyExpired by setting its expired_ts to the past (now - 10m).
	mockKeyServer.mu.Lock()
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
