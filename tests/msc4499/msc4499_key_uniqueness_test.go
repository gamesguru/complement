package tests

import (
	"bytes"
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
}

func (m *MockKeyServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")

	if m.shouldCollide {
		_, colPriv, _ := ed25519.GenerateKey(rand.Reader)
		colPub := colPriv.Public().(ed25519.PublicKey)

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

	// Query notary again with higher minimum_valid_until_ts to trigger a re-fetch.
	// Even on re-fetch, hs1 MUST reject the colliding Keypair B and stick to the first seen Keypair A.
	minValidUntil := time.Now().Add(12 * time.Hour).UnixMilli()
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

	if resp.StatusCode == 200 {
		respBytes, err := io.ReadAll(resp.Body)
		must.NotError(t, "failed to read response", err)
		result := gjson.ParseBytes(respBytes)
		serverKeys := result.Get("server_keys").Array()
		for _, sk := range serverKeys {
			if sk.Get("server_name").Str == string(originName) {
				foundKey := sk.Get("verify_keys." + client.GjsonEscape(string(keyID)) + ".key").Str
				if foundKey != "" {
					t.Fatalf("hs1 accepted a malformed/colliding intra-payload key response and returned key: %s", foundKey)
				}
			}
		}
	}
}
