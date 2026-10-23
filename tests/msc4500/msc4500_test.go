package msc4500

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Wombat-Foundation/gomatrixcrypto/lthash"
	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/gomatrixserverlib/fclient"
	"github.com/tidwall/gjson"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/must"
)

// TestMSC4500State exercises the
// outbound state_hashes extension on /send transactions.
func TestMSC4500State(t *testing.T) {
	t.Run("StateHashes", testMSC4500StateHashes)
	t.Run("Outbound", testMSC4500StateOutbound)
}

const (
	// msc4500PrimaryAlgorithm names the primary BLAKE3 LtHash16 accumulator. The
	// "-v1" is an algorithm
	// identifier, not a spec version.
	msc4500PrimaryAlgorithm = "lthash16-blake3-v1"

	// msc4500Algorithm is the composite profile carried in a /send
	// transaction's state_hashes.algorithm: the primary accumulator plus the
	// redaction overlay.
	msc4500Algorithm = msc4500PrimaryAlgorithm + "+redactions-blake3-v1"

	// msc4500EmptyDigest is the collapse digest of an all-zero lattice. It is the
	// redaction digest of a state in which no selected event is redacted.
	msc4500EmptyDigest = "viqN49z0bJTOhc3I4HrDCPTYqVSQ2VbDjXgP1hDbCBM"
)

// testMSC4500StateHashes drives the receiver contract with hand-built
// state_hashes payloads: a match, primary and redaction-only mismatches, and the
// cases a receiver must defer instead of reporting.
func testMSC4500StateHashes(t *testing.T) {
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
	serverRoom := srv.MustJoinRoom(t, deployment, "hs1", roomID, charlie)
	joinEvent := serverRoom.CurrentState("m.room.member", charlie)
	must.NotEqual(t, joinEvent, nil, "expected charlie join event in remote room state")

	// A message leaves state untouched, so its before and after digests are the
	// digest after charlie's join, which hs1 already knows.
	stateDigest := msc4500StateDigest(serverRoom)
	const bogusDigest = "ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8"

	// send builds a fresh message, sends it with the given state_hashes entry
	// builder under the given algorithm, and returns hs1's result for it.
	send := func(t *testing.T, algorithm string, entry func(eventID string) map[string]interface{}) gjson.Result {
		t.Helper()
		event := srv.MustCreateEvent(t, serverRoom, federation.Event{
			Sender: charlie,
			Type:   "m.room.message",
			Content: map[string]interface{}{
				"msgtype": "m.text",
				"body":    "state hash case",
			},
		})
		return mustSendStateHashes(t, srv, deployment, event, map[string]interface{}{
			"algorithm": algorithm,
			"entries":   map[string]interface{}{event.EventID(): entry(event.EventID())},
		})
	}
	full := func(after, redactionsAfter string) func(string) map[string]interface{} {
		return func(string) map[string]interface{} {
			return map[string]interface{}{
				"before":            stateDigest,
				"after":             after,
				"redactions_before": msc4500EmptyDigest,
				"redactions_after":  redactionsAfter,
			}
		}
	}

	t.Run("Match", func(t *testing.T) {
		res := send(t, msc4500Algorithm, full(stateDigest, msc4500EmptyDigest))
		must.Equal(t, res.Get("state_hash_mismatch").Exists(), false, "unexpected state_hash_mismatch")
	})

	t.Run("PrimaryMismatch", func(t *testing.T) {
		res := send(t, msc4500Algorithm, full(bogusDigest, msc4500EmptyDigest))
		mismatch := res.Get("state_hash_mismatch")
		must.Equal(t, mismatch.Exists(), true, "state_hash_mismatch not found in response")
		must.Equal(t, mismatch.Get("algorithm").Str, msc4500Algorithm, "mismatch algorithm wrong")
		must.Equal(t, mismatch.Get("expected_after").Str, stateDigest, "expected_after wrong")
		must.Equal(t, mismatch.Get("received_after").Str, bogusDigest, "received_after wrong")
		// The redaction overlays agree, so they must not be blamed.
		must.Equal(t, mismatch.Get("expected_redactions_after").Str, msc4500EmptyDigest, "expected_redactions_after wrong")
		must.Equal(t, mismatch.Get("received_redactions_after").Str, msc4500EmptyDigest, "received_redactions_after wrong")
	})

	// The servers agree on every selected event ID but not on whether one is
	// effectively redacted: the case the primary digest is blind to.
	t.Run("RedactionOnlyMismatch", func(t *testing.T) {
		res := send(t, msc4500Algorithm, full(stateDigest, bogusDigest))
		mismatch := res.Get("state_hash_mismatch")
		must.Equal(t, mismatch.Exists(), true, "redaction-only mismatch was not reported")
		must.Equal(t, mismatch.Get("expected_after").Str, mismatch.Get("received_after").Str,
			"primary digests should agree in a redaction-only mismatch")
		must.Equal(t, mismatch.Get("expected_redactions_after").Str, msc4500EmptyDigest, "expected_redactions_after wrong")
		must.Equal(t, mismatch.Get("received_redactions_after").Str, bogusDigest, "received_redactions_after wrong")
	})

	// A limited entry is an explicit deferral, never a mismatch, even when the
	// receiver would otherwise disagree.
	t.Run("Limited", func(t *testing.T) {
		res := send(t, msc4500Algorithm, func(string) map[string]interface{} {
			return map[string]interface{}{
				"before":            nil,
				"redactions_before": nil,
				"limited":           true,
			}
		})
		must.Equal(t, res.Get("state_hash_mismatch").Exists(), false, "limited entry must be deferred")
	})

	// Omitting a redaction digest is malformed, not an empty overlay.
	t.Run("MalformedEntryDeferred", func(t *testing.T) {
		res := send(t, msc4500Algorithm, func(string) map[string]interface{} {
			return map[string]interface{}{
				"before":            stateDigest,
				"after":             bogusDigest,
				"redactions_before": msc4500EmptyDigest,
			}
		})
		must.Equal(t, res.Get("state_hash_mismatch").Exists(), false, "malformed entry must be deferred")
	})

	// One algorithm governs the transaction; an unknown one defers it whole.
	t.Run("UnknownAlgorithmDeferred", func(t *testing.T) {
		res := send(t, "lthash16-blake3-v9+future", full(bogusDigest, bogusDigest))
		must.Equal(t, res.Get("state_hash_mismatch").Exists(), false, "unknown algorithm must be deferred")
	})
}

// mustSendStateHashes sends one PDU with the given state_hashes object under the
// unstable key and returns hs1's per-PDU result.
func mustSendStateHashes(
	t *testing.T,
	srv *federation.Server,
	deployment complement.Deployment,
	event gomatrixserverlib.PDU,
	stateHashes map[string]interface{},
) gjson.Result {
	t.Helper()

	txnBody, err := json.Marshal(map[string]interface{}{
		"origin":                        srv.ServerName(),
		"origin_server_ts":              time.Now().UnixNano() / 1000000,
		"pdus":                          []json.RawMessage{event.JSON()},
		"tk.nutra.msc4500.state_hashes": stateHashes,
	})
	must.NotError(t, "json marshal txn", err)

	txnID := fmt.Sprintf("txn-%d", time.Now().UnixNano())
	reqURI := fmt.Sprintf("/_matrix/federation/v1/send/%s", txnID)
	req := fclient.NewFederationRequest("PUT", srv.ServerName(), deployment.GetFullyQualifiedHomeserverName(t, "hs1"), reqURI)
	must.NotError(t, "set content", req.SetContent(json.RawMessage(txnBody)))

	res, err := srv.DoFederationRequest(context.Background(), t, deployment, req)
	must.NotError(t, "do federation request", err)
	resBody, err := io.ReadAll(res.Body)
	must.NotError(t, "read res body", err)
	must.NotError(t, "close res body", res.Body.Close())
	t.Logf("Response: %s", string(resBody))

	result := gjson.GetBytes(resBody, "pdus").Get(gjson.Escape(event.EventID()))
	must.Equal(t, result.Exists(), true, fmt.Sprintf("send response omitted result for event %s", event.EventID()))
	must.Equal(t, result.Get("error").Exists(), false, fmt.Sprintf("send response rejected event %s: %s", event.EventID(), result.Get("error").Str))
	return result
}

// testMSC4500StateOutbound verifies that outbound /send transactions carry the
// MSC4500 state_hashes extension, so that remote
// servers can validate state equivalence across the wire.
func testMSC4500StateOutbound(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	// Remote homeserver that captures raw /send transaction bodies. We parse the
	// raw body (rather than gomatrixserverlib.Transaction) because the custom
	// state_hashes field would otherwise be dropped.
	found := helpers.NewWaiter()
	var (
		mu             sync.Mutex
		observedAfter  string
		observedDigest bool
		expectedDigest string
	)

	srv := federation.NewServer(t, deployment,
		federation.HandleKeyRequests(),
		federation.HandleMakeSendJoinRequests(),
	)
	srv.Mux().HandleFunc("/_matrix/federation/v1/send/{transactionID}", func(w http.ResponseWriter, req *http.Request) {
		defer func() {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				return
			}
			// Check the transaction for the state_hashes extension after reading it.
			checkMSC4500Outbound(body, found, &mu, &observedAfter, &observedDigest)
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
	serverRoom := srv.MustJoinRoom(t, deployment, "hs1", roomID, charlie)
	joinEvent := serverRoom.CurrentState("m.room.member", charlie)
	must.NotEqual(t, joinEvent, nil, "expected charlie join event in remote room state")
	expectedDigest = msc4500StateDigest(serverRoom)

	// Trigger an outbound transaction by having alice send a message and syncing
	// until it is present (which forces the homeserver to forward it to charlie).
	alice.SendEventSynced(t, roomID, b.Event{
		Type: "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "hello",
		},
	})

	found.Waitf(t, 15*time.Second, "timed out waiting for outbound state_hashes on /send")

	mu.Lock()
	defer mu.Unlock()
	must.Equal(t, observedDigest, true, "did not observe a valid outbound state_hashes entry")
	must.Equal(t, observedAfter, expectedDigest, "outbound state_hashes digest wrong")
}

// checkMSC4500Outbound inspects a raw /send transaction body and finishes the
// waiter if it carries a valid state_hashes extension.
//
// It parses the body into a generic map because the custom state_hashes
// extension is not represented by the strongly-typed Transaction.
func checkMSC4500Outbound(raw json.RawMessage, found *helpers.Waiter, mu *sync.Mutex, observedAfter *string, observedDigest *bool) {
	var body map[string]interface{}
	if err := json.Unmarshal(raw, &body); err != nil {
		return
	}
	stateHashes, ok := body["state_hashes"]
	if !ok {
		stateHashes, ok = body["tk.nutra.msc4500.state_hashes"]
	}
	if !ok {
		return
	}
	sh, ok := stateHashes.(map[string]interface{})
	if !ok {
		return
	}
	if algo, _ := sh["algorithm"].(string); algo != msc4500Algorithm {
		return
	}
	entries, ok := sh["entries"].(map[string]interface{})
	if !ok {
		return
	}
	for _, v := range entries {
		entry, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		if limited, _ := entry["limited"].(bool); limited {
			continue
		}
		// Every non-limited entry carries all four digests, each a 43-char
		// base64url BLAKE3-256 collapse.
		digests := make(map[string]string, 4)
		complete := true
		for _, key := range []string{"before", "after", "redactions_before", "redactions_after"} {
			d, _ := entry[key].(string)
			if len(d) != 43 {
				complete = false
				break
			}
			digests[key] = d
		}
		if !complete || digests["before"] != digests["after"] {
			continue
		}
		// A message leaves the redaction overlay empty in this room.
		if digests["redactions_before"] != msc4500EmptyDigest || digests["redactions_after"] != msc4500EmptyDigest {
			continue
		}
		mu.Lock()
		*observedAfter = digests["after"]
		*observedDigest = true
		mu.Unlock()
		found.Finish()
		return
	}
}

// msc4500StateDigest is the MSC4500 state digest of the room's current state as
// the test server holds it: the BLAKE3 collapse of the LtHash over every
// (type, state_key, event_id) tuple.
func msc4500StateDigest(room *federation.ServerRoom) string {
	var entries []lthash.Entry
	for _, ev := range room.AllCurrentState() {
		entries = append(entries, lthash.Entry{EventType: ev.Type(), StateKey: *ev.StateKey(), EventID: ev.EventID()})
	}
	digest := lthash.FromEntries(entries).Checksum()
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
