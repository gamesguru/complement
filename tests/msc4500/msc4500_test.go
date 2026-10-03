package msc4500

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wombat-Foundation/gomatrixcrypto/lthash"
	"github.com/matrix-org/gomatrixserverlib"
	"github.com/matrix-org/gomatrixserverlib/fclient"
	"github.com/tidwall/gjson"
	"github.com/zeebo/blake3"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/match"
	"github.com/matrix-org/complement/must"
)

// TestMSC4500State exercises the MSC4500 state_accumulator endpoint and the
// outbound state_hashes extension on /send transactions.
func TestMSC4500State(t *testing.T) {
	t.Run("Accumulator", testMSC4500StateAccumulator)
	t.Run("HashMatch", testMSC4500StateHashMatch)
	t.Run("HashMismatch", testMSC4500StateHashMismatch)
	t.Run("Outbound", testMSC4500StateOutbound)
}

// msc4500Algorithm is the MSC4500 wire identifier for the BLAKE3 LtHash16
// digest profile. It names the complete cryptographic profile so a receiver can
// never mistake it for a pre-BLAKE3 instantiation.
const msc4500Algorithm = "lthash16-blake3-v1"

// testMSC4500StateAccumulator verifies the state_accumulator endpoint against a
// lattice rebuilt independently with gomatrixcrypto's lthash package, covering a
// baseline snapshot, a rejected state event, and an accepted state replacement.
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
	serverRoom := srv.MustJoinRoom(t, deployment, "hs1", roomID, charlie)

	// The join exchange already handed this test the membership events, so they
	// enter the cache for free; every other state event must be fetched lazily
	// over federation.
	cache := newMSC4500StateCache(srv, deployment)
	seeded := cache.seed(
		serverRoom.CurrentState("m.room.member", alice.UserID),
		serverRoom.CurrentState("m.room.member", charlie),
	)
	must.Equal(t, seeded >= 1, true, "expected to already know at least one membership event")

	// --- Baseline ---------------------------------------------------------------
	// A message event does not change room state, so the accumulator's
	// post-event snapshot and federation's pre-event /state_ids snapshot are the
	// same set. That is what makes the rebuild below meaningful.
	msg1 := alice.SendEventSynced(t, roomID, b.Event{
		Type: "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "accumulator baseline",
		},
	})

	baseline := mustGetAccumulator(t, srv, deployment, roomID, msg1)
	baselineEntries, baselineFetched := cache.mustRebuildAccumulator(t, roomID, baseline)
	must.Equal(t, baselineFetched >= 1, true, "expected to lazily fetch at least one state event")

	// --- A rejected state event leaves the accumulator alone --------------------
	// Charlie has no power to set m.room.name, so hs1 must reject this event and
	// apply no state change at all.
	emptyStateKey := ""
	rejected := srv.MustCreateEvent(t, serverRoom, federation.Event{
		Sender:   charlie,
		Type:     "m.room.name",
		StateKey: &emptyStateKey,
		Content: map[string]interface{}{
			"name": "rejected by auth rules",
		},
	})
	mustSendTransaction(t, srv, deployment, []json.RawMessage{rejected.JSON()})

	msg2 := alice.SendEventSynced(t, roomID, b.Event{
		Type: "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "after the rejected state event",
		},
	})

	afterReject := mustGetAccumulator(t, srv, deployment, roomID, msg2)
	must.Equal(t, afterReject.latticeB64, baseline.latticeB64, "rejected state event changed the lattice")
	must.Equal(t, afterReject.digestB64, baseline.digestB64, "rejected state event changed the digest")
	must.Equal(t, afterReject.nStateEvents, baseline.nStateEvents, "rejected state event changed n_state_events")

	rejectEntries, rejectFetched := cache.mustRebuildAccumulator(t, roomID, afterReject)
	// The unchanged lattice only shows the observable result; confirm the cause
	// by checking the rejected event never became part of the room's state.
	rejectIDs := msc4500SortedEventIDs(rejectEntries)
	must.Equal(t, slices.Contains(rejectIDs, rejected.EventID()), false, "rejected state event is present in the state set")
	must.Equal(t, rejectFetched, 0, "state set did not change, so nothing should have been fetched")
	must.Equal(t,
		strings.Join(rejectIDs, ","),
		strings.Join(msc4500SortedEventIDs(baselineEntries), ","),
		"rejected state event changed the state set",
	)

	// --- An accepted state event replaces exactly one element -------------------
	// Alice's displayname update rewrites her m.room.member event: same tuple
	// position, new event ID, so n_state_events is unchanged and the lattice
	// must move by exactly Remove(old) + Insert(new).
	res := alice.MustDo(t, "PUT", []string{"_matrix", "client", "v3", "rooms", roomID, "state", "m.room.member", alice.UserID},
		client.WithJSONBody(t, map[string]interface{}{
			"membership":  "join",
			"displayname": "Accumulator Rewrite",
		}))
	newMemberEventID := must.ParseJSON(t, res.Body).Get("event_id").Str
	must.NotEqual(t, newMemberEventID, "", "displayname update returned no event ID")
	alice.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, newMemberEventID))

	oldMemberEventID := msc4500MemberEventID(baselineEntries, alice.UserID)
	must.NotEqual(t, oldMemberEventID, "", "baseline state set has no member event for alice")
	must.NotEqual(t, newMemberEventID, oldMemberEventID, "displayname update did not mint a new member event")

	msg3 := alice.SendEventSynced(t, roomID, b.Event{
		Type: "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "after the displayname update",
		},
	})

	afterReplace := mustGetAccumulator(t, srv, deployment, roomID, msg3)
	must.Equal(t, afterReplace.nStateEvents, baseline.nStateEvents, "a state replacement must not change n_state_events")

	expected := lthash.FromEntries(baselineEntries)
	expected.Remove("m.room.member", alice.UserID, oldMemberEventID)
	expected.Insert("m.room.member", alice.UserID, newMemberEventID)
	expectedLattice := expected.Bytes()
	must.Equal(t,
		afterReplace.latticeB64,
		base64.RawURLEncoding.EncodeToString(expectedLattice[:]),
		"accumulator did not move by exactly Remove(old) + Insert(new)",
	)
	expectedDigest := expected.Checksum()
	must.Equal(t,
		afterReplace.digestB64,
		base64.RawURLEncoding.EncodeToString(expectedDigest[:]),
		"digest does not match the expected single-element replacement",
	)

	replaceEntries, replaceFetched := cache.mustRebuildAccumulator(t, roomID, afterReplace)
	// Exact on purpose: the cache already held every other event, so only the
	// replacement member event can be missing.
	must.Equal(t, replaceFetched, 1, "expected to fetch exactly the replacement member event")
	must.Equal(t, msc4500MemberEventID(replaceEntries, alice.UserID), newMemberEventID, "rebuilt state set still holds the old member event")
	must.Equal(t,
		strings.Join(msc4500SortedEventIDs(replaceEntries), ","),
		strings.Join(msc4500ReplacedEventIDs(baselineEntries, oldMemberEventID, newMemberEventID), ","),
		"state set was not replaced by exactly one event",
	)
}

func testMSC4500StateHashMatch(t *testing.T) {
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
	joinEvent := serverRoom.CurrentState("m.room.member", charlie)
	must.NotEqual(t, joinEvent, nil, "expected charlie join event in remote room state")

	event := srv.MustCreateEvent(t, serverRoom, federation.Event{
		Sender: charlie,
		Type:   "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "Matching state hash event",
		},
	})

	// The message event does not change room state, so the post-event digest is
	// the same as the one after charlie's join event, which hs1 already knows.
	digestHex := mustGetStateAccumulatorDigest(t, srv, deployment, roomID, joinEvent.EventID())

	pdus := []json.RawMessage{event.JSON()}
	txnJSON := map[string]interface{}{
		"origin":           srv.ServerName(),
		"origin_server_ts": time.Now().UnixNano() / 1000000,
		"pdus":             pdus,
		"tk.nutra.msc4500.state_hashes": map[string]interface{}{
			event.EventID(): map[string]interface{}{
				"algorithm": msc4500Algorithm,
				"after":     digestHex,
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

	// Verify the response does not contain state_hash_mismatch for the event
	parsedRes := gjson.ParseBytes(resBody)
	mismatchObj := gjson.Result{}
	parsedRes.Get("pdus").ForEach(func(key, value gjson.Result) bool {
		if key.Str == event.EventID() {
			mismatchObj = value.Get("state_hash_mismatch")
			return false
		}
		return true
	})
	must.Equal(t, mismatchObj.Exists(), false, "state_hash_mismatch should not be present in response")
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
				"algorithm": msc4500Algorithm,
				"after":     "ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8",
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
	must.Equal(t, mismatchObj.Get("algorithm").Str, msc4500Algorithm, "mismatch algorithm wrong")
	expectedDigest := mustGetStateAccumulatorDigest(t, srv, deployment, roomID, badEvent.EventID())
	must.Equal(t, mismatchObj.Get("digest").Str, expectedDigest, "mismatch digest wrong")
}

func mustGetStateAccumulatorDigest(
	t *testing.T,
	srv *federation.Server,
	deployment complement.Deployment,
	roomID string,
	eventID string,
) string {
	t.Helper()

	reqURI := fmt.Sprintf("/_matrix/federation/unstable/tk.nutra.msc4500/state_accumulator/%s?event_id=%s", roomID, eventID)
	req := fclient.NewFederationRequest("GET", srv.ServerName(), deployment.GetFullyQualifiedHomeserverName(t, "hs1"), reqURI)

	fedRes, err := srv.DoFederationRequest(context.Background(), t, deployment, req)
	must.NotError(t, "do federation request", err)
	defer fedRes.Body.Close()

	fedBody := must.ParseJSON(t, fedRes.Body)
	digestB64 := fedBody.Get("digest").Str
	must.NotEqual(t, digestB64, "", "Digest is empty")
	return digestB64
}

// msc4500Accumulator is one observation of the MSC4500 state_accumulator
// endpoint at a single DAG point.
type msc4500Accumulator struct {
	eventID      string
	algorithm    string
	latticeB64   string
	digestB64    string
	nStateEvents uint64
}

// mustGetAccumulator reads the accumulator at eventID and checks the parts that
// need no rebuild: the profile identifier, the lattice width, and that the
// digest really is the BLAKE3-256 collapse of the lattice that was served.
func mustGetAccumulator(
	t *testing.T,
	srv *federation.Server,
	deployment complement.Deployment,
	roomID string,
	eventID string,
) msc4500Accumulator {
	t.Helper()

	reqURI := fmt.Sprintf("/_matrix/federation/unstable/tk.nutra.msc4500/state_accumulator/%s?event_id=%s", roomID, eventID)
	req := fclient.NewFederationRequest("GET", srv.ServerName(), deployment.GetFullyQualifiedHomeserverName(t, "hs1"), reqURI)

	fedRes, err := srv.DoFederationRequest(context.Background(), t, deployment, req)
	must.NotError(t, "do state_accumulator request", err)
	defer fedRes.Body.Close()

	fedBody := must.ParseJSON(t, fedRes.Body)

	must.MatchGJSON(t, fedBody, match.JSONKeyEqual("event_id", eventID))
	must.MatchGJSON(t, fedBody, match.JSONKeyEqual("algorithm", msc4500Algorithm))

	latticeB64 := fedBody.Get("lattice").Str
	digestB64 := fedBody.Get("digest").Str
	must.NotEqual(t, latticeB64, "", "Lattice is empty")
	must.Equal(t, len(digestB64), 43, "Digest is not 43 base64url characters")

	latticeBytes, err := base64.RawURLEncoding.DecodeString(latticeB64)
	must.NotError(t, "base64 decode lattice", err)
	must.Equal(t, len(latticeBytes), lthash.ByteSize, "Lattice is not 2048 bytes")

	// Deliberately independent of gomatrixcrypto: this checks the collapse on
	// its own before the rebuild below checks the expansion.
	hash := blake3.Sum256(latticeBytes)
	must.Equal(t, digestB64, base64.RawURLEncoding.EncodeToString(hash[:]), "Digest does not match BLAKE3-256 of lattice")

	return msc4500Accumulator{
		eventID:      eventID,
		algorithm:    fedBody.Get("algorithm").Str,
		latticeB64:   latticeB64,
		digestB64:    digestB64,
		nStateEvents: fedBody.Get("n_state_events").Uint(),
	}
}

// msc4500StateCache stands in for a homeserver's local event store. State event
// IDs come from federation /state_ids, and only IDs the cache does not already
// hold are fetched over federation /event.
type msc4500StateCache struct {
	srv        *federation.Server
	deployment complement.Deployment
	known      map[string]lthash.Entry
}

func newMSC4500StateCache(srv *federation.Server, deployment complement.Deployment) *msc4500StateCache {
	return &msc4500StateCache{
		srv:        srv,
		deployment: deployment,
		known:      make(map[string]lthash.Entry),
	}
}

// seed records events the test already knows without asking hs1 for them.
// Nil PDUs are skipped so optional lookups can be passed straight through.
func (c *msc4500StateCache) seed(pdus ...gomatrixserverlib.PDU) int {
	seeded := 0
	for _, pdu := range pdus {
		if pdu == nil {
			continue
		}
		stateKey := pdu.StateKey()
		if stateKey == nil {
			continue
		}
		c.known[pdu.EventID()] = lthash.Entry{
			EventType: pdu.Type(),
			StateKey:  *stateKey,
			EventID:   pdu.EventID(),
		}
		seeded++
	}
	return seeded
}

// entriesAt returns the authoritative state event ID set at eventID, fetching
// only the IDs the cache does not hold, and reports how many were fetched.
func (c *msc4500StateCache) entriesAt(t *testing.T, roomID, eventID string) ([]lthash.Entry, int) {
	t.Helper()

	reqURI := fmt.Sprintf("/_matrix/federation/v1/state_ids/%s?event_id=%s", roomID, eventID)
	req := fclient.NewFederationRequest("GET", c.srv.ServerName(), c.deployment.GetFullyQualifiedHomeserverName(t, "hs1"), reqURI)
	res, err := c.srv.DoFederationRequest(context.Background(), t, c.deployment, req)
	must.NotError(t, "do state_ids request", err)
	defer res.Body.Close()

	ids := must.ParseJSON(t, res.Body).Get("pdu_ids").Array()
	must.NotEqual(t, len(ids), 0, "state_ids returned an empty state set")

	fetched := 0
	entries := make([]lthash.Entry, 0, len(ids))
	for _, id := range ids {
		if entry, ok := c.known[id.Str]; ok {
			entries = append(entries, entry)
			continue
		}
		entry := c.mustFetchEvent(t, id.Str)
		c.known[id.Str] = entry
		fetched++
		entries = append(entries, entry)
	}
	return entries, fetched
}

// mustFetchEvent pulls a single event over federation and reduces it to the
// (type, state_key, event_id) tuple the accumulator is built from.
func (c *msc4500StateCache) mustFetchEvent(t *testing.T, eventID string) lthash.Entry {
	t.Helper()

	reqURI := fmt.Sprintf("/_matrix/federation/v1/event/%s", eventID)
	req := fclient.NewFederationRequest("GET", c.srv.ServerName(), c.deployment.GetFullyQualifiedHomeserverName(t, "hs1"), reqURI)
	res, err := c.srv.DoFederationRequest(context.Background(), t, c.deployment, req)
	must.NotError(t, "do event request", err)
	defer res.Body.Close()

	body := must.ParseJSON(t, res.Body)
	// The federation response normally carries the PDU in a one-element `pdus`
	// array; tolerate a bare object too.
	pdu := body.Get("pdus.0")
	if !pdu.IsObject() {
		pdu = body.Get("pdus")
	}
	must.Equal(t, pdu.IsObject(), true, "event response carried no PDU for "+eventID)
	must.NotEqual(t, pdu.Get("type").Str, "", "event has no type: "+eventID)
	// /state_ids should only ever return state events, so a missing state_key
	// means the response is malformed or the set contains something unexpected.
	must.Equal(t, pdu.Get("state_key").Exists(), true, "event is not a state event (no state_key): "+eventID)

	return lthash.Entry{
		EventType: pdu.Get("type").Str,
		StateKey:  pdu.Get("state_key").Str,
		EventID:   eventID,
	}
}

// mustRebuildAccumulator rebuilds the lattice from the state set at the
// accumulator's event ID and asserts it matches, byte for byte, everything the
// endpoint served. It returns the entries used and how many had to be fetched.
func (c *msc4500StateCache) mustRebuildAccumulator(t *testing.T, roomID string, acc msc4500Accumulator) ([]lthash.Entry, int) {
	t.Helper()

	entries, fetched := c.entriesAt(t, roomID, acc.eventID)
	rebuilt := lthash.FromEntries(entries)

	rebuiltLattice := rebuilt.Bytes()
	must.Equal(t,
		base64.RawURLEncoding.EncodeToString(rebuiltLattice[:]),
		acc.latticeB64,
		"lattice rebuilt from /state_ids does not match the served lattice",
	)

	rebuiltDigest := rebuilt.Checksum()
	must.Equal(t,
		base64.RawURLEncoding.EncodeToString(rebuiltDigest[:]),
		acc.digestB64,
		"digest of rebuilt lattice does not match the served digest",
	)

	must.Equal(t, uint64(len(entries)), acc.nStateEvents, "n_state_events does not match the /state_ids set")

	return entries, fetched
}

// mustSendTransaction PUTs the given PDUs to hs1 over federation.
func mustSendTransaction(t *testing.T, srv *federation.Server, deployment complement.Deployment, pdus []json.RawMessage) {
	t.Helper()

	txnBody, err := json.Marshal(map[string]interface{}{
		"origin":           srv.ServerName(),
		"origin_server_ts": time.Now().UnixNano() / 1000000,
		"pdus":             pdus,
	})
	must.NotError(t, "json marshal txn", err)

	txnID := fmt.Sprintf("txn-%d", time.Now().UnixNano())
	reqURI := fmt.Sprintf("/_matrix/federation/v1/send/%s", txnID)
	req := fclient.NewFederationRequest("PUT", srv.ServerName(), deployment.GetFullyQualifiedHomeserverName(t, "hs1"), reqURI)
	must.NotError(t, "set content", req.SetContent(json.RawMessage(txnBody)))

	res, err := srv.DoFederationRequest(context.Background(), t, deployment, req)
	must.NotError(t, "do federation request", err)
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	must.NotError(t, "read send response", err)
	t.Logf("send transaction response: %d %s", res.StatusCode, string(body))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		t.Fatalf("send transaction failed with HTTP %d: %s", res.StatusCode, body)
	}
}

// msc4500SortedEventIDs returns the event IDs of entries in a stable order so
// two state sets can be compared as strings.
func msc4500SortedEventIDs(entries []lthash.Entry) []string {
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		ids = append(ids, entry.EventID)
	}
	slices.Sort(ids)
	return ids
}

// msc4500MemberEventID finds the member event ID for userID in entries.
func msc4500MemberEventID(entries []lthash.Entry, userID string) string {
	for _, entry := range entries {
		if entry.EventType == "m.room.member" && entry.StateKey == userID {
			return entry.EventID
		}
	}
	return ""
}

// msc4500ReplacedEventIDs is entries' ID set with one member event swapped for
// another, used to assert a replacement changed the set by exactly -1/+1.
func msc4500ReplacedEventIDs(entries []lthash.Entry, oldEventID, newEventID string) []string {
	replaced := make([]lthash.Entry, 0, len(entries))
	for _, entry := range entries {
		if entry.EventID == oldEventID {
			entry.EventID = newEventID
		}
		replaced = append(replaced, entry)
	}
	return msc4500SortedEventIDs(replaced)
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
	expectedDigest = mustGetStateAccumulatorDigest(t, srv, deployment, roomID, joinEvent.EventID())

	// Trigger an outbound transaction by having alice send a message and syncing
	// until it is present (which forces the homeserver to forward it to charlie).
	alice.SendEventSynced(t, roomID, b.Event{
		Type: "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "hello",
		},
	})

	found.Waitf(t, 30*time.Second, "timed out waiting for outbound state_hashes on /send")

	mu.Lock()
	defer mu.Unlock()
	must.Equal(t, observedDigest, true, "did not observe a valid outbound state_hashes entry")
	must.Equal(t, observedAfter, expectedDigest, "outbound state_hashes digest wrong")
}

// checkMSC4500Outbound inspects a raw /send transaction body and finishes the
// waiter if it carries a valid state_hashes extension.
//
// It parses the body twice: once into a gomatrixserverlib.Transaction to confirm
// the payload is a well-formed /send transaction (optional - ignored on failure),
// and once into a generic map so the custom state_hashes extension (which the
// strongly-typed Transaction drops) can be inspected.
func checkMSC4500Outbound(raw json.RawMessage, found *helpers.Waiter, mu *sync.Mutex, observedAfter *string, observedDigest *bool) {
	// Optional: verify the body also unmarshals as a standard Transaction. This
	// is not required for the state_hashes check, so a parse error is ignored.
	var txn gomatrixserverlib.Transaction
	_ = json.Unmarshal(raw, &txn)

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
		if algo == msc4500Algorithm && len(after) == 43 {
			mu.Lock()
			*observedAfter = after
			*observedDigest = true
			mu.Unlock()
			found.Finish()
			return
		}
	}
}
