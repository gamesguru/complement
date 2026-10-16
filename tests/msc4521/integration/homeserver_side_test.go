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
	"slices"
	"strconv"
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

// homeserverSide is the real-homeserver half of testSetReconciliation.
// A remote federation server holds the requester's side of a room's event set,
// hs1 holds the other, and the library's own reconciliation client recovers the
// difference over /room_digest and /room_diff.
type homeserverSide struct {
	deployment complement.Deployment
	alice      *client.CSAPI
	srv        *federation.Server
	charlie    string
}

// scenarioRoom is one room whose two sides diverge by exactly the events
// recorded in hsOnly and reqOnly. Every scenario gets its own, so no scenario
// depends on another's state.
type scenarioRoom struct {
	id      string
	room    *federation.ServerRoom
	hsOnly  []string
	reqOnly []string
}

func newHomeserverSide(t *testing.T) *homeserverSide {
	t.Helper()
	deployment := complement.Deploy(t, 1)
	t.Cleanup(func() { deployment.Destroy(t) })

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	// The remote server ignores transactions, so events sent by hs1 after it
	// joined stay unknown to it: that is how the two sides come to differ.
	srv := federation.NewServer(t, deployment,
		federation.HandleKeyRequests(),
		federation.HandleMakeSendJoinRequests(),
		federation.HandleTransactionRequests(nil, nil),
	)
	t.Cleanup(srv.Listen())
	return &homeserverSide{deployment, alice, srv, srv.UserID("charlie")}
}

func (h *homeserverSide) newRoom(t *testing.T) *scenarioRoom {
	t.Helper()
	roomID := h.alice.MustCreateRoom(t, map[string]interface{}{"preset": "public_chat"})
	room := h.srv.MustJoinRoom(t, h.deployment, h.deployment.GetFullyQualifiedHomeserverName(t, "hs1"), roomID, h.charlie)
	return &scenarioRoom{id: roomID, room: room}
}

// addHomeserverEvents makes hs1 hold n events the requester does not.
func (h *homeserverSide) addHomeserverEvents(t *testing.T, r *scenarioRoom, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		r.hsOnly = append(r.hsOnly, h.alice.SendEventSynced(t, r.id, b.Event{
			Type:    "m.room.message",
			Content: map[string]interface{}{"msgtype": "m.text", "body": "homeserver-only MSC4521 event"},
		}))
	}
}

// addRequesterEvents makes the requester hold n events hs1 does not.
func (h *homeserverSide) addRequesterEvents(t *testing.T, r *scenarioRoom, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		event := h.srv.MustCreateEvent(t, r.room, federation.Event{
			Sender:  h.charlie,
			Type:    "m.room.message",
			Content: map[string]interface{}{"body": "remote-only MSC4521 event"},
		})
		r.room.AddEvent(event)
		r.reqOnly = append(r.reqOnly, event.EventID())
	}
}

// eventIDs is the requester's set: every event in the mock room's current
// state and its timeline, once each.
func eventIDs(room *federation.ServerRoom) []string {
	var ids []string
	seen := map[string]bool{}
	add := func(id string) {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	room.StateMutex.RLock()
	for _, event := range room.State {
		add(event.EventID())
	}
	room.StateMutex.RUnlock()
	room.TimelineMutex.RLock()
	for _, event := range room.Timeline {
		add(event.EventID())
	}
	room.TimelineMutex.RUnlock()
	return ids
}

// h64s is the requester's set as short identifiers.
func (r *scenarioRoom) h64s(t *testing.T) []uint64 {
	t.Helper()
	var out []uint64
	for _, id := range eventIDs(r.room) {
		out = append(out, reconcileHash(t, id))
	}
	return out
}

func (r *scenarioRoom) kernel(t *testing.T) reconcile.ResidentKernel {
	return kernelOf(t, r.room)
}

// wantRoots is the symmetric difference the exchange must recover.
func (r *scenarioRoom) wantRoots(t *testing.T) []uint64 {
	t.Helper()
	var out []uint64
	for _, id := range slices.Concat(r.hsOnly, r.reqOnly) {
		out = append(out, reconcileHash(t, id))
	}
	return out
}

// exchange is the record of one full reconciliation conversation.
type exchange struct {
	statuses []string
	requests [][]reconcile.BucketRequest
	roots    []uint64
}

// reconcile drives the library's requester client against hs1 until it
// resolves the difference. initial, when set, replaces the first request so a
// scenario can start with a deliberately undersized bucket.
func (h *homeserverSide) reconcile(t *testing.T, r *scenarioRoom, initial []reconcile.BucketRequest) exchange {
	t.Helper()
	local := r.kernel(t)
	rc, err := reconcile.NewReconciliationClient(reconcile.MaxLocalSketchDecodeCapacity)
	must.NotError(t, "NewReconciliationClient", err)

	action := rc.SelectAction(&local, h.remoteDigest(t, r), 0)
	if initial != nil {
		action = reconcile.ClientAction{Type: reconcile.ActionBucketSketches, Requests: initial}
	}

	var ex exchange
	for round := 0; round < 12; round++ {
		switch action.Type {
		case reconcile.ActionSynchronized:
			return ex
		case reconcile.ActionResolveRoots:
			ex.roots = action.Roots
			return ex
		case reconcile.ActionBucketSketches:
			ex.requests = append(ex.requests, action.Requests)
			response := h.diff(t, r, local, r.h64s(t), action.Requests)
			ex.statuses = append(ex.statuses, response.Get("sketch_status").Str)
			batch := bucketBatch(t, response, action.Requests)
			action = rc.TransitionBucketBatch(batch, action.Requests, action.AccumulatedRoots, nil, round+1, reconcile.MaxBucketedSketchCapacity)
		default:
			t.Fatalf("unexpected client action %v", action.Type)
		}
	}
	t.Fatalf("reconciliation did not converge: statuses %v", ex.statuses)
	return ex
}

// bucketBatch turns a room_diff response into the library's batch type: a
// capacity_exceeded response fails every requested bucket, a decoded one is
// split into per-bucket roots by prefix.
func bucketBatch(t *testing.T, response gjson.Result, requests []reconcile.BucketRequest) reconcile.BucketDecodeBatch {
	t.Helper()
	var batch reconcile.BucketDecodeBatch
	switch status := response.Get("sketch_status").Str; status {
	case "capacity_exceeded":
		for _, request := range requests {
			batch.FailedBuckets = append(batch.FailedBuckets, reconcile.FailedBucket{Depth: request.Depth, Prefix: request.Prefix})
		}
	case "decoded":
		roots := rootsOf(t, response)
		for _, request := range requests {
			success := reconcile.BucketDecodeSuccess{Depth: request.Depth, Prefix: request.Prefix}
			for _, root := range roots {
				if bucketPrefix(root, request.Depth) == request.Prefix {
					success.Roots = append(success.Roots, root)
				}
			}
			batch.SuccessfulBuckets = append(batch.SuccessfulBuckets, success)
		}
	default:
		t.Fatalf("unexpected sketch_status %q in %s", status, response.Raw)
	}
	return batch
}

// rootsOf is every short identifier a decoded room_diff response reports:
// the homeserver-only events by ID, and the requester-only ones directly.
func rootsOf(t *testing.T, response gjson.Result) []uint64 {
	t.Helper()
	var roots []uint64
	for _, id := range stringsOf(response.Get("missing_event_ids")) {
		roots = append(roots, reconcileHash(t, id))
	}
	for _, short := range stringsOf(response.Get("requester_only_short_ids")) {
		raw, err := base64.RawURLEncoding.DecodeString(short)
		must.NotError(t, "decode short identifier", err)
		roots = append(roots, binary.BigEndian.Uint64(raw))
	}
	return roots
}

// remoteDigest reads hs1's digest and strata for the room and decodes them with
// the library's types, which exercises the wire encoding end to end.
func (h *homeserverSide) remoteDigest(t *testing.T, r *scenarioRoom) reconcile.RemoteDigest {
	t.Helper()
	body, status := getRoomDigest(t, h.srv, h.deployment, r.id, "/strata")
	must.Equal(t, status, 200, "room digest strata status")
	digest := gjson.ParseBytes(body)

	remote := reconcile.RemoteDigest{
		KnownEventCount: digest.Get("known_event_count").Uint(),
		FrameMatches:    true,
	}
	var err error
	remote.Digest, err = reconcile.DecodeDigest(digest.Get("digest").Str)
	must.NotError(t, "decode digest", err)

	strata := digest.Get("strata").Array()
	must.Equal(t, len(strata), reconcile.StrataCount, "strata count")
	for i, stratum := range strata {
		raw, err := base64.RawURLEncoding.DecodeString(stratum.Str)
		must.NotError(t, "decode stratum", err)
		must.Equal(t, len(raw), reconcile.StratumCapacity*8, "stratum size")
		for j := range remote.Strata[i] {
			remote.Strata[i][j] = binary.LittleEndian.Uint64(raw[j*8:])
		}
	}
	return remote
}

type frame struct {
	id      string
	anchors []string
}

func (h *homeserverSide) loadFrame(t *testing.T, r *scenarioRoom) frame {
	t.Helper()
	body, status := getRoomDigest(t, h.srv, h.deployment, r.id, "/strata")
	must.Equal(t, status, 200, "room digest strata status")
	digest := gjson.ParseBytes(body)
	return frame{id: digest.Get("frame_id").Str, anchors: stringsOf(digest.Get("frame_event_ids"))}
}

// diffBody builds a sketch-mode room_diff request for the given buckets over
// the given requester set.
func diffBody(t *testing.T, f frame, local reconcile.ResidentKernel, h64s []uint64, requests []reconcile.BucketRequest) map[string]interface{} {
	t.Helper()
	var wire []map[string]interface{}
	var sketches []string
	for _, request := range requests {
		// The library cannot build a sketch above the per-bucket maximum, so an
		// over-capacity request carries a maximum-size sketch and is rejected on
		// the request itself.
		sketch, err := reconcile.NewSyndromeSketch(min(request.Capacity, reconcile.MaxBucketSketchCapacity))
		must.NotError(t, "new bucket sketch", err)
		for _, h64 := range h64s {
			if bucketPrefix(h64, request.Depth) == request.Prefix {
				must.NotError(t, "toggle into bucket sketch", sketch.Toggle(h64))
			}
		}
		wire = append(wire, map[string]interface{}{"depth": request.Depth, "prefix": strconv.FormatUint(uint64(request.Prefix), 10), "capacity": request.Capacity})
		sketches = append(sketches, sketch.Encode())
	}
	return map[string]interface{}{
		"mode":                    "sketch",
		"frame_id":                f.id,
		"local_digest":            local.Accumulator().EncodeDigest(),
		"digest_type":             "algebraic_v1",
		"local_known_event_count": local.Accumulator().Count,
		"frame_event_ids":         f.anchors,
		"estimated_delta":         1,
		"requests":                wire,
		"local_sketches":          sketches,
		"limit":                   100,
	}
}

// diff posts a room_diff and requires it to be accepted.
func (h *homeserverSide) diff(t *testing.T, r *scenarioRoom, local reconcile.ResidentKernel, h64s []uint64, requests []reconcile.BucketRequest) gjson.Result {
	t.Helper()
	body, status := doRoomDiff(t, h.srv, h.deployment, r.id, diffBody(t, h.loadFrame(t, r), local, h64s, requests))
	must.Equal(t, status, 200, "room diff status: "+string(body))
	return gjson.ParseBytes(body)
}

func doRoomDiff(t *testing.T, srv *federation.Server, deployment complement.Deployment, roomID string, body map[string]interface{}) ([]byte, int) {
	t.Helper()
	requestBody, err := json.Marshal(body)
	must.NotError(t, "encode room_diff request", err)
	path := msc4521Prefix + "room_diff/" + url.PathEscape(roomID)
	req := fclient.NewFederationRequest("POST", srv.ServerName(), deployment.GetFullyQualifiedHomeserverName(t, "hs1"), path)
	must.NotError(t, "set room_diff request", req.SetContent(json.RawMessage(requestBody)))
	res, err := srv.DoFederationRequest(context.Background(), t, deployment, req)
	must.NotError(t, "POST "+path, err)
	defer res.Body.Close()
	out, err := io.ReadAll(res.Body)
	must.NotError(t, "read room_diff response", err)
	if res.StatusCode != 200 {
		t.Logf("room_diff -> %d\nrequest:  %s\nresponse: %s", res.StatusCode, requestBody, out)
	}
	return out, res.StatusCode
}

var rootBucket = []reconcile.BucketRequest{{Depth: 0, Prefix: 0, Capacity: 2}}

// wireFormat: hs1's digest, count and strata for a room both sides agree on
// decode with the library to exactly what the library computes locally.
func (h *homeserverSide) wireFormat(t *testing.T) {
	t.Helper()
	r := h.newRoom(t)
	local := r.kernel(t)
	remote := h.remoteDigest(t, r)
	must.Equal(t, remote.KnownEventCount, local.Accumulator().Count, "event count")
	must.Equal(t, remote.Digest, local.Accumulator().Digest, "digest")
	must.Equal(t, remote.Strata == *local.Strata(), true, "strata")
}

// identicalSets: with nothing to reconcile both sides agree and hs1 reports no
// difference.
func (h *homeserverSide) identicalSets(t *testing.T) {
	t.Helper()
	r := h.newRoom(t)
	response := h.diff(t, r, r.kernel(t), r.h64s(t), rootBucket)
	must.Equal(t, response.Get("sketch_status").Str, "decoded", "sketch status")
	must.Equal(t, len(rootsOf(t, response)), 0, "identical sets have no difference")
}

// oneSidedChanges: an event only hs1 has is reported by ID, and nothing is
// reported as requester-only.
func (h *homeserverSide) oneSidedChanges(t *testing.T) {
	t.Helper()
	r := h.newRoom(t)
	h.addHomeserverEvents(t, r, 1)
	response := h.diff(t, r, r.kernel(t), r.h64s(t), rootBucket)
	must.Equal(t, slices.Contains(stringsOf(response.Get("missing_event_ids")), r.hsOnly[0]), true,
		"homeserver event is reported missing from the requester")
	must.Equal(t, len(response.Get("requester_only_short_ids").Array()), 0, "no requester-only events")
}

// symmetricDifference: each side has an event the other lacks, and both are
// recovered.
func (h *homeserverSide) symmetricDifference(t *testing.T) {
	t.Helper()
	r := h.newRoom(t)
	h.addHomeserverEvents(t, r, 1)
	h.addRequesterEvents(t, r, 1)
	response := h.diff(t, r, r.kernel(t), r.h64s(t), []reconcile.BucketRequest{{Depth: 0, Prefix: 0, Capacity: 4}})
	must.Equal(t, equalU64Set(rootsOf(t, response), r.wantRoots(t)), true, "both differences are recovered")
}

// adaptiveBuckets: the library client selects its own requests for a small
// difference and resolves it against hs1 in one decoded round.
func (h *homeserverSide) adaptiveBuckets(t *testing.T) {
	t.Helper()
	r := h.newRoom(t)
	h.addHomeserverEvents(t, r, 1)
	h.addRequesterEvents(t, r, 1)
	ex := h.reconcile(t, r, nil)
	must.Equal(t, slices.Equal(ex.statuses, []string{"decoded"}), true, "a small delta decodes in one round")
	must.Equal(t, equalU64Set(ex.roots, r.wantRoots(t)), true, "resolved roots")
}

// mixedBucketBatch: several buckets in one request are decoded independently
// and their roots, grouped by prefix, add up to the whole difference.
func (h *homeserverSide) mixedBucketBatch(t *testing.T) {
	t.Helper()
	r := h.newRoom(t)
	h.addHomeserverEvents(t, r, 1)
	h.addRequesterEvents(t, r, 1)
	requests := []reconcile.BucketRequest{{Depth: 1, Prefix: 0, Capacity: 2}, {Depth: 1, Prefix: 1, Capacity: 2}}
	response := h.diff(t, r, r.kernel(t), r.h64s(t), requests)
	must.Equal(t, response.Get("sketch_status").Str, "decoded", "sketch status")
	batch := bucketBatch(t, response, requests)
	var roots []uint64
	for _, bucket := range batch.SuccessfulBuckets {
		roots = append(roots, bucket.Roots...)
	}
	must.Equal(t, equalU64Set(roots, r.wantRoots(t)), true, "buckets together recover the difference")
}

// bucketEscalation: a bucket smaller than the difference is reported as
// capacity_exceeded and the client retries it with a larger capacity.
func (h *homeserverSide) bucketEscalation(t *testing.T) {
	t.Helper()
	r := h.newRoom(t)
	h.addRequesterEvents(t, r, 3)
	ex := h.reconcile(t, r, rootBucket)
	must.Equal(t, ex.statuses[0], "capacity_exceeded", "an undersized bucket is not decoded")
	must.Equal(t, ex.statuses[len(ex.statuses)-1], "decoded", "the retry decodes")
	must.Equal(t, ex.requests[1][0].Capacity > rootBucket[0].Capacity, true, "the retry asks for a larger capacity")
	must.Equal(t, equalU64Set(ex.roots, r.wantRoots(t)), true, "resolved roots")
}

// bucketSplit: a difference beyond the per-bucket maximum splits the bucket
// into deeper children until each decodes.
func (h *homeserverSide) bucketSplit(t *testing.T) {
	t.Helper()
	r := h.newRoom(t)
	h.addRequesterEvents(t, r, reconcile.MaxBucketSketchCapacity+8)
	full := []reconcile.BucketRequest{{Depth: 0, Prefix: 0, Capacity: reconcile.MaxBucketSketchCapacity}}
	ex := h.reconcile(t, r, full)
	split := false
	for _, requests := range ex.requests {
		for _, request := range requests {
			split = split || request.Depth > 0
		}
	}
	must.Equal(t, split, true, "an over-full bucket is split into deeper buckets")
	must.Equal(t, equalU64Set(ex.roots, r.wantRoots(t)), true, "resolved roots")
}

// validateBucketRequests: hs1 accepts a well-formed antichain and rejects
// malformed bucket sets as a client error.
func (h *homeserverSide) validateBucketRequests(t *testing.T) {
	t.Helper()
	r := h.newRoom(t)
	local, h64s, f := r.kernel(t), r.h64s(t), h.loadFrame(t, r)

	ok := []reconcile.BucketRequest{{Depth: 1, Prefix: 0, Capacity: 4}, {Depth: 1, Prefix: 1, Capacity: 4}}
	_, status := doRoomDiff(t, h.srv, h.deployment, r.id, diffBody(t, f, local, h64s, ok))
	must.Equal(t, status, 200, "valid antichain")

	for name, requests := range map[string][]reconcile.BucketRequest{
		"OverCapacity":     {{Depth: 0, Prefix: 0, Capacity: reconcile.MaxBucketSketchCapacity + 1}},
		"DepthTooLarge":    {{Depth: 33, Prefix: 0, Capacity: 4}},
		"PrefixOutOfRange": {{Depth: 2, Prefix: 4, Capacity: 4}},
		"Overlapping":      {{Depth: 1, Prefix: 0, Capacity: 4}, {Depth: 2, Prefix: 1, Capacity: 4}},
		"ReversedOrder":    {{Depth: 1, Prefix: 1, Capacity: 4}, {Depth: 1, Prefix: 0, Capacity: 4}},
	} {
		t.Run("Homeserver/"+name, func(t *testing.T) {
			_, status := doRoomDiff(t, h.srv, h.deployment, r.id, diffBody(t, f, local, h64s, requests))
			must.Equal(t, status >= 400 && status < 500 && status != 404, true,
				"malformed bucket requests must be a client error, not success, 404 or 5xx")
		})
	}
}

// residualVerification: hs1's expected_requester_side_accumulator is the digest
// of exactly what the requester holds alone, so it is zero when the requester
// has nothing extra and equals the requester-only elements otherwise.
func (h *homeserverSide) residualVerification(t *testing.T) {
	t.Helper()
	r := h.newRoom(t)
	h.addHomeserverEvents(t, r, 1)
	h.addRequesterEvents(t, r, 1)
	response := h.diff(t, r, r.kernel(t), r.h64s(t), []reconcile.BucketRequest{{Depth: 0, Prefix: 0, Capacity: 4}})

	got, err := reconcile.DecodeDigest(response.Get("expected_requester_side_accumulator").Str)
	must.NotError(t, "decode expected accumulator", err)
	var want [16]byte
	for _, id := range r.reqOnly {
		hash, err := reconcile.FromMatrixEventID(id, reconcile.V4Plus)
		must.NotError(t, "hash requester-only event", err)
		for i := range want {
			want[i] ^= hash.H128[i]
		}
	}
	must.Equal(t, got, want, "expected requester-side accumulator")
}

// malformedInputs: a malformed room_diff is the requester's fault, so it must
// be a client error other than "route not found".
func (h *homeserverSide) malformedInputs(t *testing.T) {
	t.Helper()
	r := h.newRoom(t)
	valid := diffBody(t, h.loadFrame(t, r), r.kernel(t), r.h64s(t), rootBucket)
	// The unmodified request must be accepted, otherwise every 4xx below could
	// just be the route being missing.
	_, status := doRoomDiff(t, h.srv, h.deployment, r.id, valid)
	must.Equal(t, status, 200, "unmodified room_diff request")

	for name, mutate := range map[string]func(map[string]interface{}){
		"UnknownDigestType": func(b map[string]interface{}) { b["digest_type"] = "nope" },
		"UndecodableSketch": func(b map[string]interface{}) { b["local_sketches"] = []string{"!!not-base64!!"} },
		"ZeroCapacity": func(b map[string]interface{}) {
			b["requests"] = []map[string]interface{}{{"depth": 0, "prefix": "0", "capacity": 0}}
		},
		"UnknownFrame":         func(b map[string]interface{}) { b["frame_id"] = "not-a-frame" },
		"MalformedFrameAnchor": func(b map[string]interface{}) { b["frame_event_ids"] = []string{"not-an-event-id"} },
		"SketchCountMismatch":  func(b map[string]interface{}) { b["local_sketches"] = []string{} },
	} {
		t.Run("Homeserver/"+name, func(t *testing.T) {
			body := map[string]interface{}{}
			for k, v := range valid {
				body[k] = v
			}
			mutate(body)
			_, status := doRoomDiff(t, h.srv, h.deployment, r.id, body)
			must.Equal(t, status >= 400 && status < 500 && status != 404, true,
				"malformed room_diff must be a client error, not success, 404 or 5xx")
		})
	}
}

// eventIDBinding: short identifiers are bound to event IDs. A real hs1 event
// is reported by its ID, and a short identifier that belongs to no event is
// reported as requester-only rather than being turned into an event ID.
func (h *homeserverSide) eventIDBinding(t *testing.T) {
	t.Helper()
	r := h.newRoom(t)
	h.addHomeserverEvents(t, r, 1)

	fake := reconcileHash(t, fakeEventID(1))
	fakeHash, err := reconcile.FromMatrixEventID(fakeEventID(1), reconcile.V4Plus)
	must.NotError(t, "hash fabricated event ID", err)
	local := r.kernel(t)
	must.NotError(t, "insert fabricated event ID", local.Insert(fakeHash))

	response := h.diff(t, r, local, append(r.h64s(t), fake), []reconcile.BucketRequest{{Depth: 0, Prefix: 0, Capacity: 4}})
	must.Equal(t, slices.Contains(stringsOf(response.Get("missing_event_ids")), r.hsOnly[0]), true, "real event reported by ID")
	must.Equal(t, slices.Contains(stringsOf(response.Get("requester_only_short_ids")), shortID(fake)), true,
		"unbound short identifier reported as requester-only")
	must.Equal(t, len(response.Get("missing_event_ids").Array()), 1, "no event ID is invented for the unbound identifier")
}

// estimateDelta: the library's strata estimate computed from hs1's own strata
// covers a known two-element symmetric difference.
func (h *homeserverSide) estimateDelta(t *testing.T) {
	t.Helper()
	r := h.newRoom(t)
	h.addHomeserverEvents(t, r, 1)
	h.addRequesterEvents(t, r, 1)
	local := r.kernel(t)
	remote := h.remoteDigest(t, r)
	estimate, ok, err := reconcile.EstimateDelta(local.Strata(), &remote.Strata)
	must.NotError(t, "EstimateDelta", err)
	must.Equal(t, ok, true, "EstimateDelta should produce an estimate")
	must.Equal(t, estimate >= 2, true, "estimate covers the 2-element symmetric difference")
}

// kernelOf builds the requester's view of the set from its own room.
func kernelOf(t *testing.T, room *federation.ServerRoom) reconcile.ResidentKernel {
	t.Helper()
	kernel := reconcile.NewResidentKernel()
	for _, id := range eventIDs(room) {
		hash, err := reconcile.FromMatrixEventID(id, reconcile.V4Plus)
		must.NotError(t, "hash event ID", err)
		must.NotError(t, "insert event ID", kernel.Insert(hash))
	}
	return kernel
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
