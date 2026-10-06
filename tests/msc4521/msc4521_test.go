package msc4521

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"testing"

	"github.com/Wombat-Foundation/gomatrixcrypto/reconcile"

	"github.com/matrix-org/complement/must"
)

// TestMSC4521SetReconciliation groups the library-level checks that back the
// adaptive set reconciliation proposal. The suite deliberately exercises the
// gomatrixcrypto/reconcile primitives directly so the protocol logic can be
// verified without a homeserver; the federation-facing endpoint test is
// scaffolded separately until its wire shape is settled.
func TestMSC4521SetReconciliation(t *testing.T) {
	t.Run("IdenticalSets", testIdenticalSets)
	t.Run("OneSidedChanges", testOneSidedChanges)
	t.Run("SymmetricDifference", testSymmetricDifference)
	t.Run("EstimateDelta", testEstimateDelta)
	t.Run("ResidualVerification", testResidualVerification)
	t.Run("AdaptiveBuckets", testAdaptiveBuckets)
	t.Run("BucketEscalation", testBucketEscalation)
	t.Run("MalformedInputs", testMalformedInputs)
	t.Run("EventIDBinding", testEventIDBinding)
	t.Run("ValidateBucketRequests", testValidateBucketRequests)
	t.Run("FederationEndpoint", testFederationEndpoint)
}

// element derives a deterministic element hash from a label.
func element(label string) reconcile.ElementHash {
	return reconcile.FromDigest32(sha256.Sum256([]byte(label)))
}

// kernelWith builds a resident kernel containing the given labels.
func kernelWith(t *testing.T, labels ...string) reconcile.ResidentKernel {
	t.Helper()
	kernel := reconcile.NewResidentKernel()
	for _, label := range labels {
		if err := kernel.Insert(element(label)); err != nil {
			t.Fatalf("Insert(%q): %v", label, err)
		}
	}
	return kernel
}

// sketchOf builds an unbucketed sketch over the given labels.
func sketchOf(t *testing.T, labels []string, capacity int) *reconcile.SyndromeSketch {
	t.Helper()
	sketch, err := reconcile.NewSyndromeSketch(capacity)
	if err != nil {
		t.Fatalf("NewSyndromeSketch(%d): %v", capacity, err)
	}
	for _, label := range labels {
		if err := sketch.Toggle(element(label).H64); err != nil {
			t.Fatalf("Toggle(%q): %v", label, err)
		}
	}
	return sketch
}

// bucketPrefix returns the top `depth` bits of an element hash's short
// identifier, matching the bucket antichain used by ValidateBucketRequests.
func bucketPrefix(h64 uint64, depth uint8) uint32 {
	if depth == 0 {
		return 0
	}
	return uint32(h64 >> (64 - depth))
}

// bucketedDifferenceSketches builds the XOR of the local and remote bucket
// sketches for each request, which is what a requester decodes.
func bucketedDifferenceSketches(t *testing.T, local, remote []string, requests []reconcile.BucketRequest) []byte {
	t.Helper()
	var encoded []byte
	for _, request := range requests {
		sketch, err := reconcile.NewSyndromeSketch(request.Capacity)
		if err != nil {
			t.Fatalf("NewSyndromeSketch(%d): %v", request.Capacity, err)
		}
		for _, labels := range [][]string{local, remote} {
			for _, label := range labels {
				hash := element(label)
				if bucketPrefix(hash.H64, request.Depth) != request.Prefix {
					continue
				}
				if err := sketch.Toggle(hash.H64); err != nil {
					t.Fatalf("Toggle(%q): %v", label, err)
				}
			}
		}
		raw, err := base64.RawURLEncoding.DecodeString(sketch.Encode())
		if err != nil {
			t.Fatalf("DecodeString(sketch): %v", err)
		}
		encoded = append(encoded, raw...)
	}
	return encoded
}

// equalU64Set reports whether two slices contain the same values in any order.
func equalU64Set(got, want []uint64) bool {
	if len(got) != len(want) {
		return false
	}
	left := slices.Clone(got)
	right := slices.Clone(want)
	slices.Sort(left)
	slices.Sort(right)
	return slices.Equal(left, right)
}

// testIdenticalSets verifies that peers holding the same population agree on
// both the accumulator digest and the exact event count.
func testIdenticalSets(t *testing.T) {
	local := kernelWith(t, "a", "b", "c")
	remote := kernelWith(t, "a", "b", "c")

	must.Equal(t, local.Accumulator().Count, remote.Accumulator().Count, "identical sets must agree on count")
	must.Equal(t, local.Accumulator().Digest, remote.Accumulator().Digest, "identical sets must agree on digest")
	must.Equal(t, local.Accumulator().Residual(remote.Accumulator()), [16]byte{}, "identical sets must have a zero residual")
}

// testOneSidedChanges verifies the accumulator tracks one-sided insertions and
// removals, including count underflow protection.
func testOneSidedChanges(t *testing.T) {
	local := kernelWith(t, "a", "b", "c")
	remote := kernelWith(t, "a", "b")

	must.Equal(t, local.Accumulator().Count, uint64(3), "local count")
	must.Equal(t, remote.Accumulator().Count, uint64(2), "remote count")
	must.NotEqual(t, local.Accumulator().Residual(remote.Accumulator()), [16]byte{}, "one-sided addition must perturb the residual")

	removed := element("c")
	if err := local.Remove(removed); err != nil {
		t.Fatalf("Remove(c): %v", err)
	}
	must.Equal(t, local.Accumulator().Digest, remote.Accumulator().Digest, "removing the extra element must resynchronise the digest")
	must.Equal(t, local.Accumulator().Residual(remote.Accumulator()), [16]byte{}, "resynchronised peers must have a zero residual")

	for _, label := range []string{"a", "b"} {
		if err := local.Remove(element(label)); err != nil {
			t.Fatalf("Remove(%q): %v", label, err)
		}
	}
	if err := local.Remove(element("a")); !errors.Is(err, reconcile.ErrCountUnderflow) {
		t.Fatalf("Remove on an empty accumulator = %v, want ErrCountUnderflow", err)
	}
}

// testSymmetricDifference verifies that the XOR of two sketches decodes exactly
// the symmetric difference, and that underprovisioned capacity fails closed.
func testSymmetricDifference(t *testing.T) {
	const capacity = 8

	local := sketchOf(t, []string{"a", "b", "c", "d"}, capacity)
	remote := sketchOf(t, []string{"a", "b", "c", "e"}, capacity)
	difference, err := local.Subtract(remote)
	must.NotError(t, "Subtract", err)

	roots, err := difference.DecodeElements(2)
	must.NotError(t, "DecodeElements(2)", err)
	want := []uint64{element("d").H64, element("e").H64}
	if !equalU64Set(roots, want) {
		t.Fatalf("decoded roots = %#x, want %#x", roots, want)
	}

	// A three-element difference cannot be extracted from a two-element sketch.
	local = sketchOf(t, []string{"a", "b", "c", "d"}, capacity)
	remote = sketchOf(t, []string{"a", "b", "c", "e", "f"}, capacity)
	difference, err = local.Subtract(remote)
	must.NotError(t, "Subtract", err)
	if _, err := difference.DecodeElements(2); !errors.Is(err, reconcile.ErrDecodeFailure) {
		t.Fatalf("DecodeElements(2) with a 3-element difference = %v, want ErrDecodeFailure", err)
	}

	if _, err := difference.DecodeElements(0); !errors.Is(err, reconcile.ErrInvalidSketchCapacity) {
		t.Fatalf("DecodeElements(0) = %v, want ErrInvalidSketchCapacity", err)
	}
	if _, err := difference.DecodeElements(capacity + 1); !errors.Is(err, reconcile.ErrInvalidSketchCapacity) {
		t.Fatalf("DecodeElements(over capacity) = %v, want ErrInvalidSketchCapacity", err)
	}
}

// testEstimateDelta verifies the strata estimator reports a non-zero delta for
// divergent populations.
func testEstimateDelta(t *testing.T) {
	local := kernelWith(t, "a", "b", "c", "d", "e")
	remote := kernelWith(t, "a", "b", "c", "d", "f")

	estimate, ok, err := reconcile.EstimateDelta(local.Strata(), remote.Strata())
	must.NotError(t, "EstimateDelta", err)
	must.Equal(t, ok, true, "EstimateDelta should produce an estimate")
	if estimate < 2 {
		t.Fatalf("EstimateDelta = %d, want >= 2 for a 2-element symmetric difference", estimate)
	}
}

// testResidualVerification verifies that decoded roots reproduce the accumulator
// residual both globally and per-side.
func testResidualVerification(t *testing.T) {
	local := kernelWith(t, "a", "b", "c", "d")
	remote := kernelWith(t, "a", "b", "c", "e")
	residual := local.Accumulator().Residual(remote.Accumulator())

	removed := element("d")
	added := element("e")

	must.Equal(t, reconcile.VerifyResidual(residual, []reconcile.ElementHash{removed, added}), true, "residual must match both roots")
	must.Equal(t, reconcile.VerifyResidual(residual, []reconcile.ElementHash{removed}), false, "residual must not match a single root")
	must.Equal(t, reconcile.VerifyGlobalResidual(residual, [][16]byte{removed.H128}, [][16]byte{added.H128}), true, "global residual must match split roots")
	must.Equal(t, reconcile.VerifyGlobalResidual(residual, [][16]byte{removed.H128}, nil), false, "global residual must reject missing roots")
}

// testAdaptiveBuckets runs the requester action selection, bucket sketch
// construction and batch transition end to end for a small difference.
func testAdaptiveBuckets(t *testing.T) {
	localLabels := []string{"a", "b", "c", "d", "e"}
	remoteLabels := []string{"a", "b", "c", "d", "f"}
	local := kernelWith(t, localLabels...)
	remote := kernelWith(t, remoteLabels...)

	client, err := reconcile.NewReconciliationClient(reconcile.MaxLocalSketchDecodeCapacity)
	must.NotError(t, "NewReconciliationClient", err)

	remoteDigest := reconcile.RemoteDigest{
		Digest:          remote.Accumulator().Digest,
		KnownEventCount: remote.Accumulator().Count,
		Strata:          *remote.Strata(),
		FrameMatches:    true,
	}

	action := client.SelectAction(&local, remoteDigest, 0)
	must.Equal(t, action.Type, reconcile.ActionBucketSketches, "a small delta should request bucket sketches")
	must.NotError(t, "ValidateBucketRequests", reconcile.ValidateBucketRequests(action.Requests))

	encoded := bucketedDifferenceSketches(t, localLabels, remoteLabels, action.Requests)
	batch, err := reconcile.DecodeBucketSketches(encoded, action.Requests)
	must.NotError(t, "DecodeBucketSketches", err)
	must.Equal(t, len(batch.FailedBuckets), 0, "a small delta should decode without failed buckets")

	transition := client.TransitionBucketBatch(batch, action.Requests, nil, nil, 1, reconcile.MaxBucketedSketchCapacity)
	must.Equal(t, transition.Type, reconcile.ActionResolveRoots, "a clean batch should resolve roots")

	want := []uint64{element("e").H64, element("f").H64}
	if !equalU64Set(transition.Roots, want) {
		t.Fatalf("resolved roots = %#x, want %#x", transition.Roots, want)
	}
}

// testBucketEscalation verifies an over-subscribed bucket fails to decode and is
// retried with a larger capacity rather than aborting the exchange.
func testBucketEscalation(t *testing.T) {
	client, err := reconcile.NewReconciliationClient(reconcile.MaxLocalSketchDecodeCapacity)
	must.NotError(t, "NewReconciliationClient", err)

	const capacity = 2
	sketch, err := reconcile.NewSyndromeSketch(capacity)
	must.NotError(t, "NewSyndromeSketch", err)
	// A residual whose leading syndrome is zero with a non-zero later syndrome
	// cannot be produced by any set within the requested capacity, so Berlekamp-
	// Massey must reject it deterministically.
	sketch.Coordinates = []uint64{0, 5}
	encoded, err := base64.RawURLEncoding.DecodeString(sketch.Encode())
	must.NotError(t, "DecodeString", err)

	requests := []reconcile.BucketRequest{{Depth: 0, Prefix: 0, Capacity: capacity}}
	batch, err := reconcile.DecodeBucketSketches(encoded, requests)
	must.NotError(t, "DecodeBucketSketches", err)
	must.Equal(t, len(batch.FailedBuckets), 1, "an over-subscribed bucket must fail")
	must.Equal(t, len(batch.SuccessfulBuckets), 0, "an over-subscribed bucket must not succeed")

	transition := client.TransitionBucketBatch(batch, requests, nil, nil, 1, reconcile.MaxBucketedSketchCapacity)
	must.Equal(t, transition.Type, reconcile.ActionBucketSketches, "a failed bucket should escalate to a retry")
	if len(transition.Requests) == 0 {
		t.Fatal("escalation produced no follow-up requests")
	}
	if transition.Requests[0].Capacity <= capacity {
		t.Fatalf("escalated capacity = %d, want > %d", transition.Requests[0].Capacity, capacity)
	}
}

// testMalformedInputs verifies decoding fails closed on malformed or
// structurally invalid inputs.
func testMalformedInputs(t *testing.T) {
	if _, err := reconcile.NewSyndromeSketch(0); !errors.Is(err, reconcile.ErrInvalidSketchCapacity) {
		t.Fatalf("NewSyndromeSketch(0) = %v, want ErrInvalidSketchCapacity", err)
	}
	if _, err := reconcile.NewSyndromeSketch(reconcile.MaxSketchCapacity + 1); !errors.Is(err, reconcile.ErrInvalidSketchCapacity) {
		t.Fatalf("NewSyndromeSketch(over capacity) = %v, want ErrInvalidSketchCapacity", err)
	}

	sketch, err := reconcile.NewSyndromeSketch(4)
	must.NotError(t, "NewSyndromeSketch(4)", err)
	if err := sketch.Toggle(0); !errors.Is(err, reconcile.ErrZeroShortIdentifier) {
		t.Fatalf("Toggle(0) = %v, want ErrZeroShortIdentifier", err)
	}

	if _, err := reconcile.DecodeSyndromeSketch(4, "AAAA"); !errors.Is(err, reconcile.ErrInvalidSketchLength) {
		t.Fatalf("DecodeSyndromeSketch(short) = %v, want ErrInvalidSketchLength", err)
	}

	decoded, err := reconcile.DecodeSyndromeSketch(4, sketch.Encode())
	must.NotError(t, "DecodeSyndromeSketch(round trip)", err)
	if !slices.Equal(decoded.Coordinates, sketch.Coordinates) {
		t.Fatalf("round-tripped coordinates = %#x, want %#x", decoded.Coordinates, sketch.Coordinates)
	}

	if _, err := reconcile.DecodeDigest("AAAA"); !errors.Is(err, reconcile.ErrInvalidDigestLength) {
		t.Fatalf("DecodeDigest(short) = %v, want ErrInvalidDigestLength", err)
	}

	if _, err := reconcile.DecodeBucketSketches([]byte{1, 2, 3}, []reconcile.BucketRequest{{Depth: 0, Prefix: 0, Capacity: 4}}); !errors.Is(err, reconcile.ErrInvalidSketchLength) {
		t.Fatalf("DecodeBucketSketches(short) = %v, want ErrInvalidSketchLength", err)
	}
}

// testEventIDBinding verifies the V3/V4+ event-ID to element-hash bindings and
// their rejection of unsupported or malformed identifiers.
func testEventIDBinding(t *testing.T) {
	digest := make([]byte, 32)
	digest[0] = 1
	v3 := "$" + base64.RawStdEncoding.EncodeToString(digest)
	v4 := "$" + base64.RawURLEncoding.EncodeToString(digest)

	v3Hash, err := reconcile.FromMatrixEventID(v3, reconcile.V3)
	must.NotError(t, "FromMatrixEventID(V3)", err)
	v4Hash, err := reconcile.FromMatrixEventID(v4, reconcile.V4Plus)
	must.NotError(t, "FromMatrixEventID(V4Plus)", err)
	must.Equal(t, v3Hash, v4Hash, "V3 and V4+ must derive the same element hash")

	viaAlias, err := reconcile.DecodeDigest32(v4, reconcile.V4Plus)
	must.NotError(t, "DecodeDigest32", err)
	must.Equal(t, v3Hash, reconcile.FromDigest32(viaAlias), "DecodeDigest32 must match FromMatrixEventID")

	if _, err := reconcile.FromMatrixEventID("not-an-event", reconcile.V3); !errors.Is(err, reconcile.ErrInvalidEventID) {
		t.Fatalf("FromMatrixEventID(bad sigil) = %v, want ErrInvalidEventID", err)
	}
	if _, err := reconcile.FromMatrixEventID("$!!!", reconcile.V3); !errors.Is(err, reconcile.ErrInvalidBase64) {
		t.Fatalf("FromMatrixEventID(bad base64) = %v, want ErrInvalidBase64", err)
	}
	if _, err := reconcile.FromMatrixEventID(v3, reconcile.Legacy); !errors.Is(err, reconcile.ErrUnsupportedRoomVersion) {
		t.Fatalf("FromMatrixEventID(Legacy) = %v, want ErrUnsupportedRoomVersion", err)
	}
}

// testValidateBucketRequests verifies the bucket request validator enforces the
// antichain ordering, per-bucket caps and aggregate capacity limit.
func testValidateBucketRequests(t *testing.T) {
	must.NotError(t, "valid antichain", reconcile.ValidateBucketRequests([]reconcile.BucketRequest{
		{Depth: 1, Prefix: 0, Capacity: 4},
		{Depth: 1, Prefix: 1, Capacity: 4},
	}))

	if err := reconcile.ValidateBucketRequests([]reconcile.BucketRequest{{Depth: 0, Prefix: 0, Capacity: reconcile.MaxBucketSketchCapacity + 1}}); !errors.Is(err, reconcile.ErrInvalidSketchCapacity) {
		t.Fatalf("ValidateBucketRequests(over capacity) = %v, want ErrInvalidSketchCapacity", err)
	}
	if err := reconcile.ValidateBucketRequests([]reconcile.BucketRequest{{Depth: 33, Prefix: 0, Capacity: 4}}); !errors.Is(err, reconcile.ErrInvalidBucketIndex) {
		t.Fatalf("ValidateBucketRequests(depth > 32) = %v, want ErrInvalidBucketIndex", err)
	}
	if err := reconcile.ValidateBucketRequests([]reconcile.BucketRequest{{Depth: 2, Prefix: 4, Capacity: 4}}); !errors.Is(err, reconcile.ErrInvalidBucketIndex) {
		t.Fatalf("ValidateBucketRequests(prefix out of range) = %v, want ErrInvalidBucketIndex", err)
	}
	if err := reconcile.ValidateBucketRequests([]reconcile.BucketRequest{
		{Depth: 1, Prefix: 0, Capacity: 4},
		{Depth: 2, Prefix: 1, Capacity: 4},
	}); !errors.Is(err, reconcile.ErrInvalidBucketIndex) {
		t.Fatalf("ValidateBucketRequests(overlapping antichain) = %v, want ErrInvalidBucketIndex", err)
	}

	many := make([]reconcile.BucketRequest, 0, 129)
	for prefix := 0; prefix < 129; prefix++ {
		many = append(many, reconcile.BucketRequest{Depth: 8, Prefix: uint32(prefix), Capacity: reconcile.MaxBucketSketchCapacity})
	}
	if err := reconcile.ValidateBucketRequests(many); !errors.Is(err, reconcile.ErrInvalidSketchCapacity) {
		t.Fatalf("ValidateBucketRequests(aggregate over capacity) = %v, want ErrInvalidSketchCapacity", err)
	}
}

// testFederationEndpoint is the placeholder for the federated exchange once the
// proposed endpoint shape is finalised and a homeserver implements it.
func testFederationEndpoint(t *testing.T) {
	t.Skip("MSC-4521 federation endpoint shape is not finalised; scaffold awaiting homeserver support")
}
