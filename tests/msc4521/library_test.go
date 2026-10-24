//go:build !dendrite_blacklist && !venator_blacklist

package msc4521

import (
	"slices"
	"testing"
)

// testPrimitives drives each adaptive set reconciliation scenario against a real
// homeserver through the library's requester client over the /room_digest and
// /room_diff federation endpoints. The same scenarios run against the library
// alone in tests/msc4521/library, which needs no homeserver.
func testPrimitives(t *testing.T) {
	hs := newHomeserverSide(t)

	t.Run("Plumbing", func(t *testing.T) {
		t.Run("Vectors", func(t *testing.T) {
			hs.wireFormat(t)
		})
		t.Run("Buckets", func(t *testing.T) {
			t.Run("AdaptiveBuckets", func(t *testing.T) {
				hs.adaptiveBuckets(t)
			})
			t.Run("MixedBucketBatch", func(t *testing.T) {
				hs.mixedBucketBatch(t)
			})
			t.Run("BucketEscalation", func(t *testing.T) {
				hs.bucketEscalation(t)
			})
			t.Run("BucketSplit", func(t *testing.T) {
				hs.bucketSplit(t)
			})
			t.Run("ValidateBucketRequests", func(t *testing.T) {
				hs.validateBucketRequests(t)
			})
		})
		t.Run("Residual", func(t *testing.T) {
			t.Run("ResidualVerification", func(t *testing.T) {
				hs.residualVerification(t)
			})
		})
		t.Run("Other", func(t *testing.T) {
			t.Run("MalformedInputs", func(t *testing.T) {
				hs.malformedInputs(t)
			})
			t.Run("EventIDBinding", func(t *testing.T) {
				hs.eventIDBinding(t)
			})
		})
	})
	t.Run("Porcelain", func(t *testing.T) {
		t.Run("IdenticalSets", func(t *testing.T) {
			hs.identicalSets(t)
		})
		t.Run("OneSidedChanges", func(t *testing.T) {
			hs.oneSidedChanges(t)
		})
		t.Run("SymmetricDifference", func(t *testing.T) {
			hs.symmetricDifference(t)
		})
		t.Run("EstimateDelta", func(t *testing.T) {
			hs.estimateDelta(t)
		})
	})
}

// bucketPrefix returns the top `depth` bits of an element hash's short
// identifier, matching the bucket antichain used by ValidateBucketRequests.
func bucketPrefix(h64 uint64, depth uint8) uint32 {
	if depth == 0 {
		return 0
	}
	return uint32(h64 >> (64 - depth))
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
