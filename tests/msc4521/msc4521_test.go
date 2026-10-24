//go:build !dendrite_blacklist && !venator_blacklist

package msc4521

import (
	"testing"

	"github.com/matrix-org/complement"
)

// TestMSC4521 groups MSC4521 checks by the behavior they exercise. Every test
// here needs the Complement runner, except the primitive library checks.
func TestMSC4521(t *testing.T) {
	// Start every homeserver the suite will use at once. A dirty deployment is
	// otherwise grown lazily, so each test that needs another server waits for
	// its boot in turn.
	deployment := complement.Deploy(t, 4)
	t.Cleanup(func() { deployment.Destroy(t) })
	t.Run("Primitives", testPrimitives)
	t.Run("Convergence", func(t *testing.T) {
		t.Run("ActiveRoom", testActiveRoomReconciliation)
		t.Run("PausedHomeserverCatchesUp", testPausedHomeserverCatchesUp)
		t.Run("PartitionHeal", testPartitionHealUsesReconciliation)
		t.Run("Bulk", testBulkReconciliation)
	})
	t.Run("Adversarial", func(t *testing.T) {
		t.Run("FabricatedIDs", testFabricatedIDs)
		t.Run("PartlyFakeClaimIsSampled", testPartlyFakeClaimIsSampled)
		t.Run("ValidChainAccepted", testValidChainingIsAccepted)
		t.Run("RejectedEventNotRefetched", testRejectedEventNotRefetched)
	})
	t.Run("Authorization", func(t *testing.T) {
		t.Run("NonMembersAndACLBlocked", testNonMembersAndACLBlocked)
	})
	t.Run("Compatibility", func(t *testing.T) {
		t.Run("NonAdvertisingPeerFallsBack", testNonAdvertisingPeerFallsBack)
	})
}
