package integration

import "testing"

// TestMSC4521 groups MSC4521 checks by the behavior they exercise. Every test
// here needs the Complement runner, except the primitive library checks.
func TestMSC4521(t *testing.T) {
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
