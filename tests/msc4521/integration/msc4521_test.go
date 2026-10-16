package integration

import "testing"

// TestMSC4521 groups every MSC4521 check under one parent, so a single test is
// selected with a slash path (`TestMSC4521/SetReconciliation/Porcelain`)
// instead of a name prefix. Every test here needs the Complement runner.
func TestMSC4521(t *testing.T) {
	t.Run("WireBisect", testWireBisect) // TEMPORARY
	t.Run("SetReconciliation", testSetReconciliation)
	t.Run("ActiveRoomReconciliation", testActiveRoomReconciliation)
	t.Run("FabricatedIDs", testFabricatedIDs)
	t.Run("PartlyFakeClaimIsSampled", testPartlyFakeClaimIsSampled)
	t.Run("ValidChainingIsAccepted", testValidChainingIsAccepted)
	t.Run("RejectedEventNotRefetched", testRejectedEventNotRefetched)
	t.Run("NonMembersAndACLBlocked", testNonMembersAndACLBlocked)
	t.Run("NonAdvertisingPeerFallsBack", testNonAdvertisingPeerFallsBack)
	t.Run("PausedHomeserverCatchesUp", testPausedHomeserverCatchesUp)
	t.Run("PartitionHealUsesReconciliation", testPartitionHealUsesReconciliation)
	t.Run("BulkReconciliation", testBulkReconciliation)
}
