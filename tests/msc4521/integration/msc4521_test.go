package integration

import (
	"os"
	"testing"
)

// TestMSC4521 groups every MSC4521 check under one parent, so a single test is
// selected with a slash path (`TestMSC4521/SetReconciliation/Porcelain`)
// instead of a name prefix. Without a Complement runner (COMPLEMENT_BASE_IMAGE
// unset) only the library half of SetReconciliation runs; everything else needs
// a homeserver.
func TestMSC4521(t *testing.T) {
	t.Run("SetReconciliation", testSetReconciliation)
	if os.Getenv("COMPLEMENT_BASE_IMAGE") == "" {
		t.Log("no Complement runner: only the library half of SetReconciliation ran")
		return
	}
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
