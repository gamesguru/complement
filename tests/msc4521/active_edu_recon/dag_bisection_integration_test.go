//go:build !dendrite_blacklist && !venator_blacklist

// Venator does not yet implement federation.

package activeedurecon

import "testing"

// TestMSC4521DAGBisectionIntegration is the hs1/hs2 test for the room_bisect
// federation endpoint described in ../DAG_BISECTION_API.md.
//
// Blocked: no homeserver implements room_bisect, and Complement has no
// supported hook to give one peer a partial DAG. The digest/strata/diff flow is
// already covered against real homeservers by TestMSC4521ActiveRoomReconciliation.
//
// Revisit when a target homeserver serves room_bisect. The test should then
// deploy two homeservers, join hs2 to a room on hs1, make the views diverge
// (event/state omission and conflict, total and partial views), POST to
// room_bisect, and compare the reported earliest divergence against
// ../bisect.First, which is the oracle.
func TestMSC4521DAGBisectionIntegration(t *testing.T) {
	t.Skip("blocked: no homeserver implements room_bisect and there is no partial-DAG test hook; see ../DAG_BISECTION_API.md")
}
