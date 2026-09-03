package tests

import (
	"testing"

	"github.com/matrix-org/complement"
)

func TestMain(m *testing.M) {
	complement.TestMain(m, "msc4242")
}

// TestMSC4242StateDAGs is the single top-level entry point for the entire
// MSC4242 (State DAGs) complement suite. Every State DAG test is registered
// here as a subtest so the whole feature's results live under one hierarchy:
//
//	TestMSC4242StateDAGs/Graph
//	TestMSC4242StateDAGs/Federation_Simple
//	TestMSC4242StateDAGs/GetMissingEvents:_inbound
//	TestMSC4242StateDAGs/SendJoin:_SJ01_outbound
//	TestMSC4242StateDAGs/STATE09:_Asymmetric_3-way_partition_eventual_consistency_and_rolling_heal
//	...
func TestMSC4242StateDAGs(t *testing.T) {
	t.Run("Graph", testGraph)
	t.Run("Federation Simple", testMSC4242FederationSimple)
	t.Run("Sending faulty event does not brick room", testMSC4242SendingFaultyEventDoesntBrickRoom)
	t.Run("Ban evasion", testMSC4242BanEvasion)
	t.Run("SendJoin: malformed response SJ00", testMSC4242SendJoinMalformedResponseSJ00)
	t.Run("SendJoin: SJ01 outbound", testMSC4242SendJoinSJ01Outbound)
	t.Run("SendJoin: SJ01 inbound", testMSC4242SendJoinSJ01Inbound)
	t.Run("SendJoin: SJ02 invalid state DAG", testMSC4242SendJoinSJ02InvalidStateDAG)
	// SJ03 tests are commented out in msc4242_send_join_test.go (see /* */ block),
	// so their helper funcs don't compile; kept here as a reference to re-enable.
	// t.Run("SendJoin: faster SJ03 inbound", testMSC4242SendJoinFasterSJ03Inbound)
	// t.Run("SendJoin: faster SJ03 outbound", testMSC4242SendJoinFasterSJ03Outbound)
	t.Run("On send join SJ04", testMSC4242OnSendJoinSJ04)
	t.Run("GetMissingEvents: inbound", testMSC4242GetMissingEventsInbound)
	t.Run("GetMissingEvents: outbound", testMSC4242GetMissingEventsOutbound)
	t.Run("GetMissingEvents: bad inputs", testMSC4242GetMissingEventsBadInputs)
	t.Run("GetMissingEvents: faulty events", testMSC4242GetMissingEventsFaultyEvents)
	t.Run("GetMissingEvents: filling state DAG fails", testMSC4242GetMissingEventsFillingStateDAGFails)
	t.Run("STATE00: Temporary network error is okay", testMSC4242STATE00TemporaryNetworkErrorIsOkay)
	t.Run("STATE01: De-outliered state is correct", testMSC4242STATE01DeOutlieredStateIsCorrect)
	t.Run("STATE02: Old state changes between events", testMSC4242STATE02OldStateChangesBetweenEvents)
	t.Run("STATE03: Concurrent losing state event", testMSC4242STATE03ConcurrentLosingStateEvent)
	t.Run("STATE04: Mismatched prev_state_events vs prev_events", testMSC4242STATE04MismatchedPrevStateEventsVsPrevEvents)
	t.Run("STATE05: Demoted moderator concurrent action", testMSC4242STATE05DemotedModeratorConcurrentAction)
	t.Run("STATE06: Concurrent ban and kick dominance", testMSC4242STATE06ConcurrentBanAndKickDominance)
	t.Run("STATE07: Phantom join rules lockdown", testMSC4242STATE07PhantomJoinRulesLockdown)
	t.Run("STATE08: Redaction of state event", testMSC4242STATE08RedactionOfStateEvent)
	t.Run("STATE09: Asymmetric 3-way partition eventual consistency and rolling heal", testMSC4242STATE09AsymmetricPartitionEventualConsistency)
	t.Run("DIVERGENCE00: Partitioned server accepts incomplete state DAG from buggy peer", testMSC4242DIVERGENCE00PartitionedServerAcceptsIncompleteStateDAG)
	t.Run("DIVERGENCE01: Differential rejection after partition with divergent state DAGs", testMSC4242DIVERGENCE01DifferentialRejectionAfterPartition)
	t.Run("DIVERGENCE02: Offline server accepts malicious fork, then cannot self-heal", testMSC4242DIVERGENCE02OfflineServerAcceptsMaliciousForkThenCannotSelfHeal)
}
