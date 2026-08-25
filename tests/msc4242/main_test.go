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
//	TestMSC4242StateDAGs/FederationSimple
//	TestMSC4242StateDAGs/GetMissingEventsInbound/GME00
//	TestMSC4242StateDAGs/SendJoinSJ01Outbound
//	...
func TestMSC4242StateDAGs(t *testing.T) {
	t.Run("Graph", testGraph)
	t.Run("FederationSimple", testMSC4242FederationSimple)
	t.Run("SendingFaultyEventDoesntBrickRoom", testMSC4242SendingFaultyEventDoesntBrickRoom)
	t.Run("BanEvasion", testMSC4242BanEvasion)
	t.Run("SendJoinMalformedResponseSJ00", testMSC4242SendJoinMalformedResponseSJ00)
	t.Run("SendJoinSJ01Outbound", testMSC4242SendJoinSJ01Outbound)
	t.Run("SendJoinSJ01Inbound", testMSC4242SendJoinSJ01Inbound)
	t.Run("SendJoinSJ02InvalidStateDAG", testMSC4242SendJoinSJ02InvalidStateDAG)
	// SJ03 tests are commented out in msc4242_send_join_test.go (see /* */ block),
	// so their helper funcs don't compile; kept here as a reference to re-enable.
	// t.Run("SendJoinFasterSJ03Inbound", testMSC4242SendJoinFasterSJ03Inbound)
	// t.Run("SendJoinFasterSJ03Outbound", testMSC4242SendJoinFasterSJ03Outbound)
	t.Run("OnSendJoinSJ04", testMSC4242OnSendJoinSJ04)
	t.Run("GetMissingEventsInbound", testMSC4242GetMissingEventsInbound)
	t.Run("GetMissingEventsOutbound", testMSC4242GetMissingEventsOutbound)
	t.Run("GetMissingEventsBadInputs", testMSC4242GetMissingEventsBadInputs)
	t.Run("GetMissingEventsFaultyEvents", testMSC4242GetMissingEventsFaultyEvents)
	t.Run("GetMissingEventsFillingStateDAGFails", testMSC4242GetMissingEventsFillingStateDAGFails)
	t.Run("STATE00TemporaryNetworkErrorIsOkay", testMSC4242STATE00TemporaryNetworkErrorIsOkay)
	t.Run("STATE01DeOutlieredStateIsCorrect", testMSC4242STATE01DeOutlieredStateIsCorrect)
	t.Run("STATE02OldStateChangesBetweenEvents", testMSC4242STATE02OldStateChangesBetweenEvents)
	t.Run("STATE04MismatchedPrevStateEventsVsPrevEvents", testMSC4242STATE04MismatchedPrevStateEventsVsPrevEvents)
}
