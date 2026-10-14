package runtime

import (
	"testing"
)

type mockTest struct {
	name       string
	skipped    bool
	skipReason string
}

func (m *mockTest) Name() string {
	return m.name
}

func (m *mockTest) Skipf(format string, args ...interface{}) {
	m.skipped = true
}

func (m *mockTest) Helper() {}

func (m *mockTest) Logf(format string, args ...interface{}) {}

func (m *mockTest) Error(args ...interface{}) {}

func (m *mockTest) Errorf(format string, args ...interface{}) {}

func (m *mockTest) Fatalf(format string, args ...interface{}) {}

func (m *mockTest) Failed() bool {
	return false
}

func TestSkipIfInheritanceAndExemptions(t *testing.T) {
	// Backup original state
	origHomeserver := Homeserver
	defer func() {
		Homeserver = origHomeserver
	}()

	tests := []struct {
		hs              string
		testName        string
		skipOn          []string
		expectedSkipped bool
	}{
		// Basic exact match skips
		{Conduit, "TestSomeFunc", []string{Conduit}, true},
		{Conduit, "TestSomeFunc", []string{Conduwuit}, false},

		// Inheritance skips
		{Conduwuit, "TestSomeFunc", []string{Conduit}, true},      // Conduwuit inherits Conduit
		{Continuwuity, "TestSomeFunc", []string{Conduit}, false},  // Conduit is not an ancestor of Continuwuity
		{Continuwuity, "TestSomeFunc", []string{Conduwuit}, true}, // Continuwuity inherits Conduwuit
		{Tuwunel, "TestSomeFunc", []string{Conduit}, false},       // nor of Tuwunel

		// Congruent inherits nothing
		{Congruent, "TestSomeFunc", []string{Conduit}, false},
		{Congruent, "TestSomeFunc", []string{Conduwuit}, false},
		{Congruent, "TestSomeFunc", []string{Continuwuity}, false},
		{Congruent, "TestSomeFunc", []string{Congruent}, true},

		// Exemptions
		{Tuwunel, "TestPartialStateJoin", []string{Conduit}, false},           // Tuwunel exempt on TestPartialStateJoin
		{Tuwunel, "TestPartialStateJoin/Subtest", []string{Conduwuit}, false}, // Tuwunel exempt on subtest
		{Continuwuity, "TestPartialStateJoin", []string{Conduwuit}, false},    // Continuwuity exempt on TestPartialStateJoin
		{Conduwuit, "TestTxnIdempotency", []string{Conduit}, false},
		{Continuwuity, "TestTxnIdWithRefreshToken", []string{Conduit}, false},
	}

	for _, tc := range tests {
		Homeserver = tc.hs
		mt := &mockTest{name: tc.testName}
		SkipIf(mt, tc.skipOn...)
		if mt.skipped != tc.expectedSkipped {
			t.Errorf("For HS=%s, Test=%s, SkipOn=%v: expected skipped=%v, got %v", tc.hs, tc.testName, tc.skipOn, tc.expectedSkipped, mt.skipped)
		}
	}
}

func TestSkipUnless(t *testing.T) {
	origHomeserver := Homeserver
	defer func() { Homeserver = origHomeserver }()

	cases := []struct {
		hs       string
		allowed  []string
		wantSkip bool
	}{
		{Congruent, []string{Conduwuit}, false},
		{Congruent, []string{Synapse, Conduwuit}, false},
		{Congruent, []string{Synapse}, true},
		{Continuwuity, []string{Conduwuit}, false},
		{Tuwunel, []string{Conduwuit}, false},
	}
	for _, tc := range cases {
		Homeserver = tc.hs
		mt := &mockTest{name: "TestSomeFunc"}
		SkipUnless(mt, tc.allowed...)
		if mt.skipped != tc.wantSkip {
			t.Errorf("HS=%s allowed=%v: expected skipped=%v, got %v", tc.hs, tc.allowed, tc.wantSkip, mt.skipped)
		}
	}
}
