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
		hs             string
		testName       string
		skipOn         []string
		expectedSkipped bool
	}{
		// Basic exact match skips
		{Conduit, "TestSomeFunc", []string{Conduit}, true},
		{Conduit, "TestSomeFunc", []string{Conduwuit}, false},

		// Inheritance skips
		{Conduwuit, "TestSomeFunc", []string{Conduit}, true}, // Conduwuit inherits Conduit
		{Continuwuity, "TestSomeFunc", []string{Conduit}, true}, // Continuwuity inherits Conduit
		{Continuwuity, "TestSomeFunc", []string{Conduwuit}, true}, // Continuwuity inherits Conduwuit
		{Tuwunel, "TestSomeFunc", []string{Conduit}, true}, // Tuwunel inherits Conduit

		// Exemptions
		{Tuwunel, "TestPartialStateJoin", []string{Conduit}, false}, // Tuwunel exempt on TestPartialStateJoin
		{Tuwunel, "TestPartialStateJoin/Subtest", []string{Conduwuit}, false}, // Tuwunel exempt on subtest
		{Continuwuity, "TestPartialStateJoin", []string{Conduwuit}, true}, // Continuwuity NOT exempt on TestPartialStateJoin
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
