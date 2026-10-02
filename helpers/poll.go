package helpers

import (
	"time"

	"github.com/matrix-org/complement/ct"
)

// DefaultPollInterval is the interval used by polling helpers when the caller
// does not specify one. It is short enough that tests rarely wait meaningfully
// longer than the underlying condition takes, but long enough to avoid hammering
// the homeserver.
const DefaultPollInterval = 25 * time.Millisecond

// PollUntil blocks until cond returns true, polling at the given interval. If
// the timeout elapses first, the test fails. cond is re-invoked immediately on
// entry so a condition which already holds returns without sleeping at all.
//
// Prefer this over time.Sleep whenever a fixed delay is standing in for "wait
// until the server has done something": it is both faster when the server is
// quick and more reliable when it is slow.
func PollUntil(t ct.TestLike, timeout, interval time.Duration, cond func() bool) {
	t.Helper()
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			ct.Fatalf(t, "condition still not met after %f seconds.", timeout.Seconds())
		}
		time.Sleep(interval)
	}
}

// PollUntilf is PollUntil but fails with a caller-supplied message so failures
// name the specific condition that was being waited on.
func PollUntilf(t ct.TestLike, timeout, interval time.Duration, cond func() bool, errFormat string, args ...any) {
	t.Helper()
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			ct.Fatalf(t, errFormat+": timed out after %f seconds.", append(args, timeout.Seconds())...)
		}
		time.Sleep(interval)
	}
}

// WaitForNewMillis blocks until the wall-clock millisecond counter advances at
// least once from now. Tests which need distinct millisecond timestamps (or
// which need a sample to not share a millisecond with a subsequent request)
// should use this instead of sleeping a fixed duration: it guarantees the
// condition they actually need while usually returning in well under a
// millisecond.
func WaitForNewMillis(t ct.TestLike) {
	t.Helper()
	start := time.Now().UnixMilli()
	PollUntil(t, 5*time.Second, 0, func() bool {
		return time.Now().UnixMilli() > start
	})
}
