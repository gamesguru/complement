package tests

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/helpers"
)

// dockerExec runs a shell command inside the given container via
// `docker exec sh -c <script>`, returning combined stdout+stderr. The
// complement-synapse image is minimal and has neither a supervisorctl
// control socket nor even `ps`/`pgrep`/`pkill`, so process discovery and
// signalling below goes straight through /proc instead of relying on any
// of those.
func dockerExec(containerID string, script string) (string, error) {
	out, err := exec.Command("docker", "exec", containerID, "sh", "-c", script).CombinedOutput()
	return string(out), err
}

// findRedisServerPID returns the redis-server PID (as seen from /proc)
// inside the container, or "" if none is running.
const findRedisServerPIDScript = `
for p in /proc/[0-9]*; do
  if [ -r "$p/cmdline" ] && tr '\0' ' ' < "$p/cmdline" | grep -q redis-server; then
    printf '%s' "${p#/proc/}"
    exit 0
  fi
done
`

func findRedisServerPID(containerID string) (string, error) {
	out, err := dockerExec(containerID, findRedisServerPIDScript)
	return strings.TrimSpace(out), err
}

// TestRedisRestartRecovery exercises Synapse's replication reconnect path
// directly: it kills the `redis-server` process supervised inside the
// homeserver container (mirroring an out-of-band crash, since supervisord
// has autorestart=true for it -- see
// docker/conf-workers/supervisord.conf.j2), then asserts that a locally-sent
// event still becomes visible via /sync within a generous bound.
//
// This is deliberately *not* run against the same tight timeout as
// TestMSC4297StateResolutionV2_1_includes_conflicted_subgraph. That test's
// failure under the `workers, Postgres` CI arrangement coincided with a
// Redis crash+restart in the same run, and its 5s MustSyncUntil timeout is
// tighter than the worst case for reconnect+REPLICATE+catch-up. This test
// isolates the Redis-restart variable alone with a 15s bound so a pass here
// is real evidence that recovery itself works and the fix belongs in that
// test's timeout, not in the replication code.
//
// Skips outside of a `workers`-mode deployment (there is no redis-server
// process in monolith mode).
func TestRedisRestartRecovery(t *testing.T) {
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	containerID := deployment.ContainerID(t, "hs1")

	pid, err := findRedisServerPID(containerID)
	if err != nil {
		t.Fatalf("failed to inspect %s for redis-server: %v", containerID, err)
	}
	if pid == "" {
		t.Skip("no redis-server process found in this deployment (monolith mode)")
	}

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{
		LocalpartSuffix: "alice",
	})
	roomID := alice.MustCreateRoom(t, map[string]interface{}{
		"preset": "public_chat",
	})

	// Establish a baseline sync position before the restart.
	since := alice.MustSyncUntil(t, client.SyncReq{})

	// Under Complement's dirty-run container reuse, the PID we just read can
	// already be gone by the time we signal it (supervisord itself cycles
	// redis-server between tests sharing a container) -- "No such process"
	// here means the crash-and-respawn we wanted already happened on its
	// own, not that the test is broken, so it isn't fatal.
	if out, err := dockerExec(containerID, "kill -9 "+pid); err != nil && !strings.Contains(out, "No such process") {
		t.Fatalf("failed to kill redis-server (pid %s): %v (output: %s)", pid, err, out)
	}

	// Confirm supervisord actually respawned it under a new PID -- if this
	// never becomes true the test should fail loudly rather than mask the
	// crash by timing out later in MustSyncUntil with a confusing error.
	respawned := false
	for i := 0; i < 50; i++ {
		newPID, _ := findRedisServerPID(containerID)
		if newPID != "" && newPID != pid {
			respawned = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !respawned {
		t.Fatalf("redis-server did not respawn within 5s of being killed -- supervisord autorestart appears broken, not just slow")
	}

	// SendEventSynced itself waits for /sync, so set the recovery allowance
	// before calling it rather than only for the later incremental sync.
	alice.SyncUntilTimeout = 15 * time.Second
	eventID := alice.SendEventSynced(t, roomID, b.Event{
		Type: "m.room.message",
		Content: map[string]interface{}{
			"msgtype": "m.text",
			"body":    "post-redis-restart",
		},
	})

	// Recovery after a Redis restart is downtime + reconnect backoff +
	// resubscribe + REPLICATE catch-up, not just the ~5s reconnect delay
	// cap alone -- give it real headroom rather than reusing the tight
	// bound that made the original test flaky.
	alice.MustSyncUntil(t, client.SyncReq{Since: since}, client.SyncTimelineHasEventID(roomID, eventID))

	t.Logf("event became visible via /sync after redis restart within the 15s bound")
}
