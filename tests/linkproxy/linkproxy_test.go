//go:build !dendrite_blacklist && !venator_blacklist

// Venator does not yet implement federation.

package linkproxy

import (
	"strings"
	"testing"
	"time"

	"github.com/matrix-org/gomatrixserverlib/spec"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/federation/linkproxy"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/must"
)

// TestLinkProxy checks the proxy itself, independent of any MSC: federation
// between two homeservers flows through it, a blocked link stops delivery and
// fails fast, and releasing the link lets delivery resume.
func TestLinkProxy(t *testing.T) {
	deployment := complement.Deploy(t, 2)
	defer deployment.Destroy(t)
	proxy := linkproxy.New(t, deployment, "hs1", "hs2")
	defer proxy.Close()

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	bob := deployment.Register(t, "hs2", helpers.RegistrationOpts{})

	roomID := alice.MustCreateRoom(t, map[string]interface{}{"preset": "public_chat"})
	bob.MustJoinRoom(t, roomID, []spec.ServerName{"hs1"})

	t.Run("TrafficFlowsThroughProxy", func(t *testing.T) {
		// hs2 reached hs1 through the proxy to join, so the join handshake is logged.
		must.Equal(t, proxy.Count("hs2", "hs1", "/make_join/") > 0, true, "hs2 -> hs1 make_join went through the proxy")
		must.Equal(t, proxy.Count("hs2", "hs1", "/send_join/") > 0, true, "hs2 -> hs1 send_join went through the proxy")
		for _, e := range proxy.Log() {
			t.Logf("%s %s -> %s %s %s => %d", e.Time.Format("15:04:05.000"), e.Src, e.Dst, e.Method, e.Path, e.Status)
		}
	})

	t.Run("BlockedLinkFailsFastAndHealsOnRelease", func(t *testing.T) {
		blocked := len(proxy.Log())
		proxy.Set("hs1", "hs2", linkproxy.Block)
		sent := alice.SendEventSynced(t, roomID, b.Event{Type: "m.room.message", Content: map[string]interface{}{"msgtype": "m.text", "body": "blocked"}})

		deadline := time.Now().Add(30 * time.Second)
		for proxy.CountStatus("hs1", "hs2", "/send/", 503) == 0 {
			if time.Now().After(deadline) {
				t.Fatal("hs1 never attempted /send to hs2 while the link was blocked")
			}
			time.Sleep(500 * time.Millisecond)
		}
		must.Equal(t, proxy.CountStatus("hs1", "hs2", "/send/", 200), 0, "no /send reached hs2 while blocked")

		proxy.Set("hs1", "hs2", linkproxy.Allow)
		// hs1 retries with backoff, so allow generous time.
		bob.MustSyncUntil(t, client.SyncReq{}, client.SyncTimelineHasEventID(roomID, sent))
		// Only hs1 -> hs2 is blocked, so the event may be redelivered by hs1's
		// /send retry or pulled by hs2 with MSC4521 reconciliation, possibly even
		// before the release. Either way it reached hs2 without a blocked /send.
		viaSend, viaReconcile := false, false
		for _, e := range proxy.Log()[blocked:] {
			switch {
			case e.Src == "hs1" && e.Dst == "hs2" && strings.Contains(e.Path, "/send/") && e.Status == 200:
				viaSend = true
			case e.Src == "hs2" && e.Dst == "hs1" && strings.Contains(e.Path, "room_digest"):
				viaReconcile = true
			}
		}
		must.Equal(t, viaSend || viaReconcile, true, "the event reached hs2 via /send or reconciliation")
		t.Logf("healed via /send: %t, via reconciliation: %t", viaSend, viaReconcile)
	})
}
