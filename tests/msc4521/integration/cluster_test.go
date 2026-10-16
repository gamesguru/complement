//go:build !dendrite_blacklist && !venator_blacklist

package integration

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Wombat-Foundation/gomatrixcrypto/reconcile"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/tidwall/gjson"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/federation"
	"github.com/matrix-org/complement/federation/linkproxy"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/must"
)

// cluster is n homeservers in one room, all federation between them routed
// through a link proxy, with a prober for reading digests.
type cluster struct {
	n          int
	deployment complement.Deployment
	prober     *federation.Server
	proxy      *linkproxy.Proxy
	users      []*client.CSAPI
	roomID     string
}

func newCluster(t *testing.T, n int) *cluster {
	t.Helper()
	deployment := complement.Deploy(t, n)
	t.Cleanup(func() { deployment.Destroy(t) })
	prober := federation.NewServer(t, deployment, federation.HandleKeyRequests())
	t.Cleanup(prober.Listen())
	names := make([]string, n)
	for i := range names {
		names[i] = hsName(i)
	}
	proxy := linkproxy.New(t, deployment, names...)
	t.Cleanup(proxy.Close)

	c := &cluster{n: n, deployment: deployment, prober: prober, proxy: proxy, users: make([]*client.CSAPI, n)}
	for i := range c.users {
		c.users[i] = deployment.Register(t, hsName(i), helpers.RegistrationOpts{})
	}
	c.roomID = c.users[0].MustCreateRoom(t, map[string]interface{}{"preset": "public_chat"})
	hs1 := deployment.GetFullyQualifiedHomeserverName(t, "hs1")
	for i := 1; i < n; i++ {
		c.users[i].MustJoinRoom(t, c.roomID, []spec.ServerName{hs1})
	}
	return c
}

func (c *cluster) say(t *testing.T, i int, body string) string {
	t.Helper()
	return c.users[i].SendEventSynced(t, c.roomID, b.Event{
		Type: "m.room.message", Content: map[string]interface{}{"msgtype": "m.text", "body": body},
	})
}

func (c *cluster) digestOf(t *testing.T, i int) (string, int64) {
	t.Helper()
	body, status := getRoomDigestFrom(t, c.prober, c.deployment, hsName(i), c.roomID, "")
	skipIfUnsupported(t, status)
	must.Equal(t, status, 200, hsName(i)+" digest status")
	d := gjson.ParseBytes(body)
	return d.Get("digest").Str, d.Get("known_event_count").Int()
}

// expectedDigest is the digest and count of every event in the room as seen by user 0.
func (c *cluster) expectedDigest(t *testing.T) (string, int64) {
	t.Helper()
	k := reconcile.NewResidentKernel()
	for _, id := range roomEventIDs(t, c.users[0], c.roomID) {
		h, err := reconcile.FromMatrixEventID(id, reconcile.V4Plus)
		must.NotError(t, "hash event", err)
		must.NotError(t, "insert event", k.Insert(h))
	}
	return k.Accumulator().EncodeDigest(), int64(k.Accumulator().Count)
}

// waitDigest waits until every listed homeserver reports the given digest and count.
func (c *cluster) waitDigest(t *testing.T, servers []int, digest string, count int64, what string) {
	t.Helper()
	deadline := time.Now().Add(120 * time.Second)
	for {
		ok := true
		for _, i := range servers {
			if d, n := c.digestOf(t, i); d != digest || n != count {
				ok = false
			}
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Second)
	}
}

func (c *cluster) all() []int {
	s := make([]int, c.n)
	for i := range s {
		s[i] = i
	}
	return s
}

// countSince counts successful (200) proxied requests after log offset `from`
// whose path contains pathSubstr.
func (c *cluster) countSince(from int, pathSubstr string) int {
	n := 0
	for _, e := range c.proxy.Log()[from:] {
		if e.Status == 200 && strings.Contains(e.Path, pathSubstr) {
			n++
		}
	}
	return n
}

// Partition: one homeserver is frozen while others originate events, then
// resumed. It must reach the exact expected set.
func TestMSC4521PausedHomeserverCatchesUp(t *testing.T) {
	c := newCluster(t, 4)
	c.say(t, 0, "before partition")
	d0, n0 := c.expectedDigest(t)
	c.waitDigest(t, c.all(), d0, n0, "pre-partition agreement")

	c.deployment.PauseServer(t, hsName(3))
	for i := 0; i < 3; i++ {
		c.say(t, i, fmt.Sprintf("during partition %d", i))
	}
	want, wantCount := c.expectedDigest(t)
	must.Equal(t, wantCount, n0+3, "the partition produced exactly 3 new events")
	c.waitDigest(t, []int{0, 1, 2}, want, wantCount, "the unpaused homeservers to agree")

	c.deployment.UnpauseServer(t, hsName(3))
	c.waitDigest(t, []int{3}, want, wantCount, "the resumed homeserver to catch up")
}

// TestMSC4521PartitionHealUsesReconciliation cuts every link into and out of
// one homeserver, lets the rest originate events, heals the links, and checks
// from the proxy log WHICH mechanism closed the gap: reconciliation requests
// were made and succeeded, and no ordinary history fetch was needed.
func TestMSC4521PartitionHealUsesReconciliation(t *testing.T) {
	c := newCluster(t, 4)
	c.say(t, 0, "before partition")
	d0, n0 := c.expectedDigest(t)
	c.waitDigest(t, c.all(), d0, n0, "pre-partition agreement")

	c.proxy.SetInto(hsName(3), linkproxy.Block)
	c.proxy.SetAll(hsName(3), linkproxy.Block)
	for i := 0; i < 3; i++ {
		c.say(t, i, fmt.Sprintf("during partition %d", i))
	}
	want, wantCount := c.expectedDigest(t)
	c.waitDigest(t, []int{0, 1, 2}, want, wantCount, "the connected homeservers to agree")

	healedAt := len(c.proxy.Log())
	c.proxy.SetInto(hsName(3), linkproxy.Allow)
	c.proxy.SetAll(hsName(3), linkproxy.Allow)
	c.waitDigest(t, []int{3}, want, wantCount, "the healed homeserver to catch up")

	if n := c.countSince(healedAt, "room_diff") + c.countSince(healedAt, "room_digest"); n == 0 {
		t.Error("no reconciliation request crossed a link after healing: catch-up used another mechanism")
	}
	for _, fallback := range []string{"/state_ids/", "/get_missing_events/", "/backfill/"} {
		if n := c.countSince(healedAt, fallback); n != 0 {
			t.Errorf("%d successful %s request(s) after healing: the gap was not closed by reconciliation alone", n, fallback)
		}
	}
}
