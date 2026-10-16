package integration

import (
	"sort"
	"testing"
)

// testWireBisect is TEMPORARY. It finds which request key makes hs1 answer
// room_diff with "expected string" by sending the otherwise valid body with
// each key removed, and a required-fields-only body. It only logs.
func testWireBisect(t *testing.T) {
	h := newHomeserverSide(t)
	r := h.newRoom(t)
	valid := diffBody(t, h.loadFrame(t, r), r.kernel(t), r.h64s(t), rootBucket)

	send := func(label string, body map[string]interface{}) {
		out, status := doRoomDiff(t, h.srv, h.deployment, r.id, body)
		t.Logf("BISECT %-28s -> %d %.110s", label, status, out)
	}
	send("full", valid)

	keys := make([]string, 0, len(valid))
	for k := range valid {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, drop := range keys {
		body := map[string]interface{}{}
		for k, v := range valid {
			if k != drop {
				body[k] = v
			}
		}
		send("without "+drop, body)
	}

	required := map[string]interface{}{}
	for _, k := range []string{"mode", "digest_type", "frame_id", "local_digest", "local_known_event_count", "requests", "local_sketches"} {
		required[k] = valid[k]
	}
	send("required only", required)

	withNulls := map[string]interface{}{"scope": nil, "state_at": nil, "frame_negotiation": false}
	for k, v := range required {
		withNulls[k] = v
	}
	send("required + null optionals", withNulls)
}
