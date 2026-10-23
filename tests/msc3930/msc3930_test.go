// This file contains tests for "push rules of polls" as defined by MSC3930.
// The MSC that defines the design of the polls system is MSC3381.
//
// Note that implementation of MSC3381 is not required by the homeserver to
// pass the tests in this file.
//
// You can read either MSC using the links below.
// Polls: https://github.com/matrix-org/matrix-doc/pull/3381
// Push rules for polls: https://github.com/matrix-org/matrix-doc/pull/3930

package tests

import (
	"encoding/json"
	"math"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/internal/web"
	"github.com/matrix-org/complement/match"
	"github.com/matrix-org/complement/must"
	"github.com/matrix-org/complement/runtime"
)

const pollResponseRuleID = ".org.matrix.msc3930.rule.poll_response"
const pollStartOneToOneRuleID = ".org.matrix.msc3930.rule.poll_start_one_to_one"
const pollEndOneToOneRuleID = ".org.matrix.msc3930.rule.poll_end_one_to_one"
const pollStartRuleID = ".org.matrix.msc3930.rule.poll_start"
const pollEndRuleID = ".org.matrix.msc3930.rule.poll_end"

func TestPollsLocalPushRules(t *testing.T) {
	// Venator does not yet implement pushers.
	runtime.SkipIf(t, runtime.Venator)
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	// Create a user to poll the push rules of.
	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	// Test for the presence of the expected push rules. Clients are expected
	// to implement local matching of events based on the presented rules.
	t.Run("Polls push rules are correctly presented to the client", func(t *testing.T) {
		// Request each of the push rule IDs defined by MSC3930 and verify their structure.

		// This push rule silences all poll responses.
		pollResponseRule := alice.MustGetPushRule(t, "global", "override", pollResponseRuleID)
		must.MatchGJSON(
			t,
			pollResponseRule,
			match.JSONKeyEqual("actions", []string{}),
			match.JSONKeyEqual("default", true),
			match.JSONKeyEqual("enabled", true),
			// There should only be one condition defined for this type
			match.JSONKeyEqual("conditions.#", 1),
			// Check the contents of the first (and only) condition
			match.JSONKeyEqual("conditions.0.kind", "event_match"),
			match.JSONKeyEqual("conditions.0.key", "type"),
			match.JSONKeyEqual("conditions.0.pattern", "org.matrix.msc3381.poll.response"),
		)

		// This push rule creates a sound and notifies the user when a poll is started in a one-to-one room.
		pollStartOneToOneRule := alice.MustGetPushRule(t, "global", "underride", pollStartOneToOneRuleID)
		must.MatchGJSON(
			t,
			pollStartOneToOneRule,
			// Check that the appropriate actions are set for this rule
			match.JSONKeyEqual("actions.#", 2),
			match.JSONKeyEqual("actions", []interface{}{
				"notify",
				map[string]interface{}{"set_tweak": "sound", "value": "default"},
			},
			),
			match.JSONKeyEqual("default", true),
			match.JSONKeyEqual("enabled", true),
			// There should two conditions defined for this type
			match.JSONKeyEqual("conditions.#", 2),
			// Check the condition that requires a room between two users
			match.JSONKeyEqual("conditions.#(kind==\"room_member_count\").is", "2"),
			// Check the condition that requires a poll start event
			match.JSONKeyEqual("conditions.#(kind==\"event_match\").key", "type"),
			match.JSONKeyEqual("conditions.#(kind==\"event_match\").pattern", "org.matrix.msc3381.poll.start"),
		)

		// This push rule creates a sound and notifies the user when a poll is ended in a one-to-one room.
		pollEndOneToOneRule := alice.MustGetPushRule(t, "global", "underride", pollEndOneToOneRuleID)
		must.MatchGJSON(
			t,
			pollEndOneToOneRule,
			// Check that the appropriate actions are set for this rule
			match.JSONKeyEqual("actions.#", 2),
			match.JSONKeyEqual("actions", []interface{}{
				"notify",
				map[string]interface{}{"set_tweak": "sound", "value": "default"},
			},
			),
			match.JSONKeyEqual("default", true),
			match.JSONKeyEqual("enabled", true),
			// There should two conditions defined for this type
			match.JSONKeyEqual("conditions.#", 2),
			// Check the condition that requires a room between two users
			match.JSONKeyEqual("conditions.#(kind==\"room_member_count\").is", "2"),
			// Check the condition that requires a poll start event
			match.JSONKeyEqual("conditions.#(kind==\"event_match\").key", "type"),
			match.JSONKeyEqual("conditions.#(kind==\"event_match\").pattern", "org.matrix.msc3381.poll.end"),
		)

		// This push rule notifies the user when a poll is started in any room.
		pollStartRule := alice.MustGetPushRule(t, "global", "underride", pollStartRuleID)
		must.MatchGJSON(
			t,
			pollStartRule,
			// Check that the appropriate actions are set for this rule
			match.JSONKeyEqual("actions", []string{"notify"}),
			match.JSONKeyEqual("default", true),
			match.JSONKeyEqual("enabled", true),
			// There should only be one condition defined for this type
			match.JSONKeyEqual("conditions.#", 1),
			// Check the contents of the first (and only) condition
			match.JSONKeyEqual("conditions.0.kind", "event_match"),
			match.JSONKeyEqual("conditions.0.key", "type"),
			match.JSONKeyEqual("conditions.0.pattern", "org.matrix.msc3381.poll.start"),
		)

		// This push rule notifies the user when a poll is ended in any room.
		pollEndRule := alice.MustGetPushRule(t, "global", "underride", pollEndRuleID)
		must.MatchGJSON(
			t,
			pollEndRule,
			// Check that the appropriate actions are set for this rule
			match.JSONKeyEqual("actions", []string{"notify"}),
			match.JSONKeyEqual("default", true),
			match.JSONKeyEqual("enabled", true),
			// There should only be one condition defined for this type
			match.JSONKeyEqual("conditions.#", 1),
			// Check the contents of the first (and only) condition
			match.JSONKeyEqual("conditions.0.kind", "event_match"),
			match.JSONKeyEqual("conditions.0.key", "type"),
			match.JSONKeyEqual("conditions.0.pattern", "org.matrix.msc3381.poll.end"),
		)

		// The DM-specific rules for poll start and poll end should come before the rules that
		// define behaviour for any room. We verify this by ensuring that the DM-specific rules
		// have a lower index when requesting all push rules.
		allPushRules := alice.GetAllPushRules(t)
		globalUnderridePushRules := allPushRules.Get("global").Get("underride").Array()

		pollStartOneToOneRuleIndex := math.MaxInt64
		pollEndOneToOneRuleIndex := math.MaxInt64
		for index, rule := range globalUnderridePushRules {
			// Iterate over the user's global underride rules as a client would.
			// If we come across a one-to-one room rule ID, we note down its index.
			// When we come across the rule ID of its generic counterpart, we ensure
			// its counterpart is at a higher index, and thus would be considered
			// lower priority.
			if rule.Get("rule_id").Str == pollStartOneToOneRuleID {
				pollStartOneToOneRuleIndex = index
			} else if rule.Get("rule_id").Str == pollEndOneToOneRuleID {
				pollEndOneToOneRuleIndex = index
			} else if rule.Get("rule_id").Str == pollStartRuleID {
				if pollStartOneToOneRuleIndex > index {
					t.Fatalf(
						"Expected rule '%s' to come after '%s' in '%s's global underride rules",
						pollStartRuleID,
						pollStartOneToOneRuleID,
						alice.UserID,
					)
				}
			} else if rule.Get("rule_id").Str == pollEndRuleID {
				if pollEndOneToOneRuleIndex > index {
					t.Fatalf(
						"Expected rule '%s' to come after '%s' in '%s's global underride rules",
						pollEndRuleID,
						pollEndOneToOneRuleID,
						alice.UserID,
					)
				}
			}
		}
	})
}

// TestPollsPushGatewayNotifications checks that the homeserver actually calls
// POST /_matrix/push/v1/notify according to the MSC3930 rules: poll starts
// notify, poll responses are silenced.
func TestPollsPushGatewayNotifications(t *testing.T) {
	// Venator does not yet implement pushers.
	runtime.SkipIf(t, runtime.Venator)
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	notified := make(chan string, 16)
	gateway := web.NewServer(t, deployment.GetConfig(), func(router *mux.Router) {
		router.HandleFunc("/_matrix/push/v1/notify", func(w http.ResponseWriter, req *http.Request) {
			var body struct {
				Notification struct {
					EventID string `json:"event_id"`
				} `json:"notification"`
			}
			if err := json.NewDecoder(req.Body).Decode(&body); err == nil {
				select {
				case notified <- body.Notification.EventID:
				default:
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"rejected":[]}`))
		}).Methods("POST")
	})
	defer gateway.Close()

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	bob := deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	// A third member keeps the room out of the one-to-one rules, so the generic
	// poll_start rule is the one under test.
	charlie := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	bob.MustDo(t, "POST", []string{"_matrix", "client", "v3", "pushers", "set"}, client.WithJSONBody(t, map[string]interface{}{
		"kind":                "http",
		"app_id":              "complement.msc3930",
		"app_display_name":    "Complement",
		"device_display_name": "Complement",
		"pushkey":             "msc3930_push_key",
		"lang":                "en",
		"data": map[string]interface{}{
			"url":    gateway.URL + "/_matrix/push/v1/notify",
			"format": "event_id_only",
		},
		"append": false,
	}))

	roomID := alice.MustCreateRoom(t, map[string]interface{}{"preset": "public_chat"})
	bob.MustJoinRoom(t, roomID, nil)
	charlie.MustJoinRoom(t, roomID, nil)

	// Alice's own activity (the join above) must not leak into the assertions below,
	// so drain anything the gateway has already seen.
	drain := func() {
		for {
			select {
			case <-notified:
			default:
				return
			}
		}
	}
	waitFor := func(eventID string) bool {
		timeout := time.After(10 * time.Second)
		for {
			select {
			case got := <-notified:
				if got == eventID {
					return true
				}
			case <-timeout:
				return false
			}
		}
	}

	pollStartID := ""
	t.Run("Poll start triggers a push gateway notification", func(t *testing.T) {
		drain()
		id := alice.SendEventSynced(t, roomID, b.Event{
			Type: "org.matrix.msc3381.poll.start",
			Content: map[string]interface{}{
				"org.matrix.msc3381.poll.start": map[string]interface{}{
					"kind":           "org.matrix.msc3381.poll.disclosed",
					"max_selections": 1,
					"question":       map[string]interface{}{"org.matrix.msc1767.text": "Pizza?"},
					"answers": []map[string]interface{}{
						{"id": "yes", "org.matrix.msc1767.text": "Yes"},
						{"id": "no", "org.matrix.msc1767.text": "No"},
					},
				},
				"org.matrix.msc1767.text": "Pizza?\n1. Yes\n2. No",
			},
		})
		if !waitFor(id) {
			t.Fatalf("push gateway was not notified of poll start %s", id)
		}
		pollStartID = id
	})

	t.Run("Poll response does not trigger a push gateway notification", func(t *testing.T) {
		if pollStartID == "" {
			t.Skip("no poll start to respond to")
		}
		drain()
		responseID := alice.SendEventSynced(t, roomID, b.Event{
			Type: "org.matrix.msc3381.poll.response",
			Content: map[string]interface{}{
				"m.relates_to": map[string]interface{}{
					"rel_type": "m.reference",
					"event_id": pollStartID,
				},
				"org.matrix.msc3381.poll.response": map[string]interface{}{"answers": []string{"yes"}},
			},
		})
		// A plain message afterwards acts as a barrier. Push delivery order is not
		// guaranteed, so after the barrier arrives we keep listening for a grace
		// period. This is best-effort: it can miss a very late notification, but it
		// never fails a conforming homeserver.
		barrierID := alice.SendEventSynced(t, roomID, b.Event{
			Type:    "m.room.message",
			Content: map[string]interface{}{"msgtype": "m.text", "body": "barrier"},
		})
		barrierSeen := false
		timeout := time.After(10 * time.Second)
		for {
			select {
			case got := <-notified:
				if got == responseID {
					t.Fatalf("push gateway was notified of poll response %s, which MSC3930 silences", responseID)
				}
				if got == barrierID {
					barrierSeen = true
					timeout = time.After(2 * time.Second)
				}
			case <-timeout:
				if !barrierSeen {
					t.Fatalf("push gateway never received the barrier message %s", barrierID)
				}
				return
			}
		}
	})
}
