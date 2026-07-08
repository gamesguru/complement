package csapi_tests

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/tidwall/gjson"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/b"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/runtime"
	"github.com/matrix-org/gomatrixserverlib/spec"
)

// TestPaginationNoDuplicates is an adversarial test that stress-tests /messages
// pagination with small page sizes to catch off-by-one errors in pagination
// token boundaries that only manifest when page boundaries fall mid-sequence.
//
// Background: A real-world bug was observed where the same conduwuit binary
// produced duplicates on Ubuntu 24.04 but not 22.04, because different kernel
// scheduling affected how state events were interleaved with message events,
// which shifted page boundaries. With limit=10 and 20 messages, the bug only
// appeared when state events were distributed in a way that pushed boundaries
// to fall on certain events. Using small limits (1, 3, 7) forces many page
// boundaries and makes the off-by-one virtually guaranteed to trigger if present.
//
// The test creates realistic room activity: topic changes, power level edits,
// joins, leaves, kicks, and reactions interleaved with messages — not just a
// clean sequence of m.room.message events.
func TestPaginationNoDuplicates(t *testing.T) {
	runtime.SkipIf(t, runtime.Dendrite) // Dendrite has known backfill issues

	deployment := complement.Deploy(t, 2)
	defer deployment.Destroy(t)

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{
		LocalpartSuffix: "alice",
	})
	bob := deployment.Register(t, "hs2", helpers.RegistrationOpts{
		LocalpartSuffix: "bob",
	})

	// Test with clean messages only (baseline)
	t.Run("Clean messages only", func(t *testing.T) {
		roomID := alice.MustCreateRoom(t, map[string]interface{}{
			"preset": "public_chat",
		})

		eventIDs := sendNMessages(t, alice, roomID, 100)

		bob.MustJoinRoom(t, roomID, []spec.ServerName{
			deployment.GetFullyQualifiedHomeserverName(t, "hs1"),
		})

		for _, limit := range []int{1, 3, 7, 50} {
			t.Run(fmt.Sprintf("limit=%d", limit), func(t *testing.T) {
				assertPaginationIntegrity(t, bob, roomID, eventIDs, limit)
			})
		}
	})

	// Test with messy realistic room activity
	t.Run("Messy room activity", func(t *testing.T) {
		// Register extra local users for join/leave/kick churn
		charlie := deployment.Register(t, "hs1", helpers.RegistrationOpts{
			LocalpartSuffix: "charlie",
		})
		dana := deployment.Register(t, "hs1", helpers.RegistrationOpts{
			LocalpartSuffix: "dana",
		})
		eve := deployment.Register(t, "hs1", helpers.RegistrationOpts{
			LocalpartSuffix: "eve",
		})

		roomID := alice.MustCreateRoom(t, map[string]interface{}{
			"preset": "public_chat",
		})

		// Track only the message event IDs we care about verifying
		var trackedEventIDs []string

		// --- Phase 1: Initial chatter with topic changes ---
		trackedEventIDs = append(trackedEventIDs, sendNMessages(t, alice, roomID, 10)...)

		// Change topic
		alice.SendEventSynced(t, roomID, b.Event{
			Type:     "m.room.topic",
			StateKey: b.Ptr(""),
			Content: map[string]interface{}{
				"topic": "Phase 1: Getting started",
			},
		})

		trackedEventIDs = append(trackedEventIDs, sendNMessages(t, alice, roomID, 5)...)

		// --- Phase 2: Users join mid-conversation ---
		charlie.MustJoinRoom(t, roomID, nil)
		alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(charlie.UserID, roomID))

		trackedEventIDs = append(trackedEventIDs, sendNMessages(t, alice, roomID, 5)...)
		trackedEventIDs = append(trackedEventIDs, sendNMessages(t, charlie, roomID, 5)...)

		dana.MustJoinRoom(t, roomID, nil)
		alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(dana.UserID, roomID))

		// Change topic again
		alice.SendEventSynced(t, roomID, b.Event{
			Type:     "m.room.topic",
			StateKey: b.Ptr(""),
			Content: map[string]interface{}{
				"topic": "Phase 2: More people joining",
			},
		})

		trackedEventIDs = append(trackedEventIDs, sendNMessages(t, alice, roomID, 5)...)
		trackedEventIDs = append(trackedEventIDs, sendNMessages(t, dana, roomID, 3)...)

		// --- Phase 3: Power level changes ---
		// Give charlie moderator power
		alice.SendEventSynced(t, roomID, b.Event{
			Type:     "m.room.power_levels",
			StateKey: b.Ptr(""),
			Content: map[string]interface{}{
				"users": map[string]interface{}{
					alice.UserID:   100,
					charlie.UserID: 50,
				},
			},
		})

		trackedEventIDs = append(trackedEventIDs, sendNMessages(t, charlie, roomID, 5)...)

		// --- Phase 4: User leaves and rejoins ---
		dana.MustLeaveRoom(t, roomID)
		alice.MustSyncUntil(t, client.SyncReq{}, client.SyncLeftFrom(dana.UserID, roomID))

		trackedEventIDs = append(trackedEventIDs, sendNMessages(t, alice, roomID, 10)...)

		// Dana rejoins
		dana.MustJoinRoom(t, roomID, nil)
		alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(dana.UserID, roomID))

		trackedEventIDs = append(trackedEventIDs, sendNMessages(t, dana, roomID, 5)...)

		// --- Phase 5: Kick a user ---
		eve.MustJoinRoom(t, roomID, nil)
		alice.MustSyncUntil(t, client.SyncReq{}, client.SyncJoinedTo(eve.UserID, roomID))

		trackedEventIDs = append(trackedEventIDs, sendNMessages(t, eve, roomID, 3)...)

		// Alice kicks eve
		alice.MustDo(t, "POST", []string{"_matrix", "client", "v3", "rooms", roomID, "kick"},
			client.WithJSONBody(t, map[string]interface{}{
				"user_id": eve.UserID,
				"reason":  "Testing kick pagination",
			}),
		)
		alice.MustSyncUntil(t, client.SyncReq{}, client.SyncLeftFrom(eve.UserID, roomID))

		trackedEventIDs = append(trackedEventIDs, sendNMessages(t, alice, roomID, 5)...)

		// --- Phase 6: More topic changes and messages to pad out ---
		alice.SendEventSynced(t, roomID, b.Event{
			Type:     "m.room.topic",
			StateKey: b.Ptr(""),
			Content: map[string]interface{}{
				"topic": "Phase 6: Final stretch",
			},
		})

		trackedEventIDs = append(trackedEventIDs, sendNMessages(t, alice, roomID, 10)...)
		trackedEventIDs = append(trackedEventIDs, sendNMessages(t, charlie, roomID, 5)...)

		// Change room name for good measure
		alice.SendEventSynced(t, roomID, b.Event{
			Type:     "m.room.name",
			StateKey: b.Ptr(""),
			Content: map[string]interface{}{
				"name": "Stress Test Room",
			},
		})

		trackedEventIDs = append(trackedEventIDs, sendNMessages(t, alice, roomID, 10)...)
		trackedEventIDs = append(trackedEventIDs, sendNMessages(t, dana, roomID, 5)...)

		// --- Phase 7: Reactions (custom events) interleaved ---
		// Send some reactions to earlier messages
		for i := 0; i < 5 && i < len(trackedEventIDs); i++ {
			alice.SendEventSynced(t, roomID, b.Event{
				Type: "m.reaction",
				Content: map[string]interface{}{
					"m.relates_to": map[string]interface{}{
						"rel_type": "m.annotation",
						"event_id": trackedEventIDs[i],
						"key":      "👍",
					},
				},
			})
		}

		trackedEventIDs = append(trackedEventIDs, sendNMessages(t, alice, roomID, 9)...)

		t.Logf("Total tracked message events: %d", len(trackedEventIDs))
		t.Logf("Room should also contain: ~5 creation events, 3 topic changes, " +
			"1 room name, 1 power level change, ~8 membership changes, 5 reactions = " +
			"~23 non-message events interspersed throughout the timeline")

		// Now bob joins from a federated server and paginates through all of it
		bob.MustJoinRoom(t, roomID, []spec.ServerName{
			deployment.GetFullyQualifiedHomeserverName(t, "hs1"),
		})

		for _, limit := range []int{1, 3, 7, 50} {
			t.Run(fmt.Sprintf("limit=%d", limit), func(t *testing.T) {
				assertPaginationIntegrity(t, bob, roomID, trackedEventIDs, limit)
			})
		}
	})

	// Test re-join scenario (the one that originally failed)
	t.Run("Re-join with activity during absence", func(t *testing.T) {
		roomID := alice.MustCreateRoom(t, map[string]interface{}{
			"preset": "public_chat",
		})

		// Bob joins then leaves
		bob.MustJoinRoom(t, roomID, []spec.ServerName{
			deployment.GetFullyQualifiedHomeserverName(t, "hs1"),
		})
		bob.MustLeaveRoom(t, roomID)
		alice.MustSyncUntil(t, client.SyncReq{},
			client.SyncLeftFrom(bob.UserID, roomID))

		// While bob is away: messages + state changes
		var trackedEventIDs []string
		trackedEventIDs = append(trackedEventIDs, sendNMessages(t, alice, roomID, 30)...)

		alice.SendEventSynced(t, roomID, b.Event{
			Type:     "m.room.topic",
			StateKey: b.Ptr(""),
			Content: map[string]interface{}{
				"topic": "Bob missed this topic change",
			},
		})

		trackedEventIDs = append(trackedEventIDs, sendNMessages(t, alice, roomID, 30)...)

		alice.SendEventSynced(t, roomID, b.Event{
			Type:     "m.room.topic",
			StateKey: b.Ptr(""),
			Content: map[string]interface{}{
				"topic": "And this one too",
			},
		})

		trackedEventIDs = append(trackedEventIDs, sendNMessages(t, alice, roomID, 40)...)

		// Bob re-joins
		bob.MustJoinRoom(t, roomID, []spec.ServerName{
			deployment.GetFullyQualifiedHomeserverName(t, "hs1"),
		})

		for _, limit := range []int{1, 3, 7, 50} {
			t.Run(fmt.Sprintf("limit=%d", limit), func(t *testing.T) {
				assertPaginationIntegrity(t, bob, roomID, trackedEventIDs, limit)
			})
		}
	})
}

// TestPaginationTokenStability verifies that paginating the same room with
// different limit values always yields the same complete, ordered set of
// events. This catches bugs where pagination tokens encode limit-dependent
// state that breaks when clients retry with different parameters.
func TestPaginationTokenStability(t *testing.T) {
	runtime.SkipIf(t, runtime.Dendrite)

	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)

	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	roomID := alice.MustCreateRoom(t, map[string]interface{}{
		"preset": "public_chat",
	})

	eventIDs := sendNMessages(t, alice, roomID, 50)

	// Paginate with multiple limits and compare results
	var referenceEventIDs []string

	for i, limit := range []int{1, 5, 10, 25, 100} {
		t.Run(fmt.Sprintf("limit=%d", limit), func(t *testing.T) {
			result := collectAllMessageEventIDs(t, alice, roomID, limit)

			if i == 0 {
				referenceEventIDs = result
				t.Logf("Reference pagination (limit=%d): %d events", limit, len(result))
			} else {
				// Every limit should produce the same set of events in the same order
				if len(result) != len(referenceEventIDs) {
					t.Fatalf("limit=%d produced %d events, but limit=1 produced %d events",
						limit, len(result), len(referenceEventIDs))
				}
				for j, eventID := range result {
					if eventID != referenceEventIDs[j] {
						t.Fatalf("limit=%d event at index %d differs from limit=1: got %s, want %s",
							limit, j, eventID, referenceEventIDs[j])
					}
				}
			}
		})
	}

	// Also verify all sent messages are present in the reference
	for _, eventID := range eventIDs {
		if !slices.Contains(referenceEventIDs, eventID) {
			t.Errorf("sent event %s not found in any pagination result", eventID)
		}
	}
}

// sendNMessages sends n messages into a room, confirming each is synced.
// Returns the event IDs in send order.
func sendNMessages(t *testing.T, sender *client.CSAPI, roomID string, n int) []string {
	t.Helper()

	eventIDs := make([]string, n)
	for i := 0; i < n; i++ {
		eventIDs[i] = sender.SendEventSynced(t, roomID, b.Event{
			Type: "m.room.message",
			Content: map[string]interface{}{
				"msgtype": "m.text",
				"body":    fmt.Sprintf("Message %d of %d", i+1, n),
			},
		})
	}

	t.Logf("Sent %d messages into room %s", n, roomID)
	return eventIDs
}

// paginationResult holds the raw results of paginating through a room.
type paginationResult struct {
	// All event IDs collected (may include duplicates)
	allEventIDs []string
	// All event types collected (parallel to allEventIDs)
	allEventTypes []string
	// Number of /messages requests made
	requestCount int
	// Events per page (for diagnostics)
	eventsPerPage []int
}

// paginateRoom paginates backwards through a room's /messages endpoint,
// collecting ALL events (including state events) without any filtering.
func paginateRoom(t *testing.T, user *client.CSAPI, roomID string, limit int) paginationResult {
	t.Helper()

	result := paginationResult{}
	fromToken := ""

	for {
		messageQueryParams := url.Values{
			"dir":   []string{"b"},
			"limit": []string{strconv.Itoa(limit)},
		}
		if fromToken != "" {
			messageQueryParams.Set("from", fromToken)
		}

		messagesRes := user.MustDo(t, "GET", []string{"_matrix", "client", "v3", "rooms", roomID, "messages"},
			client.WithContentType("application/json"),
			client.WithQueries(messageQueryParams),
		)
		messagesResBody := client.ParseJSON(t, messagesRes)
		result.requestCount++

		chunkRes := gjson.GetBytes(messagesResBody, "chunk")
		if !chunkRes.Exists() || !chunkRes.IsArray() {
			t.Fatalf("page %d: missing or non-array 'chunk' in /messages response", result.requestCount)
		}

		pageEvents := chunkRes.Array()
		result.eventsPerPage = append(result.eventsPerPage, len(pageEvents))

		for _, event := range pageEvents {
			result.allEventIDs = append(result.allEventIDs, event.Get("event_id").Str)
			result.allEventTypes = append(result.allEventTypes, event.Get("type").Str)
		}

		// Paginate until no `end` token (reached room start)
		endTokenRes := gjson.GetBytes(messagesResBody, "end")
		if !endTokenRes.Exists() {
			break
		}
		fromToken = endTokenRes.Str

		// Safety valve: don't loop forever
		if result.requestCount > 500 {
			t.Fatalf("pagination did not terminate after %d requests", result.requestCount)
		}
	}

	return result
}

// collectAllMessageEventIDs paginates a room and returns only the m.room.message
// event IDs in chronological order (reversed from the backwards pagination).
func collectAllMessageEventIDs(t *testing.T, user *client.CSAPI, roomID string, limit int) []string {
	t.Helper()

	result := paginateRoom(t, user, roomID, limit)

	// Filter to just message events, deduplicating
	seen := make(map[string]bool)
	var messageEventIDs []string
	for i, eventID := range result.allEventIDs {
		if result.allEventTypes[i] == "m.room.message" && !seen[eventID] {
			messageEventIDs = append(messageEventIDs, eventID)
			seen[eventID] = true
		}
	}

	// Reverse to chronological order (pagination is backwards)
	slices.Reverse(messageEventIDs)
	return messageEventIDs
}

// assertPaginationIntegrity paginates a room and checks three independent properties:
//  1. NO DUPLICATES: no event_id appears more than once across all pages
//  2. NO GAPS: every expected message event_id is present
//  3. CORRECT ORDER: message events appear in the expected chronological order
//
// It also reports on non-message event types for diagnostic purposes.
func assertPaginationIntegrity(
	t *testing.T,
	user *client.CSAPI,
	roomID string,
	expectedMessageEventIDs []string,
	limit int,
) {
	t.Helper()

	result := paginateRoom(t, user, roomID, limit)

	t.Logf("Paginated with limit=%d: %d requests, %d total events, pages: %v",
		limit, result.requestCount, len(result.allEventIDs), result.eventsPerPage)

	// =====================================================================
	// CHECK 1: No duplicate events across pages
	// =====================================================================
	seen := make(map[string]int) // event_id -> first occurrence index
	var duplicates []string
	for i, eventID := range result.allEventIDs {
		if firstIdx, exists := seen[eventID]; exists {
			duplicates = append(duplicates, fmt.Sprintf(
				"  %s appeared at positions %d and %d (type: %s)",
				eventID, firstIdx, i, result.allEventTypes[i],
			))
		} else {
			seen[eventID] = i
		}
	}
	if len(duplicates) > 0 {
		// Show at most 20 duplicates to avoid flooding
		shown := duplicates
		if len(shown) > 20 {
			shown = shown[:20]
			shown = append(shown, fmt.Sprintf("  ... and %d more", len(duplicates)-20))
		}
		t.Errorf("DUPLICATE EVENTS DETECTED (%d duplicates across %d pages with limit=%d):\n%s",
			len(duplicates), result.requestCount, limit, strings.Join(shown, "\n"))
	}

	// =====================================================================
	// CHECK 2: No missing message events
	// =====================================================================
	var missing []string
	for i, expectedID := range expectedMessageEventIDs {
		if _, exists := seen[expectedID]; !exists {
			missing = append(missing, fmt.Sprintf("  message %d: %s", i, expectedID))
		}
	}
	if len(missing) > 0 {
		// Show at most 20 missing to avoid flooding
		shown := missing
		if len(shown) > 20 {
			shown = shown[:20]
			shown = append(shown, fmt.Sprintf("  ... and %d more", len(missing)-20))
		}
		t.Errorf("MISSING EVENTS (%d of %d messages not found with limit=%d):\n%s",
			len(missing), len(expectedMessageEventIDs), limit, strings.Join(shown, "\n"))
	}

	// =====================================================================
	// CHECK 3: Correct order (message events should be in reverse chronological
	// order since we paginate backwards)
	// =====================================================================
	var messageEventsInPaginationOrder []string
	for i, eventID := range result.allEventIDs {
		if result.allEventTypes[i] == "m.room.message" {
			// Skip duplicates for order checking
			if len(messageEventsInPaginationOrder) > 0 &&
				messageEventsInPaginationOrder[len(messageEventsInPaginationOrder)-1] == eventID {
				continue
			}
			messageEventsInPaginationOrder = append(messageEventsInPaginationOrder, eventID)
		}
	}

	// Pagination is backwards, so reverse for chronological comparison
	chronological := slices.Clone(messageEventsInPaginationOrder)
	slices.Reverse(chronological)

	// Find first out-of-order event
	minLen := len(chronological)
	if len(expectedMessageEventIDs) < minLen {
		minLen = len(expectedMessageEventIDs)
	}
	for i := 0; i < minLen; i++ {
		if chronological[i] != expectedMessageEventIDs[i] {
			t.Errorf("ORDER MISMATCH at position %d (limit=%d): got %s, want %s",
				i, limit, chronological[i], expectedMessageEventIDs[i])
			break
		}
	}

	// =====================================================================
	// DIAGNOSTIC: Report on non-message event types seen
	// =====================================================================
	typeCounts := make(map[string]int)
	for _, eventType := range result.allEventTypes {
		typeCounts[eventType]++
	}
	var typeReport []string
	for eventType, count := range typeCounts {
		typeReport = append(typeReport, fmt.Sprintf("%s: %d", eventType, count))
	}
	t.Logf("Event type breakdown: %s", strings.Join(typeReport, ", "))
}

// dumpEventDetails is a test helper that can be called to log all raw events from
// pagination for debugging purposes. This is intentionally verbose.
func dumpEventDetails(t *testing.T, messagesResBody json.RawMessage, pageNum int) {
	t.Helper()

	chunkRes := gjson.GetBytes(messagesResBody, "chunk")
	if !chunkRes.Exists() {
		return
	}

	for i, event := range chunkRes.Array() {
		t.Logf("  Page %d, event %d: type=%s event_id=%s state_key=%s",
			pageNum, i,
			event.Get("type").Str,
			event.Get("event_id").Str,
			event.Get("state_key").Str,
		)
	}
}
