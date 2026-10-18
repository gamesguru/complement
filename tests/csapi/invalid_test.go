package csapi_tests

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/matrix-org/complement"
	"github.com/matrix-org/complement/client"
	"github.com/matrix-org/complement/helpers"
	"github.com/matrix-org/complement/match"
	"github.com/matrix-org/complement/must"
	"github.com/matrix-org/complement/runtime"
)

func TestJson(t *testing.T) {
	// Venator: does not support room version 6 (>=v10 only)
	runtime.SkipIf(t, runtime.Venator)
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)
	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	roomID := alice.MustCreateRoom(t, map[string]interface{}{
		"room_opts": map[string]interface{}{
			"room_version": "6",
		},
	})

	t.Run("Parallel", func(t *testing.T) {
		// sytest: Invalid JSON integers
		// sytest: Invalid JSON floats
		t.Run("Invalid numerical values", func(t *testing.T) {
			t.Parallel()

			testCases := [][]byte{
				[]byte(`{"body": 9007199254740992}`),
				[]byte(`{"body": -9007199254740992}`),
				[]byte(`{"body": 1.1}`),
			}

			for _, testCase := range testCases {
				res := alice.Do(t, "PUT", []string{"_matrix", "client", "v3", "rooms", roomID, "send", "complement.dummy", helpers.GetTxnID("TestJson-InvalidNum")}, client.WithJSONBody(t, testCase))

				must.MatchResponse(t, res, match.HTTPResponse{
					StatusCode: 400,
					JSON: []match.JSON{
						match.JSONKeyEqual("errcode", "M_BAD_JSON"),
					},
				})
			}
		})

		// sytest: Invalid JSON special values
		t.Run("Invalid JSON special values", func(t *testing.T) {
			t.Parallel()

			testCases := [][]byte{
				[]byte(`{"body": Infinity}`),
				[]byte(`{"body": -Infinity}`),
				[]byte(`{"body": NaN}`),
			}

			for _, testCase := range testCases {
				res := alice.Do(t, "PUT", []string{"_matrix", "client", "v3", "rooms", roomID, "send", "complement.dummy", helpers.GetTxnID("TestJson-InvalidVal")}, client.WithJSONBody(t, testCase))

				must.MatchResponse(t, res, match.HTTPResponse{
					StatusCode: 400,
				})
			}
		})
	})
}

// getFilters returns filters that violate the type rules of the Filter,
// RoomFilter, EventFilter and RoomEventFilter definitions in the client-server
// spec. Every case must be rejected with a 4xx.
func getFilters() []map[string]interface{} {
	const NAO = "not_an_object"
	const NAL = "not_a_list"

	return []map[string]interface{}{
		{
			"presence": NAO,
		},

		{
			"room": map[string]interface{}{
				"timeline": NAO,
			},
		},
		{
			"room": map[string]interface{}{
				"state": NAO,
			},
		},
		{
			"room": map[string]interface{}{
				"ephemeral": NAO,
			},
		},
		{
			"room": map[string]interface{}{
				"account_data": NAO,
			},
		},

		{
			"room": map[string]interface{}{
				"timeline": map[string]interface{}{
					"rooms": NAL,
				},
			},
		},
		{
			"room": map[string]interface{}{
				"timeline": map[string]interface{}{
					"not_rooms": NAL,
				},
			},
		},
		{
			"room": map[string]interface{}{
				"timeline": map[string]interface{}{
					"senders": NAL,
				},
			},
		},
		{
			"room": map[string]interface{}{
				"timeline": map[string]interface{}{
					"not_senders": NAL,
				},
			},
		},
		{
			"room": map[string]interface{}{
				"timeline": map[string]interface{}{
					"types": NAL,
				},
			},
		},
		{
			"room": map[string]interface{}{
				"timeline": map[string]interface{}{
					"not_types": NAL,
				},
			},
		},

		{
			"room": map[string]interface{}{
				"timeline": map[string]interface{}{
					"types": []int{1},
				},
			},
		},
		{
			"room": map[string]interface{}{
				"timeline": map[string]interface{}{
					"rooms": []string{"not_a_room_id"},
				},
			},
		},
		{
			"room": map[string]interface{}{
				"timeline": map[string]interface{}{
					"senders": []string{"not_a_sender_id"},
				},
			},
		},

		// Top-level Filter fields.
		{"event_format": 1},
		{"event_format": "not_a_format"},
		{"event_fields": NAL},
		{"event_fields": []int{1}},
		{"account_data": NAO},
		{
			"presence": map[string]interface{}{
				"types": NAL,
			},
		},
		{
			"account_data": map[string]interface{}{
				"limit": "not_an_int",
			},
		},

		// RoomFilter fields.
		{
			"room": map[string]interface{}{
				"rooms": NAL,
			},
		},
		{
			"room": map[string]interface{}{
				"not_rooms": NAL,
			},
		},
		{
			"room": map[string]interface{}{
				"include_leave": "not_a_bool",
			},
		},

		// RoomEventFilter fields.
		{
			"room": map[string]interface{}{
				"timeline": map[string]interface{}{
					"limit": "not_an_int",
				},
			},
		},
		{
			"room": map[string]interface{}{
				"timeline": map[string]interface{}{
					"contains_url": "not_a_bool",
				},
			},
		},
		{
			"room": map[string]interface{}{
				"state": map[string]interface{}{
					"lazy_load_members": "not_a_bool",
				},
			},
		},
		{
			"room": map[string]interface{}{
				"state": map[string]interface{}{
					"include_redundant_members": "not_a_bool",
				},
			},
		},
	}
}

// filterCase is an invalid filter, optionally skipped on homeservers with a known bug.
type filterCase struct {
	filter map[string]interface{}
	skipOn []string
}

// getKnownBugFilters returns invalid filters that some homeservers mishandle.
// These are lost coverage on the skipped homeservers, not passing checks.
func getKnownBugFilters() []filterCase {
	return []filterCase{
		{
			// FIXME: Synapse clamps the timeline limit (set_timeline_upper_limit)
			// before validating the filter, so a string limit raises a TypeError
			// and returns 500 M_UNKNOWN instead of 400. Remove the skip once Synapse
			// validates first. TODO: link the upstream Synapse issue.
			filter: map[string]interface{}{
				"room": map[string]interface{}{
					"timeline": map[string]interface{}{
						"limit": "not_an_int",
					},
				},
			},
			skipOn: []string{runtime.Synapse},
		},
	}
}

// sytest: Check creating invalid filters returns 4xx
func TestFilter(t *testing.T) {
	runtime.SkipIf(t, runtime.Dendrite) // FIXME: https://github.com/matrix-org/dendrite/issues/2067

	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)
	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})

	var cases []filterCase
	for _, filter := range getFilters() {
		cases = append(cases, filterCase{filter: filter})
	}
	cases = append(cases, getKnownBugFilters()...)

	for _, tc := range cases {
		filter := tc.filter
		filterJSON, err := json.Marshal(filter)
		if err != nil {
			t.Fatalf("failed to marshal filter: %s", err)
		}
		t.Run(string(filterJSON), func(t *testing.T) {
			if len(tc.skipOn) > 0 {
				runtime.SkipIf(t, tc.skipOn...)
			}
			res := alice.Do(t, "POST", []string{"_matrix", "client", "v3", "user", alice.UserID, "filter"}, client.WithJSONBody(t, filter))
			body := must.MatchResponse(t, res, match.HTTPResponse{
				StatusCode: 400,
			})
			var response struct {
				ErrCode string `json:"errcode"`
			}
			if err := json.Unmarshal(body, &response); err != nil {
				t.Fatalf("failed to decode filter error response: %s", err)
			}
			if response.ErrCode != "M_BAD_JSON" && response.ErrCode != "M_UNKNOWN" {
				t.Fatalf("unexpected filter error code %q, want M_BAD_JSON or M_UNKNOWN", response.ErrCode)
			}
		})
	}
}

// sytest: Event size limits
func TestEvent(t *testing.T) {
	// Venator: does not support room version 6 (>=v10 only)
	runtime.SkipIf(t, runtime.Venator)
	deployment := complement.Deploy(t, 1)
	defer deployment.Destroy(t)
	alice := deployment.Register(t, "hs1", helpers.RegistrationOpts{})
	roomID := alice.MustCreateRoom(t, map[string]interface{}{
		"room_opts": map[string]interface{}{
			"room_version": "6",
		},
	})

	t.Run("Parallel", func(t *testing.T) {
		t.Run("Large Event", func(t *testing.T) {
			t.Parallel()

			event := map[string]interface{}{
				"msgtype": "m.text",
				"body":    strings.Repeat("and they dont stop coming ", 2700), // 2700 * 26 == 70200
			}

			res := alice.Do(t, "PUT", []string{"_matrix", "client", "v3", "rooms", roomID, "send", "m.room.message", "1"}, client.WithJSONBody(t, event))

			must.MatchResponse(t, res, match.HTTPResponse{
				StatusCode: 413,
			})
		})

		t.Run("Large State Event", func(t *testing.T) {
			t.Parallel()

			stateEvent := map[string]interface{}{
				"body": strings.Repeat("Dormammu, I've Come To Bargain.\n", 2200), // 2200 * 32 == 70400
			}

			res := alice.Do(t, "PUT", []string{"_matrix", "client", "v3", "rooms", roomID, "state", "marvel.universe.fate"}, client.WithJSONBody(t, stateEvent))

			must.MatchResponse(t, res, match.HTTPResponse{
				StatusCode: 413,
			})
		})
	})
}
