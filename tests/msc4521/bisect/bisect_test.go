package bisect

import (
	"errors"
	"fmt"
	"testing"

	"github.com/matrix-org/complement/must"
)

const chainLen = 64

func ev(depth int64, id string, state *StateKey) Item {
	parent := fmt.Sprintf("$e%d", depth-1)
	return Item{EventID: id, Depth: depth, Parents: []string{parent}, State: state}
}

// chain builds a linear DAG where every 7th event is a state event.
func chain() []Item {
	var items []Item
	for d := int64(1); d <= chainLen; d++ {
		var sk *StateKey
		if d%7 == 0 {
			sk = &StateKey{Type: "m.room.topic", Key: fmt.Sprintf("k%d", d)}
		}
		items = append(items, ev(d, fmt.Sprintf("$e%d", d), sk))
	}
	return items
}

func cov(kind ViewKind, floor, ceil int64) Coverage {
	return Coverage{Kind: kind, FloorDepth: floor, CeilingDepth: ceil, Verified: true}
}

func without(items []Item, depth int64) []Item {
	var out []Item
	for _, it := range items {
		if it.Depth != depth {
			out = append(out, it)
		}
	}
	return out
}

func replaced(items []Item, depth int64) []Item {
	out := append([]Item(nil), items...)
	for i := range out {
		if out[i].Depth == depth {
			out[i].EventID += "-forked"
		}
	}
	return out
}

func TestDAGBisectionMatrix(t *testing.T) {
	pairs := []struct {
		name          string
		local, remote ViewKind
	}{
		{"TotalTotal", ViewTotal, ViewTotal},
		{"TotalPartial", ViewTotal, ViewPartial},
		{"PartialTotal", ViewPartial, ViewTotal},
		{"PartialPartial", ViewPartial, ViewPartial},
	}
	// Divergence depths: beginning, middle, end. Partial windows are [10,50]
	// so beginning/end are only visible to total/total; for others they must
	// be ignored as "not claimed", never reported.
	positions := []struct {
		name  string
		depth int64
	}{{"Begin", 12}, {"Middle", 28}, {"End", 49}}
	diffs := []struct {
		name  string
		state bool // pick a state-event depth (multiple of 7) when true
		kind  DivergenceKind
	}{
		{"EventOmission", false, MissingRemote},
		{"StateOmission", true, MissingRemote},
		{"EventConflict", false, Conflict},
		{"StateConflict", true, Conflict},
	}

	for _, pair := range pairs {
		t.Run(pair.name, func(t *testing.T) {
			for _, d := range diffs {
				t.Run(d.name, func(t *testing.T) {
					for _, p := range positions {
						t.Run(p.name, func(t *testing.T) {
							depth := p.depth
							if d.state {
								depth = (depth + 6) / 7 * 7 // snap up to a state slot
							}
							base := chain()
							remoteItems := base
							if d.kind == Conflict {
								remoteItems = replaced(base, depth)
							} else {
								remoteItems = without(base, depth)
							}
							local := Peer{Coverage: cov(pair.local, 10, 50), Items: base}
							remote := Peer{Coverage: cov(pair.remote, 10, 50), Items: remoteItems}
							if pair.local == ViewTotal {
								local.Coverage = Coverage{Kind: ViewTotal, Verified: true}
							}
							if pair.remote == ViewTotal {
								remote.Coverage = Coverage{Kind: ViewTotal, Verified: true}
							}
							res, err := First(local, remote)
							must.NotError(t, "First", err)
							must.Equal(t, res.First != nil, true, "divergence found")
							must.Equal(t, res.First.Kind, d.kind, "direction")
							must.Equal(t, res.First.Depth, depth, "earliest depth")
							must.Equal(t, res.Rounds <= 8, true, "logarithmic rounds")
						})
					}
				})
			}
		})
	}
}

func TestDivergenceOutsidePartialViewIsNotReported(t *testing.T) {
	base := chain()
	local := Peer{Coverage: Coverage{Kind: ViewTotal, Verified: true}, Items: base}
	remote := Peer{Coverage: cov(ViewPartial, 20, 40), Items: without(base, 3)}
	res, err := First(local, remote)
	must.NotError(t, "First", err)
	must.Equal(t, res.First == nil, true, "omission below the remote's floor is not a divergence")

	remote.Items = without(base, 60)
	res, err = First(local, remote)
	must.NotError(t, "First", err)
	must.Equal(t, res.First == nil, true, "omission above the remote's ceiling is not a divergence")
}

func TestMatchingViewsNoFalsePositive(t *testing.T) {
	for _, k := range []ViewKind{ViewTotal, ViewPartial} {
		c := Coverage{Kind: k, FloorDepth: 5, CeilingDepth: 30, Verified: true}
		res, err := First(Peer{c, chain()}, Peer{c, chain()})
		must.NotError(t, "First", err)
		must.Equal(t, res.First == nil, true, "identical views")
	}
}

func TestDepthBoundaryAndNormalizedPositions(t *testing.T) {
	t.Run("DepthZeroDivergence", func(t *testing.T) {
		local := Item{EventID: "$local", Depth: 0, Parents: []string{"$p2", "$p1"}}
		remote := Item{EventID: "$remote", Depth: 0, Parents: []string{"$p1", "$p2"}}
		res, err := First(
			Peer{Coverage{Kind: ViewTotal, Verified: true}, []Item{local}},
			Peer{Coverage{Kind: ViewTotal, Verified: true}, []Item{remote}},
		)
		must.NotError(t, "First", err)
		must.Equal(t, res.First != nil, true, "depth-zero divergence found")
		must.Equal(t, res.First.Depth, int64(0), "boundary depth")
		must.Equal(t, res.First.Kind, Conflict, "same position with different IDs is a conflict")
	})

	t.Run("ParentOrderAndDuplicateItems", func(t *testing.T) {
		first := Item{EventID: "$same", Depth: 4, Parents: []string{"$b", "$a"}}
		second := Item{EventID: "$same", Depth: 4, Parents: []string{"$a", "$b"}}
		coverage := Coverage{Kind: ViewTotal, Verified: true}
		res, err := First(
			Peer{coverage, []Item{first, first}},
			Peer{coverage, []Item{second}},
		)
		must.NotError(t, "First", err)
		must.Equal(t, res.First == nil, true, "parent order is irrelevant and an identical duplicate is idempotent")
	})

	t.Run("SingleDepthPartialWindow", func(t *testing.T) {
		coverage := cov(ViewPartial, 7, 7)
		local := Peer{coverage, []Item{ev(7, "$local", nil)}}
		remote := Peer{coverage, []Item{ev(7, "$remote", nil)}}
		res, err := First(local, remote)
		must.NotError(t, "First", err)
		must.Equal(t, res.First != nil, true, "inclusive one-depth window is examined")
		must.Equal(t, res.First.Depth, int64(7), "single-depth window boundary")
	})
}

func TestEmptyViewsAgree(t *testing.T) {
	coverage := cov(ViewPartial, 10, 50)
	res, err := First(Peer{Coverage: coverage}, Peer{Coverage: coverage})
	must.NotError(t, "First", err)
	must.Equal(t, res.First == nil, true, "empty views have no divergence")
	must.Equal(t, res.Rounds, 0, "empty views require no digest rounds")
}

func TestLeafWithoutDifferenceReturnsNil(t *testing.T) {
	item := Item{EventID: "$same", Depth: 3}
	entries := []entry{{pos: positionKey(item), item: item}}
	must.Equal(t, leaf(entries, entries, 3) == nil, true, "matching leaf entries have no divergence")
}

func TestEarliestOfMultipleDivergences(t *testing.T) {
	base := chain()
	remote := without(without(replaced(base, 40), 33), 18)
	res, err := First(
		Peer{Coverage{Kind: ViewTotal, Verified: true}, base},
		Peer{Coverage{Kind: ViewTotal, Verified: true}, remote})
	must.NotError(t, "First", err)
	must.Equal(t, res.First.Depth, int64(18), "earliest wins")
}

func TestMissingLocalDirection(t *testing.T) {
	base := chain()
	res, err := First(
		Peer{Coverage{Kind: ViewTotal, Verified: true}, without(base, 9)},
		Peer{Coverage{Kind: ViewTotal, Verified: true}, base})
	must.NotError(t, "First", err)
	must.Equal(t, res.First.Kind, MissingLocal, "remote-only item")
}

func TestDAGBisectionUnitSpecResultPayloadsAndPositions(t *testing.T) {
	total := Coverage{Kind: ViewTotal, Verified: true}
	t.Run("MissingRemoteEvent", func(t *testing.T) {
		local := Item{EventID: "$local", Depth: 12, Parents: []string{"$parent"}}
		res, err := First(Peer{total, []Item{local}}, Peer{total, nil})
		must.NotError(t, "First", err)
		must.Equal(t, res.First.Kind, MissingRemote, "local-only item kind")
		must.Equal(t, res.First.Depth, int64(12), "local-only item depth")
		must.Equal(t, res.First.LocalEventID, "$local", "local-only event ID")
		must.Equal(t, res.First.RemoteEventID, "", "missing remote event ID")
		must.Equal(t, res.First.State == nil, true, "ordinary event has no state key")
	})

	t.Run("MissingLocalEvent", func(t *testing.T) {
		remote := Item{EventID: "$remote", Depth: 12, Parents: []string{"$parent"}}
		res, err := First(Peer{total, nil}, Peer{total, []Item{remote}})
		must.NotError(t, "First", err)
		must.Equal(t, res.First.Kind, MissingLocal, "remote-only item kind")
		must.Equal(t, res.First.Depth, int64(12), "remote-only item depth")
		must.Equal(t, res.First.LocalEventID, "", "missing local event ID")
		must.Equal(t, res.First.RemoteEventID, "$remote", "remote-only event ID")
		must.Equal(t, res.First.State == nil, true, "ordinary event has no state key")
	})

	t.Run("StateConflict", func(t *testing.T) {
		state := &StateKey{Type: "m.room.topic", Key: ""}
		local := Item{EventID: "$old", Depth: 12, State: state}
		remote := Item{EventID: "$new", Depth: 12, State: state}
		res, err := First(Peer{total, []Item{local}}, Peer{total, []Item{remote}})
		must.NotError(t, "First", err)
		must.Equal(t, res.First.Kind, Conflict, "state slot conflict kind")
		must.Equal(t, res.First.LocalEventID, "$old", "state conflict local ID")
		must.Equal(t, res.First.RemoteEventID, "$new", "state conflict remote ID")
		if res.First.State == nil || *res.First.State != *state {
			t.Fatalf("state conflict key = %#v, want %#v", res.First.State, state)
		}
	})

	t.Run("EventParentSetDefinesPosition", func(t *testing.T) {
		local := Item{EventID: "$local", Depth: 12, Parents: []string{"$p2", "$p1"}}
		remote := Item{EventID: "$remote", Depth: 12, Parents: []string{"$p3"}}
		res, err := First(Peer{total, []Item{local}}, Peer{total, []Item{remote}})
		must.NotError(t, "First", err)
		must.Equal(t, res.First.Kind, MissingRemote, "different parent sets are different positions")
		must.Equal(t, res.First.LocalEventID, "$local", "first sorted position belongs to local")
	})
}

func TestFailsClosed(t *testing.T) {
	total := Coverage{Kind: ViewTotal, Verified: true}
	t.Run("UnverifiedCoverage", func(t *testing.T) {
		bad := cov(ViewPartial, 1, 10)
		bad.Verified = false
		_, err := First(Peer{total, chain()}, Peer{bad, chain()})
		must.Equal(t, errors.Is(err, ErrUnverifiableView), true, "unverifiable view")
	})
	t.Run("EmptyEventID", func(t *testing.T) {
		_, err := First(Peer{total, []Item{{Depth: 1}}}, Peer{total, chain()})
		must.Equal(t, errors.Is(err, ErrMalformed), true, "malformed item")
	})
	t.Run("MalformedRemoteItem", func(t *testing.T) {
		_, err := First(Peer{total, chain()}, Peer{total, []Item{{Depth: 1}}})
		must.Equal(t, errors.Is(err, ErrMalformed), true, "malformed remote item")
	})
	t.Run("NegativeDepth", func(t *testing.T) {
		_, err := First(Peer{total, []Item{{EventID: "$negative", Depth: -1}}}, Peer{total, chain()})
		must.Equal(t, errors.Is(err, ErrMalformed), true, "negative depth is malformed")
	})
	t.Run("TwoEventsAtOneStateSlot", func(t *testing.T) {
		sk := &StateKey{Type: "m.room.topic"}
		items := []Item{ev(1, "$a", sk), ev(2, "$b", sk)}
		_, err := First(Peer{total, items}, Peer{total, chain()})
		must.Equal(t, errors.Is(err, ErrMalformed), true, "ambiguous state slot")
	})
	t.Run("DisjointPartialWindows", func(t *testing.T) {
		_, err := First(Peer{cov(ViewPartial, 1, 5), chain()}, Peer{cov(ViewPartial, 20, 30), chain()})
		must.Equal(t, errors.Is(err, ErrNoOverlap), true, "no overlap")
	})
}
