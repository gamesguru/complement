// Package bisect is the reference model of the MSC4521 DAG-bisection
// contract: how two peers, each exposing either a total or an authenticated
// partial view of a room, locate the earliest omitted or conflicting item.
//
// It pins the low-level contract only. The hs1/hs2 tests in
// tests/msc4521/active_edu_recon cover the separate digest/strata/room_diff
// API, not DAG bisection. A possible future wire format is described in
// tests/msc4521/DAG_BISECTION_API.md.
package bisect

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ViewKind says whether a peer claims to expose the whole room or a window.
type ViewKind string

const (
	ViewTotal   ViewKind = "total"
	ViewPartial ViewKind = "partial"
)

// Coverage is a peer's authenticated statement of what it is claiming to
// expose. Anything outside [FloorDepth, CeilingDepth] is "not claimed", which
// is distinct from "omitted". A total view has no bounds. Verified reports that
// the statement's signature and anchors were checked; unverified coverage is
// refused rather than reconciled (fail closed).
type Coverage struct {
	Kind            ViewKind
	FloorDepth      int64
	CeilingDepth    int64
	FloorEventIDs   []string
	CeilingEventIDs []string
	Verified        bool
}

// StateKey identifies a state slot; two state events with the same StateKey but
// different event IDs conflict.
type StateKey struct {
	Type string
	Key  string
}

// Item is one event in a peer's view.
type Item struct {
	EventID string
	Depth   int64
	Parents []string
	State   *StateKey // nil for non-state events
}

// Peer is one side of the exchange.
type Peer struct {
	Coverage Coverage
	Items    []Item
}

type DivergenceKind string

const (
	// MissingLocal: only the remote peer has the item.
	MissingLocal DivergenceKind = "missing_local"
	// MissingRemote: only the local peer has the item.
	MissingRemote DivergenceKind = "missing_remote"
	// Conflict: both have the position, with different event IDs.
	Conflict DivergenceKind = "conflict"
)

type Divergence struct {
	Kind          DivergenceKind
	Depth         int64
	LocalEventID  string
	RemoteEventID string
	State         *StateKey
}

var (
	ErrUnverifiableView = errors.New("bisect: coverage is not authenticated")
	ErrMalformed        = errors.New("bisect: malformed item")
	ErrNoOverlap        = errors.New("bisect: peers' coverage does not overlap")
)

// Result carries the earliest divergence (nil if the windows agree) and the
// number of digest comparisons used, so tests can assert logarithmic cost.
type Result struct {
	First  *Divergence
	Rounds int
}

type entry struct {
	pos  string
	item Item
}

// positionKey names the slot an item occupies: its state slot, or for plain
// events its depth plus parent set.
func positionKey(it Item) string {
	if it.State != nil {
		return "s\x00" + it.State.Type + "\x00" + it.State.Key
	}
	parents := append([]string(nil), it.Parents...)
	sort.Strings(parents)
	return "e\x00" + strconv.FormatInt(it.Depth, 10) + "\x00" + strings.Join(parents, ",")
}

func window(local, remote Coverage) (lo, hi int64, err error) {
	lo, hi = int64(0), int64(1)<<62
	for _, c := range []Coverage{local, remote} {
		if !c.Verified {
			return 0, 0, ErrUnverifiableView
		}
		if c.Kind == ViewPartial {
			if c.FloorDepth > lo {
				lo = c.FloorDepth
			}
			if c.CeilingDepth < hi {
				hi = c.CeilingDepth
			}
		}
	}
	if lo > hi {
		return 0, 0, ErrNoOverlap
	}
	return lo, hi, nil
}

func index(p Peer, lo, hi int64) (map[int64][]entry, error) {
	out := map[int64][]entry{}
	seen := map[string]string{}
	for _, it := range p.Items {
		if it.EventID == "" || it.Depth < 0 {
			return nil, fmt.Errorf("%w: %+v", ErrMalformed, it)
		}
		if it.Depth < lo || it.Depth > hi {
			continue
		}
		pos := positionKey(it)
		if prev, dup := seen[pos]; dup && prev != it.EventID {
			return nil, fmt.Errorf("%w: peer holds two events at one position: %s, %s", ErrMalformed, prev, it.EventID)
		}
		if _, dup := seen[pos]; dup {
			continue
		}
		seen[pos] = it.EventID
		out[it.Depth] = append(out[it.Depth], entry{pos, it})
	}
	return out, nil
}

// digest is an order-independent XOR of per-entry hashes over a depth range.
func digest(idx map[int64][]entry, lo, hi int64) (d [16]byte, count int) {
	for depth, es := range idx {
		if depth < lo || depth > hi {
			continue
		}
		for _, e := range es {
			h := sha256.Sum256([]byte(e.pos + "\x00\x00" + e.item.EventID))
			for i := range d {
				d[i] ^= h[i]
			}
			count++
		}
	}
	return d, count
}

// First finds the earliest divergence inside the intersection of both peers'
// coverage by bisecting on depth, descending only into the earlier mismatching
// half.
func First(local, remote Peer) (Result, error) {
	lo, hi, err := window(local.Coverage, remote.Coverage)
	if err != nil {
		return Result{}, err
	}
	li, err := index(local, lo, hi)
	if err != nil {
		return Result{}, err
	}
	ri, err := index(remote, lo, hi)
	if err != nil {
		return Result{}, err
	}
	// Clamp to the depths actually present so bisection is O(log depth).
	var maxDepth int64 = -1
	for _, m := range []map[int64][]entry{li, ri} {
		for d := range m {
			if d > maxDepth {
				maxDepth = d
			}
		}
	}
	if maxDepth < lo {
		return Result{}, nil
	}
	hi = maxDepth

	res := Result{}
	for lo < hi {
		mid := lo + (hi-lo)/2
		ld, lc := digest(li, lo, mid)
		rd, rc := digest(ri, lo, mid)
		res.Rounds++
		if ld != rd || lc != rc {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	// lo == hi: compare the final depth slot. If the earlier half matched and
	// this slot also matches, there is no divergence.
	ld, lc := digest(li, lo, lo)
	rd, rc := digest(ri, lo, lo)
	res.Rounds++
	if ld == rd && lc == rc {
		return res, nil
	}
	res.First = leaf(li[lo], ri[lo], lo)
	return res, nil
}

func leaf(l, r []entry, depth int64) *Divergence {
	lm, rm := map[string]Item{}, map[string]Item{}
	var keys []string
	for _, e := range l {
		lm[e.pos] = e.item
		keys = append(keys, e.pos)
	}
	for _, e := range r {
		rm[e.pos] = e.item
		keys = append(keys, e.pos)
	}
	sort.Strings(keys)
	for _, k := range keys {
		li, lok := lm[k]
		ri, rok := rm[k]
		switch {
		case lok && rok && li.EventID != ri.EventID:
			return &Divergence{Conflict, depth, li.EventID, ri.EventID, li.State}
		case lok && !rok:
			return &Divergence{MissingRemote, depth, li.EventID, "", li.State}
		case !lok && rok:
			return &Divergence{MissingLocal, depth, "", ri.EventID, ri.State}
		}
	}
	return nil
}
