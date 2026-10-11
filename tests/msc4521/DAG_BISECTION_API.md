# MSC4521 DAG bisection API (draft, test-side contract)

Companion to the digest/strata/`room_diff` flow under
`/_matrix/federation/unstable/tk.nutra.msc0501/`. Reference model:
`tests/msc4521/bisect`. This is a test-side draft for a possible future
endpoint; no homeserver bisection API is currently specified or tested. The
hs1/hs2 tests in `tests/msc4521/active_edu_recon` cover the existing
digest/strata/`room_diff` API only.

## Endpoint

`POST /_matrix/federation/unstable/tk.nutra.msc0501/room_bisect/{roomID}`

### Request

```json
{
  "frame_id": "...",
  "digest_type": "algebraic_v1",
  "view": {
    "kind": "total | partial",
    "floor_depth": 10,
    "ceiling_depth": 50,
    "floor_event_ids": ["$..."],
    "ceiling_event_ids": ["$..."],
    "signatures": {"<server>": {"ed25519:key": "<sig over canonical JSON of view+frame_id>"}}
  },
  "range": {"lo": 10, "hi": 50},
  "scope": "events | state"
}
```

`total` views omit the bounds and anchors. `partial` views MUST carry floor and
ceiling depth plus anchor event IDs and a signature by the sending server, so
"not claimed" is distinguishable from "omitted".

### Response

```json
{
  "frame_id": "...",
  "view": { "...same shape, signed by the responder..." },
  "range": {"lo": 10, "hi": 50},
  "digest": "<algebraic_v1 over entries in range>",
  "count": 41,
  "children": [ {"lo":10,"hi":30,"digest":"...","count":21}, {"lo":31,"hi":50,"digest":"...","count":20} ],
  "leaf": [ {"depth": 12, "position": "...", "event_id": "$..."} ]
}
```

`children` is present while `lo < hi`; `leaf` lists entries when `lo == hi`.

## Semantics

- **Window**: the intersection of both views. Anything outside is never a
  divergence. Disjoint windows -> `M_NO_OVERLAP`.
- **Position**: state events occupy `(type, state_key)`; other events occupy
  `(depth, sorted parent IDs)`.
- **Entry digest**: order-independent XOR of `H(position || event_id)`.
- **Search**: compare range digests, descend into the earlier mismatching half
  (O(log depth) rounds), compare leaf entries.
- **Result kinds**: `missing_local` (only remote has it), `missing_remote`
  (only local has it), `conflict` (same position, different event ID).
- **Fail closed**: unsigned/unverifiable `view` -> `M_UNVERIFIABLE_VIEW`;
  empty event ID, or two events at one position within one view ->
  `M_BAD_JSON`. Never reconciled around.
