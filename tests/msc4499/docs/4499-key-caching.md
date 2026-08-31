# MSC4499: Strict server signing key caching and key ID uniqueness

Because the specification lacks a strict caching contract, new homeserver
implementations often attempt to be "helpful." Without explicit guidance,
developers may design flexible caches that store multiple key bodies for a
single key ID and perform verification either with the most recently observed
key (last-wins) or the first one which works (trial verification).

While existing implementations such as Synapse effectively enforce a unique
`(server_name, key_id)` constraint at the storage layer, this only guarantees
one stored row per key ID, not which key body wins when a new observation
conflicts with an existing one: Synapse's storage layer resolves such conflicts
by last-write-wins (an upsert keyed on `(server_name, key_id)`), the opposite of
the First Seen Wins rule this MSC introduces. The protocol itself remains
underspecified and does not give clear guidance on this matter.

This ambiguity allows key collisions to cause room state divergence between
servers, and introduces undefined behavior when attempting to handle them via
trial verification.

This MSC standardizes signing key caching requirements, introduces a strict
**First Seen Wins** rule for key IDs, and lays the groundwork for future work.

This proposal deliberately rejects trial verification in favor of deterministic
binding, even though that causes more visible failures when a server publishes
conflicting material. Deterministic failure is preferable to receiver-specific
verification behavior.

## Proposal

### Relationship to existing specification

This MSC strengthens and supersedes the existing key caching and verification
rules defined in the Matrix specification (specifically the
[Server-Server API § Retrieving server keys](https://spec.matrix.org/v1.18/server-server-api/#retrieving-server-keys)
and the notary query endpoint). In particular, this proposal upgrades the
existing `SHOULD` caching guidance to `MUST`, formalizes the `valid_until_ts`
7-day validity clamp as a cache constraint, and replaces ambiguous logic with a
strict 1:1 key ID uniqueness paradigm and accompanying caching guidance.

### Scope

This MSC governs the caching and verification of _remote_ server signing keys
obtained through federation — `/_matrix/key/v2/server` responses and notary
(`/_matrix/key/v2/query`) responses used to verify PDUs signed by other servers.
It does not impose new requirements on rooms created with `m.federate: false`:
such rooms never exchange PDUs with other servers, so no peer ever needs to
fetch, cache, or corroborate a signing key on their account, and the First Seen
Wins rule, corroboration tiers, and digest-binding cap defined below have no
federated key material to act on. A room whose `m.federate: false` restriction
is not honored (for example, its events leak to peers) is subject to this MSC
from that point onward like any other federated room.

### Key caching requirements

Servers MUST cache federated server signing keys procured from
`/_matrix/key/v2/server` responses and `/_matrix/key/v2/query` notary responses.
The following requirements apply to all signing algorithm types (`ed25519`, and
any potential future signing algorithms defined by later proposals).

<!-- Read marker. -->

**Cache refresh lifetime.** Servers MUST cache key responses and SHOULD
proactively refresh cached keys before their clamped `valid_until_ts` expiry
(restricted to _at most_ 7 days from fetch) to avoid verification failures
during key rotation windows.

**Refresh on identical body.** When a server re-fetches a key and receives the
exact same key body it already has, this is a normal refresh; the server MUST
simply update its cached `valid_until_ts`.

**First `expired_ts` assignment.** A re-fetch is also the ordinary way a key
body moves from `verify_keys` to `old_verify_keys` and thereby carries an
`expired_ts` for the first time: that first-ever `expired_ts` for the binding
MUST be recorded, since a binding with no recorded retirement has no upper bound
for historical verification. What servers MUST NOT do is replace an `expired_ts`
that a prior observation already assigned to that binding — a second, different
`expired_ts` value arriving later MUST be rejected, not the first one. See
[Historical event verification](#historical-event-verification) for the full
first-assignment-wins rule.

**Rely on cache.** Servers MUST rely on their cache. They MUST NOT fetch origin
keys for every inbound message or request if a valid key is already cached
locally.

**Negative caching and backoff.** Servers MUST cache fetch failures. A dead or
unreachable remote server can cause fetch storms if every inbound event or
reference triggers a fresh network request. Servers MUST implement exponential
backoff (e.g., starting at 1 minute, capping at 1 hour) per remote server for
failed key fetches. Inbound federation demand whose authentication _requires_ a
key fetch for a backoff-listed server SHOULD permit at most one immediate
(rate-limited) fetch attempt per remote server per backoff interval, where the
rate limit MUST NOT be looser than the current backoff interval itself (i.e.
this escape valve MUST NOT be used to reconstruct a fetch frequency above what
the backoff schedule already allows); all further demand arriving within that
interval MUST fail fast against the negative cache rather than triggering its
own probe. Without this per-interval limit, an attacker can relay junk
purportedly signed by a dead server's name to induce one outbound probe per
inbound request, defeating the backoff entirely.

<!-- synapse-derived: complement coverage currently exercises this behavior
against Synapse in TestMSC4499Key/FetchCoalescing -->

**Fetch coalescing.** When multiple local codepaths concurrently need key
material for the same remote server, implementations SHOULD coalesce them into a
single active fetch attempt for that server: at any given time, there SHOULD be
at most one in-flight outbound key-fetch HTTP transaction per remote
`server_name`, and all concurrent waiters for that same fetch SHOULD observe the
same terminal result (success, malformed response rejection, or transport/notary
failure) rather than each spawning its own retry sequence. Once that shared
attempt completes, any later fetch is governed normally by the resulting cache
state and backoff state; coalescing is only a duplicate-suppression rule for
overlapping local demand, not a bypass around the negative-cache policy above.

<!-- /synapse-derived -->

The coalescing key above is per target `server_name`, but that does not compose
cleanly with notary batching: a single `/_matrix/key/v2/query` transaction can
cover many target server names at once, so "one in-flight fetch per
`server_name`" and "one in-flight notary transaction" are different units when a
notary is involved. Implementations that coalesce MUST key on the pair (target
`server_name`, whether resolution is proceeding via direct fetch or via a
specific notary), so that a single outstanding notary batch transaction
satisfies the coalescing rule for every server name it covers, rather than being
bypassed by concurrent per-name coalescing keyed on direct fetch alone.

When a shared coalesced attempt fails, that failure MUST count as exactly one
increment toward the exponential backoff state for that remote server,
regardless of how many local waiters were coalesced onto it. Naively applying
the backoff increment once per waiter turns coalescing into a backoff bypass — N
waiters coalesced onto one failed fetch would otherwise advance the backoff
state as if N separate fetch attempts had failed.

If that fetch succeeds and the request authenticates, servers SHOULD clear the
backoff state.

This direct-over-notary preference complements earlier federation transport and
discovery work such as
[MSC1711: X.509 certificate verification for federation connections](https://github.com/matrix-org/matrix-spec-proposals/pull/1711),
[MSC1708: `.well-known` support for server name resolution](https://github.com/matrix-org/matrix-spec-proposals/pull/1708),
and
[MSC1831: SRV lookups after `.well-known`](https://github.com/matrix-org/matrix-spec-proposals/pull/1831).
Those proposals aim to make direct origin-domain verification over TLS more
robust and deployable. This MSC does not require them to merge, but it
intentionally assigns higher evidentiary weight to a direct origin fetch over
validated TLS than to a relayed notary response.

Implementations SHOULD allow the minimum backoff floor to be shortened or
otherwise overridden (e.g. via a test-only configuration hook) in test
configurations, so conformance tests do not need to sleep for a full minute in
order to observe backoff being enforced and later cleared.

**Cache persistence.** Permanent key-ID-to-key-body bindings MUST be persisted
to durable storage (e.g., database) or an equivalent crash-recovery journal;
memory-only storage is insufficient for First Seen Wins. Freshness metadata such
as `valid_until_ts`, retry state, and other cache-management fields may be
stored separately, but a server restart MUST NOT discard the immutable
identity-binding record or require re-fetching every remote server's keys from
the network before it can continue enforcing existing bindings.

**Active key ceiling.** A single server-key response MUST NOT contain more than
50 active keys in `verify_keys`. Such a payload MUST be rejected as malformed.
Large historical key sets belong in `old_verify_keys`.

**Retired key ceiling (per response).** A single server-key response MUST NOT
contain more than 3,000 entries in `old_verify_keys`. Such a payload MUST be
rejected as malformed. This mirrors the 3,000-entry storage ceiling defined
under [Storage considerations](#storage-considerations) so that a conformant
origin can always publish its full retainable retired-key set in one response,
and so that a receiving server can bound parsing and hashing cost before
allocating any database records, independent of the storage-layer eviction rule.

**Notary internal indexing.** Notary servers act as massive aggregation points
for federation keys. To prevent them from becoming distribution vectors for
collisions, notaries MUST also enforce the First Seen Wins rule internally.
However, to preserve a forensic trail of misconfigurations and anomalous event
rejections, notary implementations SHOULD internally index observed key bodies
by their full SHA-256 digest. This allows the notary to safely store historical
collisions without database constraint violations, even if it only serves the
"first seen" key via the active API. Because `/_matrix/key/v2/server` and
`/_matrix/key/v2/query` responses are self-signed by the origin over the entire
payload, a notary MUST NOT satisfy this by locally patching a colliding response
to substitute the first-seen key body: mutating `verify_keys` or
`old_verify_keys` invalidates the origin's `signatures` entry for that payload,
so a patched response fails verification for any downstream client checking the
origin's own signature, regardless of any additional signature the notary itself
appends. Implementations instead satisfy this requirement by declining to update
their served cache entry for that origin when a fetch contains a rejected
collision, continuing to serve the last self-signed payload consistent with the
bindings they actually accepted. Indexing by digest also accommodates wider or
post-quantum key formats where raw key bodies are significantly larger than
traditional public key fields. This forensic index is an implementation-private
log of rejected material; it is not part of the notary's served binding set and
is therefore outside the scope of the 3,000-key retention ceiling described
under [Storage considerations](#storage-considerations), which governs only the
bindings a notary actively serves. However, the forensic index MUST still be
bounded: implementations MUST either retain only bounded digest metadata
(origin, key ID, digest, timestamps, and reason for rejection), or enforce
explicit per-origin and global limits if they retain full rejected key bodies.

**Notary fallback (two-tier binding).** When a required signing key is not
present in the local cache, servers typically query a configured notary server
(`/_matrix/key/v2/query`). Because a notary is a relay, a direct fetch over
validated TLS to the actual server name (`/_matrix/key/v2/server`) provides
strictly stronger cryptographic proof of ownership.

To prevent a malicious or compromised notary from permanently calcifying a
poisoned key binding, bindings first observed via a notary are **provisional**.
They are used normally for verification, but if a subsequent _direct_ fetch from
the origin server yields a key body that conflicts with the provisional binding,
the direct fetch MUST override the provisional one, unless the provisional key
has already expired or been retired. The server updates its cache to the
direct-observed key body and MUST log the collision loudly. The server SHOULD
log which events (or at minimum which rooms/time window) were verified under the
displaced binding, and MAY re-verify recent events. Bindings observed directly
from the origin server are **permanent** (see below). Servers MUST NOT treat
notary unavailability as a verification success. A provisional binding MUST NOT
be overridden once that same provisional observation is no longer live for
promotion purposes on the receiving server, or if it was learned from
`old_verify_keys` with a past `expired_ts`. This liveness check is about the
provisional observation itself, not about any unrelated origin-wide cache
metadata: implementations that bound the promotion window MUST track that bound
per provisional binding, so that refreshing one key does not silently extend or
shorten another key's override window.

The two-tier rule applies only to the notary-versus-direct case. Direct-versus-
direct conflicts are always resolved by First Seen Wins. Notary-versus-notary
conflicts (or the same notary at two different times) are also resolved by First
Seen Wins among provisional observations. A freshness-driven re-fetch MUST NOT
become a side channel for overriding First Seen Wins: if a server queries a
notary with `minimum_valid_until_ts` to force an upstream refresh and the
notary's re-fetch of the origin yields key material for the same key ID that
conflicts with a binding the notary already holds, the notary MUST reject the
new key as a collision rather than serving it as an update. Symmetrically, from
the querying client's perspective, a notary response returned to satisfy
`minimum_valid_until_ts` is still an ordinary provisional observation subject to
the rules above; requesting fresher validity confers no override authority over
an existing binding.

<!-- synapse-derived: complement coverage currently exercises the core
promotion path against Synapse in TestMSC4499Key/BindingPromotion; the
remaining edge cases below this sentence aren't separately covered by that
test -->

**Binding promotion.** A provisional (notary-observed) binding becomes permanent
the first time a direct fetch from the origin confirms the same key body.

<!-- /synapse-derived -->

Servers SHOULD attempt a direct fetch after learning any binding via a notary,
to promote the binding and close the provisional window. This MSC does not
require a specific latency budget or that the current request path block on that
fetch: implementations MAY start it immediately, enqueue it on a short retry
queue, or otherwise trigger it soon after the notary-backed verification
succeeds. The interoperability requirement is only that implementations SHOULD
not leave provisional bindings unpromoted indefinitely merely because no later
demand happens to ask for that exact key ID again. Once permanent, the binding
is subject to the standard First Seen Wins rule: a later direct fetch presenting
a different key body for the same key ID is a collision and MUST be rejected and
logged.

### Key ID uniqueness requirement

A key ID (`algorithm:key_id`) MUST map to exactly one public key body for a
given remote server. This is a strict, permanent 1:1 binding. The purpose of a
key ID is to provide an unambiguous reference from a signature entry to a
specific cryptographic key; allowing multiple key bodies under the same ID
defeats this purpose.

**Permanent binding.** The cryptographic binding between a key ID and its public
key body is a **permanent record**, not a cache entry. This permanence governs
_key-body identity_ only; it does not alter the validity-window semantics (e.g.,
event signatures are still verified against the key's validity at the event's
`origin_server_ts`, and federation requests still require a currently valid
key). While `valid_until_ts` dictates when a server should refresh the
`/_matrix/key/v2/server` endpoint, the observed association between a key ID and
its key body MUST NOT be purged from the server's key database when
`valid_until_ts` expires. Purging this binding would leave the server naive to
future collisions and blindly accepting colliding key bodies.

**Collision detection.** If a server observes a key response (whether fetched
directly via `/_matrix/key/v2/server` or via a `/_matrix/key/v2/query` notary)
from a remote server where a key ID that was previously associated with public
key `A` is now associated with a different public key `B`, the receiving server:

1. **MUST retain the previously observed key.** The original key body remains
   authoritative for that key ID, unless the existing binding is provisional and
   the new observation is a direct fetch, in which case the two-tier override
   rule applies (see Notary fallback). In all other cases, the conflicting
   response MUST NOT replace it.
2. **SHOULD log the collision.** Servers SHOULD log the key ID collision at
   warning level, including the remote server name, the key ID, and the SHA-256
   fingerprints of both the cached and conflicting public keys. This alerts the
   operator to a potential misconfiguration or compromise on the remote server
   and aids in forensic reconciliation.
3. **MUST NOT perform trial verification.** The server MUST NOT cache multiple
   active key bodies under the same key ID and MUST NOT attempt multi-key trial
   verification. (Notaries may index rejected bodies for internal forensics as
   described above; see [Security considerations](#security-considerations)).

<!-- synapse-derived: complement coverage currently exercises this behavior
against Synapse in TestMSC4499Key/DuplicateJSONKeyRejection -->

**Intra-payload rejection.** A single key response payload MUST NOT contain
multiple different public key bodies for the same key ID (e.g., across
`verify_keys` and `old_verify_keys`, or duplicated within the same dictionary).

<!-- /synapse-derived -->
<!-- synapse-derived: complement coverage currently exercises this behavior
against Synapse in TestMSC4499Key/IdenticalCrossMapIsLegal -->

The same key body appearing under one key ID in both `verify_keys` and
`old_verify_keys` is legal.

<!-- /synapse-derived -->

If a receiving server detects a key ID collision within a single HTTP response,
the entire response MUST be rejected as malformed.

If a notary rejects an upstream key response as malformed, it MUST still return
HTTP 200 for the enclosing `/_matrix/key/v2/query` response, omit that response
from the `server_keys` array, and MAY continue serving other valid entries in
the batch. Consequently, an empty `server_keys` array in an otherwise-successful
`200` response is not authoritative absence: it does not mean the queried server
has no keys, only that the notary has nothing valid to serve for it right now. A
requester MUST cache this outcome and feed it into the negative-caching and
backoff rule above the same as any other failed resolution, since a notary with
nothing to serve for an origin is itself a failed resolution and otherwise the
fetch-storm protection above has a hole in it. A requester MUST NOT cache or
treat the same outcome as a **negative binding assertion** — i.e. it MUST NOT be
recorded as, or treated as equivalent to, a definitive statement that the server
has no signing keys, since that absence claim is never authoritative from a
notary. Furthermore, implementations MUST reject key response payloads
containing duplicate keys within a single JSON object, at any depth, anywhere in
the response document (not only within `verify_keys` or `old_verify_keys`). This
rejection applies to the raw received bytes before any canonicalization: the
Matrix specification's Canonical JSON appendix defines canonical form for JSON a
server itself produces, but per RFC 8259, JSON documents received over the wire
may legally contain duplicate object members with implementation-defined (and
commonly silently-deduplicating) parser behavior. A duplicate key ID across
`verify_keys` and `old_verify_keys` — or duplicated within the same dictionary —
is exactly this ambiguity, which is why it must be checked against the raw
response rather than assumed already illegal by the wire format.

<!-- synapse-derived: complement coverage currently exercises event-level
enforcement against Synapse in TestMSC4499Key/FirstSeenWinsEventPath -->

**First Seen Wins.** The collision detection rule follows a strict **First Seen
Wins** policy. The first public key body observed for a given
`(server_name, algorithm, key_id)` tuple (whether found in `verify_keys` or
`old_verify_keys`) is the permanent binding.

<!-- /synapse-derived -->

This rule becomes less relevant in the future, once key IDs are reduced to
collision-resistant canonical checksums of the key body (rather than
admin-supplied near arbitrary strings).

**Local impact.** The First Seen Wins rule causes a **localized DAG divergence**
for the misconfigured server: peers that cached the original key will reject new
events from the server (signature verification fails against the wrong key
body), while peers that never cached the original key will accept them. This is
an unavoidable consequence of out-of-band key resolution — different servers
observe different key states at different times. This MSC does not and _cannot_
eliminate this divergence, because key fetching is not part of the room DAG
mainline. What this MSC does is make the divergence **deterministic, documented,
and intentional**: it prioritizes strict cryptographic integrity over silently
corrupting historical verification. While this unavoidably leaves affected peers
with a split-brain view of the room (requiring manual cache eviction or state
resets to recover) if the origin server is not fixed, it creates an immediate,
visible failure that forces the misconfigured administrator to correct their
setup. Eliminating this collateral damage entirely requires a new room version
mandating Content-Addressed Key IDs, which is deferred to a future MSC (see
[Future considerations](#future-considerations)).

### Key rotation procedure

<!-- synapse-derived: complement coverage currently exercises this behavior
against Synapse in TestMSC4499Key/Rotation -->

When a server rotates its signing key, the administrator MUST:

1. **Generate a new key with a new, unique key ID.** For example, rotating from
   `ed25519:1` to `ed25519:2`, or from `ed25519:1` to `ed25519:a7B_93k`.
2. **Retire the old key.** The old key MUST appear in the `old_verify_keys`
   section of the `/_matrix/key/v2/server` response with an appropriate
   `expired_ts` timestamp.
3. **Publish the new key.** The new key appears in `verify_keys` with the new
   key ID.

<!-- /synapse-derived -->

The point of these examples is uniqueness against every previously used ID for
that server, not any particular ID format.

Reusing a key ID with a different key body is a **protocol violation**. This
most commonly occurs when an administrator wipes a server's database,
regenerates signing keys, but leaves the server configuration set to the same
key ID (e.g., the default `ed25519:auto`). This is not a hypothetical: Synapse
defaulted every new installation to the literal key ID `auto` until a 2016 fix
introduced a randomized suffix, and any deployment whose signing key file was
generated before then, or was later restored from a backup or template predating
the fix, still carries it today — a real, non-trivial population of servers in
current federation, not merely an illustrative example.

If this happens, administrators must rotate to a fresh key ID immediately. They
should further take efforts to correct membership or state drifts that occurred
during the period when an invalid, duplicated key was used to sign PDUs.

### Admin startup guardrails

Homeserver implementations SHOULD detect key ID reuse at startup. If the
server's configured signing key has a different key body than what was
previously persisted for that key ID, the server MUST refuse to start and emit a
clear error message instructing the administrator to either restore the original
key or assign a new key ID. This prevents the misconfiguration from propagating
to the federation in the first place. Implementations MAY also check configured
notaries for pre-existing keys under that ID at startup.

Because local startup guardrails cannot detect collisions if the server's
database has been entirely wiped (the most common cause of key ID reuse),
homeserver implementations SHOULD ensure that default key ID generation
incorporates a collision-resistant random component or a persisted uniqueness
mechanism alongside any timestamp (e.g., `ed25519:a7B_93k` rather than the
default `ed25519:auto` or `ed25519:1`). A timestamp alone is deterministic, not
probabilistic, and that is exactly the problem: it fails in a specific,
reproducible way rather than merely with low probability. A machine whose
persisted state was wiped typically also has its clock reset (e.g., to the
epoch, or to whatever a fresh install or restored snapshot sets it to), so key
regeneration after state loss is precisely the scenario most likely to reproduce
the same timestamp-derived key ID it used before. A random component protects
here because it does not depend on state that state loss also erases; a
structurally guaranteed fresh key ID requires persisted uniqueness state, or
randomness of sufficient width, in addition to any time component. This protects
against an administrator regenerating keys after a total state loss, and against
a new server owner unwittingly re-registering under a domain which formerly ran
a Conduit server.

This is the most effective mitigation because it eliminates the root cause: it
all but certainly stops the bad key from ever being published and sidesteps the
federation-wide collision detection and localized divergence entirely.

### Recovery from key loss

If a remote server has irrecoverably lost its private signing key (e.g.,
unrecoverable database failure without backup):

1. **The administrator MUST generate a new key with a new key ID.**
2. **If the public key material is still known** (e.g., from backups, logs, or
   cached by peers), the lost key SHOULD be published in `old_verify_keys` with
   `expired_ts` set to the approximate time of loss. Peers that never
   independently observed this key as active will treat the entry as
   **uncorroborated** (see [Storage considerations](#storage-considerations)):
   it is still retained for historical PDU verification, but sits at the bottom
   of the retention order under the eviction ceiling. A peer's binding becomes
   corroborated only through that peer's own prior observation of the key as
   active (for example, if its own notary fallback happened to relay this key
   while it was still genuinely active elsewhere, before the loss), or through
   an explicit local operator action grounded in independently verified evidence
   — never by asking a notary to vouch for the retirement after the fact, which
   no implementation may treat as corroboration.

<!-- synapse-derived: complement coverage currently exercises this
     behavior against Synapse in
     TestMSC4499Key/LostKeyPublicationHistoricalVerification/
     FullyLostKeyRemainsUnverifiableToColdPeers -->
<!-- /synapse-derived -->

3. **If the public key material is completely lost**, the administrator must
   accept that historical events signed by the lost key may fail verification on
   servers that never cached it. By design there is no protocol-level recovery
   for this scenario.

The protocol does not provide an automated recovery mechanism for key ID
collisions. The protocol deliberately surfaces misconfiguration as a
deterministic verification failure rather than introducing trial verification
fallbacks that mask key collisions.

**Manual cache eviction.** Because the First Seen Wins policy permanently binds
a key ID, a successful TOFU poisoning attack (or serious remote
misconfiguration) will result in permanent federation failure with that server.
To allow recovery, homeserver implementations MUST provide an administrative
mechanism (e.g., an admin API or CLI interface) to manually evict cached
key-body bindings for a specific remote server name, allowing a human operator
to break the binding and re-initiate TOFU.

This manual eviction MUST atomically remove or replace the retained digest
binding together with the relevant cached verification material, so a
replacement body can be learned only as one deliberate operator action. It MUST
be logged loudly by the homeserver, including both the server name and the
fingerprints of the evicted keys. This is an intentionally manual,
operator-gated ability to perform cache merges or manual overrides. It must not
be automated or triggered via inbound/outbound federation traffic; room ACLs and
other federation-visible mechanisms MUST NOT be able to force eviction or bypass
First Seen Wins. This includes any third-party forensic or attestation evidence
about a key binding, however cryptographically strong — for example, a
cross-server equivocation proof a future proposal might define. Such evidence
remains advisory and MUST NOT automatically trigger eviction, rebinding, or any
other deviation from First Seen Wins on a receiving server. It may inform the
human operator who decides whether to invoke this manual mechanism; it must
never invoke it by itself.

### Historical event verification

Cached keys, including keys retired to `old_verify_keys`, MUST be retained for
historical PDU verification. An event signed by `algorithm:key_id` at time `T`
(where `T` is the event's `origin_server_ts`) is valid if and only if: (1) `T`
falls within the key's validity window (i.e., `T` is less than the key's
`expired_ts` if present, and for room versions whose signature rules consult
`valid_until_ts` it is also less than the `valid_until_ts` asserted when the key
was active), and (2) the event signature cryptographically validates. This
`valid_until_ts` check MUST apply for the event's room version 5 and later; a
future room version that changes the signing-validity rule governs itself.
Earlier room versions remain compatible by relying on key retention plus
cryptographic signature verification without introducing a new `valid_until_ts`
requirement. The 7-day cache validity clamp restricts the window in which the
key is authorized to sign new events, but does not invalidate historically
signed events when verifying them years later.

Servers MUST sanity-check `expired_ts` values in `old_verify_keys`. A future
`expired_ts` (beyond a 5-minute clock-skew allowance) MUST be treated as
malformed for that specific key entry, but MUST NOT poison the rest of the
response payload. This should be uncommon, but servers must not use the key in
this case. An `expired_ts` rejected as malformed under this check MUST NOT
consume the first-assignment-wins slot described below: it is treated as if no
`expired_ts` had been observed for that key ID yet, so a later, sanity-passing
value from the same or a different response is free to become the first accepted
assignment. Without this, an origin with a persistently bad clock would submit
an invalid value first, permanently poison that key ID's `expired_ts` binding
against every subsequent (valid) republication, and retirement metadata for that
key could never be recorded at all.

**`expired_ts` is first-assignment-wins, like the key body it retires.** A key
observed active with no `expired_ts` yet, later republished in `old_verify_keys`
with its first `expired_ts`, is ordinary retirement — this is the expected
lifecycle (see [Cache refresh lifetime](#key-caching-requirements)) and MUST be
applied prospectively without comment. The rule applies only once an
`expired_ts` has actually been observed: that first-observed value is then the
binding's retirement timestamp, permanently, the same way the key body itself is
permanent. A later observation asserting a _different_ `expired_ts` for the same
key ID — earlier **or** later — MUST be logged as suspicious and MUST NOT
replace the first-observed value, for eviction ordering or for any future
verification.

**Why both directions are rejected.** Earlier values would retroactively fail
already-accepted PDUs, forcing a state reset over pure metadata with no dispute
about the event or the key's ownership; later values would widen the window a
holder of that compromised retired key can backdate forgeries into (see the
discussion under [Security considerations](#security-considerations)), so
neither direction is benign.

**No early revocation.** A deliberate consequence of this rule is that there is
no early-revocation path for `expired_ts`: an origin cannot shorten a retired
key's validity window after the fact, even to respond to a compromise discovered
after the first `expired_ts` was recorded. That gap is intentional, not an
oversight — widening the window is the more dangerous failure mode of the two —
and the only recourse for a compromised retired key is out-of-band manual
operator action on each affected peer; this MSC does not specify a
protocol-level peer-side cache-eviction mechanism, and `expired_ts` updates are
not one.

**Distinct from provisional-binding override.** This is distinct from the
provisional-binding override above, where a direct fetch replacing a
_conflicting key body_ MAY prompt re-verification of recent events — that path
corrects which key was ever legitimate; this rule instead governs metadata churn
on a key body that was never in question, and requires no per-PDU reliance
bookkeeping beyond simply never re-verifying an already-accepted PDU against a
later-observed `expired_ts`.

**Per-receiver divergence.** Because this binding is per-receiver and local, a
peer that first observes the changed `expired_ts` (e.g., one joining or
refreshing after the change) may still reach a different verdict than one that
locked in the original value earlier — the same cross-peer divergence already
accepted for key-body First Seen Wins (see
[Localized DAG divergence is unavoidable](#potential-issues)), just triggered by
validity-window metadata instead of key-body identity.

The strict key ID uniqueness requirement ensures that this lookup is always
unambiguous: for any `(server_name, algorithm, key_id)` tuple, there is at most
one public key body, and its validity window is well-defined. This permanent
binding also ensures auditors can deterministically verify which key body signed
a given event and when.

This MSC deliberately does not put collision handling into room version auth
rules. Key ID collisions are local observations from out-of-band HTTP key
fetching, not facts carried by the event JSON. Encoding them into auth rules
would make the split-brain permanent: old peers with the old key cached would
reject, new peers seeing only the replacement key would accept, and both would
believe they were following the room version.

## Potential issues

- **Misconfigured servers will experience local isolation.** An administrator
  who wipes their database and regenerates keys under the same key ID will find
  their server unable to federate with peers that cached the original key. This
  is intentional — the protocol prioritizes correctness and security over
  convenience. The fix is straightforward: change the key ID in the server
  configuration and remediate any membership or state divergences.

- **No automated key ID collision recovery.** Unlike some protocols that provide
  key-reset ceremonies or trusted-third-party recovery, Matrix provides no
  automated mechanism, since it conflicts with the zero-trust federation model.

- **Permanent key-body storage.** The permanent binding requirement means
  servers must retain key-body records indefinitely, proportional to the number
  of remote servers encountered. For a typical homeserver federating with a few
  thousand servers, this is negligible (a few megabytes of public key material).

- **Two-tier binding and the TOFU window.** Allowing a direct fetch to override
  a provisional notary binding means an attacker who can serve a direct
  `/_matrix/key/v2/server` response (IP hijack, DNS spoofing) can displace a
  notary-learned key. While this extends the window of vulnerability beyond the
  initial TOFU race, requiring servers to attempt a prompt direct fetch upon
  learning a notary binding bounds this window. The override primarily removes
  the ability of a compromised _notary_ to permanently calcify a poisoned
  binding. Security limitations or concerns here hint at the need for follow-up
  work (e.g., a Global Settings Lock).

- **Localized DAG divergence is unavoidable.** The First Seen Wins rule means
  that peers with different cache histories may disagree on events from a
  misconfigured server. This is an inherent property of out-of-band key
  resolution and cannot be solved at the protocol level. This MSC makes the
  behavior deterministic rather than implementation-dependent, which is an
  improvement over the status quo. A solution to this concern is deferred to
  content-addressable keys or to Member Keys; see
  [Future considerations](#future-considerations).

## Alternatives

- **Trial verification (try all cached keys for a key ID).** Explicitly
  rejected. Trial verification introduces a CPU-exhaustion DoS vector, breaks
  historical DAG verification (which key was active when?), needlessly
  complicates the spec and homeserver requirements, while violating the
  cryptographic identity contract implicitly specified by the key ID.

- **Soft failure on key ID collision (warn but accept the new key).** This
  silently breaks historical verification. Events signed under the old key body
  would fail verification using the new key, corrupting state resolution for any
  room involving the affected host and any other pre-MSC4499 server.

- **Key ID collision resolution via notary consensus.** Peers could query
  multiple notary servers and accept the key body attested by a majority. This
  introduces a trusted-third-party assumption that Matrix's federation model
  explicitly avoids. Notary servers may themselves have stale caches,
  complicating efforts at gossip or consensus.

- **Pure Trust-On-First-Use (MSC3834).** Keep the existing TOFU model and accept
  first-contact poisoning as an explicit trade-off. This is simpler than adding
  corroboration layers, but it leaves the first observed binding unprotected
  against DNS or routing attacks.

- **Scoped signing keys (MSC4100).** This is a narrower protocol-hardening
  measure than the caching rules in this MSC, but it is still a relevant prior
  art because it constrains which keys can be used for which federation
  purposes.

- **Bind federation more tightly to WebPKI-validated origin domains.** This is
  directionally attractive, and has prior art in
  [MSC1711](https://github.com/matrix-org/matrix-spec-proposals/pull/1711),
  [MSC1708](https://github.com/matrix-org/matrix-spec-proposals/pull/1708),
  [MSC1831](https://github.com/matrix-org/matrix-spec-proposals/pull/1831), and
  [MSC4045](https://github.com/matrix-org/matrix-spec-proposals/pull/4045).
  However, this MSC is intentionally narrower: it standardizes cache semantics
  and collision handling for the protocol as deployed today, without making
  X.509 trust or room-version-gated server-name restrictions a precondition for
  safer key handling.

## Security considerations

- **CPU-exhaustion.** The strict "1:1 key ID to key body mapping" eliminates the
  trial verification attack vector. Signature verification is performed against
  exactly one key per key ID, bounding the computational cost of event
  verification.

- **TOFU cache poisoning.** Under Matrix's Trust-On-First-Use model, a
  `/_matrix/key/v2/server` response is self-signed by the private key associated
  with the payload. An attacker who briefly hijacks a server's IP (DNS spoofing,
  BGP hijacking) can generate a new keypair and re-publish it under the target's
  key ID — with valid self-signature. The First Seen Wins policy protects
  against this: if the legitimate key was cached first, the attacker's key is
  rejected as a collision. If the attacker's key is cached first (the server was
  never contacted before), TOFU provides no protection regardless of this MSC —
  an inherent limitation of TOFU, not a flaw in the proposal. Mitigating
  first-contact poisoning remains an out-of-band administrative verification
  task.

- **Bounded key revocation lag (inherited limitation).** Matrix key resolution
  is strictly pull-based; an origin server cannot push a rotation or an
  emergency revocation to the federation. Because this MSC requires servers to
  rely on their local cache and not probe the network while a cached key remains
  within its `valid_until_ts`, worst-case revocation propagation is bounded only
  by the 7-day ceiling inherited from the base Server-Server specification (see
  [Cache refresh lifetime](#key-caching-requirements)), not by how quickly the
  origin publishes the fix. A peer that fetched an origin's keys shortly before
  a compromise will continue to trust the compromised key for up to 7 days from
  that peer's own last fetch — counted from when _that peer_ last checked, not
  from when the origin rotated or discovery occurred — before its cache
  naturally expires and forces a re-fetch. This MSC accepts that ceiling as a
  deliberate trade-off rather than tightening it: mandating faster mandatory
  refreshes would trade this lag for federation-wide fetch storms, and this
  MSC's own negative-caching and backoff requirements exist precisely to bound
  that opposite failure mode (see
  [Negative caching and backoff](#key-caching-requirements)). An operator who
  learns of a compromise out-of-band before the 7-day window naturally lapses
  can use out-of-band operator action to clear the stale binding immediately;
  this MSC does not standardize that peer-local mechanism. The next signature
  check against that `key_id` then triggers a fresh fetch, rather than the
  operator action itself reaching out to the origin.

- **Origin spoofing.** While allowing direct fetches to override provisional
  notary-learned keys prevents notary-enforced lock-in, it temporarily exposes
  the server to DNS/BGP spoofing on direct connections. This is an acceptable
  TOFU trade-off because (1) direct connections use WebPKI TLS certificate
  validation (leveraging standard WebPKI validation), (2) the window of
  vulnerability is bounded to the brief provisional period before the server
  performs a confirming direct fetch, and (3) future MSCs such as a Global
  Settings Lock would effectively mitigate this concern.

- **DAG integrity.** The key ID uniqueness requirement protects abiding servers
  by guaranteeing that historical signature verification is locally
  deterministic. For any event at any point in time, the key that signed it is
  unambiguously identified by the `(server_name, algorithm, key_id)` tuple in
  the `signatures` dictionary.

- **Compromise monitoring.** Key ID collisions are a potential indicator of
  server compromise (an attacker generating a new key and attempting to publish
  it under an existing ID). Hard rejection with operator alerting provides an
  early warning mechanism. They can also be a sign of outdated, legacy servers.

- **Stolen retired keys and backdated forgeries.** Enforcing `expired_ts` stops
  an attacker with a compromised retired key from signing current events. It
  does not prevent them from backdating `origin_server_ts` to forge historical
  events, though the reach of such events is limited by `prev_events` and depth.

- **Cache expiration is not binding expiration.** The `valid_until_ts` field
  governs when to _refresh_ the key endpoint, not when to _forget_ the key body.
  Servers that purge key-body bindings on `valid_until_ts` expiry create a
  window where collision detection is blind. This MSC explicitly requires
  permanent retention of key-body bindings to close this gap.

### Storage considerations

Mandating indefinite storage of key-body bindings introduces a storage
exhaustion vector if an attacker forces a server to fetch and permanently store
millions of unique key IDs. Homeservers MUST enforce a cumulative maximum of
3,000 retired bindings per remote server name — both explicitly-published
`old_verify_keys` entries and keys inferred as retired (a key previously
observed active that later disappears from the origin's responses without ever
appearing in `old_verify_keys`) count toward this same ceiling. This is a
retained-storage ceiling, distinct from the per-response validation ceiling
above; current `verify_keys` (bounded separately at 50) are active keys and are
exempt from and not counted against this retired-key ceiling. If a remote server
reaches this quota, receiving servers MUST NOT ignore new key IDs permanently;
instead, they MUST evict retired keys according to the deterministic ordering
below — never by recency or least-recently-used heuristics, which would make
eviction implementation-dependent. Keys currently published in the `verify_keys`
section of a direct fetch MUST always be prioritized and exempt from eviction.

**Corroboration tier.** `old_verify_keys` entries are plain claims inside a
self-signed response — the origin asserts "this key used to be active," but
nothing separately signed by the retired key backs that claim, making
retired-key claims cheaper to fabricate in bulk than current `verify_keys`
entries. Corroboration does not decide which key body is correct — First Seen
Wins already settles that permanently — it only decides which
permanently-retained retired-key bindings get evicted first if the 3,000-entry
ceiling is reached. Before applying the eviction ordering, implementations MUST
sort retired bindings into two tiers:

- **Corroborated:** the receiver itself independently observed that
  `(server_name, algorithm, key_id)` as a currently-published `verify_keys`
  entry in some prior response (via a direct fetch, or a notary relaying the
  origin's genuinely-active state at that earlier time), or a local operator
  marked it corroborated from independently verified historical evidence.
- **Uncorroborated:** everything else — a retired-key entry that arrives
  already-retired, with no independent record anywhere that the key was ever
  genuinely active.

Corroboration MUST be grounded only in the receiver's own accumulated
observation history or explicit operator action, never in a live attestation
solicited at retirement time — otherwise one compromised or colluding notary
could vouch on demand for any key on any domain, turning it into a universal
corroboration-forging oracle and defeating the tier's purpose.

Uncorroborated bindings MUST still be accepted and retained for historical PDU
verification — rejecting them outright would break first-contact backfill and
the lost-key recovery case in [Recovery from key loss](#recovery-from-key-loss)
— but they sort below corroborated bindings for eviction. Corroboration changes
exactly one thing — eviction order under the ceiling — and nothing else.

The retirement source and the ceiling accounting are separate questions and
implementations MUST treat them separately:

- **Explicit retirement:** if a key is present in `old_verify_keys`, it is a
  retired binding with an effective retirement timestamp equal to its
  `expired_ts` (subject to the malformed-future check).
- **Inferred retirement:** if a key was previously observed active but later
  disappears from the origin's responses without ever appearing in
  `old_verify_keys`, the receiver still treats it as retired verification
  material with an effective retirement timestamp equal to the receiver's last
  observation time at which the key was still present.
- **Ceiling accounting:** both categories count against the same local
  3,000-entry retired-key ceiling; current `verify_keys` do not count toward it.

If MSC00E4 `trusted_notary_keys` is present, a listed full content-addressed key
identifier permits a notary to return the corresponding retained historical key
body without the origin embedding that body in `old_verify_keys`. This does not
create a new corroboration source by itself: the receiver still recomputes the
returned key body's full content-addressed `key_id`, verifies any required
proof-of-work, signatures, and expiry claims, and sorts the binding into the
corroborated or uncorroborated tier using the same local observation-history
rules above. A notary-supplied body whose recomputed full ID does not exactly
match the origin-signed `trusted_notary_keys` entry MUST be rejected.

Implementations MUST apply this ceiling deterministically: always retain all
current `verify_keys`; then retain corroborated retired keys in descending order
of an _effective retirement timestamp_; then, in whatever slots remain, retain
uncorroborated retired keys under the same ordering. Ties in the effective
retirement timestamp are broken by bytewise lexicographic comparison of the full
`algorithm:key_id` string as UTF-8, ascending. When a new valid retired-key
binding is learned while the local retired-key set is already at the 3,000-entry
ceiling, implementations MUST recompute the retained set by applying this
ordering across the union of the previously retained retired keys and the newly
learned candidate: if the new candidate sorts above the retention floor it MUST
be stored and whichever existing binding now falls below the floor MUST be
evicted; if it sorts below the floor, the implementation MUST discard it —
subject to the digest binding surviving that eviction regardless (see the
digest-binding cap below). Hitting the storage ceiling MUST therefore degrade
into this deterministic prune-and-retain behavior, not into fetch failure, not
into dropping all newly learned historical bindings unconditionally, and not
into eviction of currently-active `verify_keys`. Uncorroborated bindings are
therefore always evicted before any corroborated binding, regardless of their
respective `expired_ts` values. For a key published in `old_verify_keys`, the
effective retirement timestamp is its `expired_ts`; for a key previously
observed active but since dropped by a lazy or misbehaving origin without an
`expired_ts`, it is the local timestamp of the last observation in which the key
was still present. This makes every retained-or-evictable binding sortable.
Equivalent pseudocode:

```text
retain all current verify_keys

retired_candidates :=
  all retired bindings already retained locally
  union all newly learned retired bindings from this fetch

sort retired_candidates by:
  1. corroborated before uncorroborated
  2. effective retirement timestamp descending
  3. full algorithm:key_id lexicographically ascending

retain the first 3000 retired_candidates
evict every retired candidate below that cut line
```

Eviction of a _corroborated_ binding SHOULD be logged at warning level: reaching
the ceiling deeply enough to displace corroborated history is itself the flood
signal, and costs nothing beyond the logging this MSC already requires for
collisions. Because corroboration and effective retirement timestamps are local
determinations rather than origin-asserted values, this ordering is local to
each implementation; this is consistent with the cross-server convergence limits
described below. When new valid historical key material is learned, notaries and
receiving servers MAY re-evaluate the retained retired-key set — including
re-evaluating corroboration as new observations arrive — but such re-evaluation
MUST apply the same deterministic pruning rule over the full locally known
candidate set. Implementations MUST rely on existing federation rate-limiting to
discard junk traffic before allocating database records. Legitimate servers
publish single-digit numbers of active keys at any given time; a server claiming
tens of thousands of key IDs is unambiguously hostile. A future Proof-of-Work
gated proposal may mitigate the spurious bulk generation of keys behind Equihash
or Cuckoo Cycle.

### Digest-binding cap

The digest binding is deliberately minimal: a `key_id` limited to 255 UTF-8
bytes and a 32-byte `SHA-256` digest of the key body — on the order of 315 bytes
per record, far smaller than a retained verification entry. It exists to survive
eviction of retired-key verification material so a future body reusing an
evicted key ID is still checked against what was first seen, closing the
collision-blind window that motivates permanent retention in the first place:
the digest itself is normative, and every later body observed for the same
`(server_name, algorithm, key_id)` MUST match the stored digest. The digest is
normative; only the `first_seen` timestamp, which records when the receiver
established the binding, is non-normative metadata kept for operator forensics
and a future proposal to build eviction or corroboration policy on top of
without a schema change. Because that guarantee depends on the binding never
being evicted for a genuinely-seen key ID, it MUST NOT be pruned the way
retired-key verification material is — evicting a digest binding to make room
for a new one reopens exactly the TOFU window this record exists to close.

That means the digest-binding set cannot be bounded by eviction; it MUST instead
be bounded by refusing new entries once a fixed cap is reached. Implementations
MUST enforce a maximum on digest-binding records independently per
`(remote server name, source category)`, where source category is direct-fetch
or notary-observed, RECOMMENDED at 30,000 for each bucket — an order of
magnitude above the 3,000-entry retired-key ceiling, since digest bindings
accumulate for the full lifetime of a key ID even after its verification
material is pruned, but still small and fixed (at ~315 bytes/record, roughly 10
MiB per origin per bucket at the recommended cap). Implementations MUST reject a
key ID longer than 255 UTF-8 bytes before allocating or persisting a
digest-binding record. A different fixed value has no wire-visible effect as
long as it is enforced deterministically and consistently; the requirement that
matters for interoperability is that reaching _some_ fixed ceiling for a given
`(origin, source category)` bucket is itself the anomaly signal, not the exact
number.

A key ID observed for the first time for a given `(origin, source category)`
bucket after that bucket's digest-binding set is already at the cap MUST be
rejected: no digest-binding record is created for it, and the key body it names
MUST NOT be used to verify signatures, since without a recorded digest binding
there is nothing to protect a later, colliding body for the same key ID from
being silently accepted. This MUST be logged at warning level; the response
containing it MUST otherwise still be processed normally (this is a per-key-ID
rejection, not a payload-level one) — other key IDs in the same response that
are still under the relevant cap are bound and usable as normal. Key IDs already
bound before the cap was reached continue to be checked and enforced as normal.
The cap is sized to accommodate legitimate bulk first contact — a late-joining
peer backfilling a full 3,000-entry retired-key response in one exchange still
lands an order of magnitude below it — so it does not need a companion rate
limit on ordinary operation to be effective; reaching the cap for one
origin/source bucket at all is itself the anomaly signal described elsewhere in
this section ("unambiguously hostile").

**Cap accounting MUST be segregated by source.** A digest binding for origin `X`
can be learned two ways: a direct fetch from `X`, or a notary response _about_
`X`. If both sources drew from the same budget, a malicious or compromised
notary could serve enough synthetic key IDs attributed to a victim origin it
does not control to exhaust that victim's cap on every peer that queries through
it, and cause the victim's own subsequent genuine key IDs — learned later via
direct fetch — to be rejected under the cap even though the victim never
misbehaved. To prevent this, implementations MUST maintain the cap independently
per `(remote server name, source category)`: a notary-sourced flood against one
origin exhausts only that origin's notary-sourced budget and MUST NOT consume or
block that origin's direct-fetch budget, or vice versa. This source split
applies only to cap accounting; the binding namespace is global per
`(server_name, algorithm, key_id)` tuple, so collision detection and lookup MUST
consider every binding for that tuple regardless of which source budget it was
counted against. When a provisional (notary-observed) binding is promoted to
permanent, its digest-binding record MUST thereafter count against the
direct-fetch budget for that origin rather than the notary-sourced one, since
promotion requires the same direct confirmation a direct-fetch binding would
have. Because promotion does not add a new binding namespace entry, it MUST NOT
fail solely because the direct-fetch budget is already at cap; implementations
MUST transfer the accounting of the existing record.

### Other considerations

- **Eviction preserves collision safety but can lose historical material.**
  Retired verification material may be evicted at the cumulative cap, but its
  identity digest remains bound. Therefore eviction cannot reopen First Seen
  Wins or TOFU: a later body under the same key ID is still rejected. The cost
  is that historical events requiring the evicted material may no longer verify.
  When the digest-binding cap is reached, new key IDs are rejected rather than
  displacing existing bindings. This is self-scoped per remote server and source
  bucket; implementations may additionally rate-limit hostile discovery.

- **The provisional-binding freeze is a deliberate trade, not an oversight.** A
  provisional binding that has retired, or whose own local promotion window has
  elapsed, MUST NOT be overridden by a later direct fetch (see Notary fallback):
  a direct fetch cannot attest anything about a key the origin no longer serves,
  and allowing post-liveness rewrites would let an attacker rewrite historical
  verification after the fact. The consequence is that a notary-poisoned binding
  that retires or otherwise ages out before any direct confirmation is frozen in
  that poisoned state permanently, recoverable only through the manual eviction
  mechanism described under [Recovery from key loss](#recovery-from-key-loss).
  This MSC accepts that trade — auditability of historical verification over
  automated self-healing — as the safer default.

## Implementation and rollout notes

Because strict collision rejection can break federation with misconfigured
servers already in the wild, implementations SHOULD ship an initial
collision-observation phase: log detected collisions as warnings without
rejecting the new key, gather real-world breakage data, then enable strict
enforcement. A configuration flag (e.g., `org.matrix.msc4499_strict_caching`) is
the obvious gate. This is rollout guidance only; the normative rules above are
unchanged by it.

## Unstable prefix

This MSC does not introduce new protocol identifiers and does not require an
unstable prefix. The behavior changes (mandatory caching, permanent key-body
binding, collision detection, trial verification prohibition) are implementation
requirements that can be readily adopted. No API endpoints substantially change.

## Dependencies

- This MSC is intentionally deployable on its own. It does not require wire
  changes, room-version changes, or the acceptance of other MSCs in order to
  improve safety for current federation key handling.

- This MSC complements
  [MSC4029: Fixing `X-Matrix` request authentication](https://github.com/matrix-org/matrix-spec-proposals/pull/4029),
  which clarifies current practice around direct key retrieval for federation
  request verification, and
  [MSC3383: Include destination in `X-Matrix` Auth Header](https://github.com/matrix-org/matrix-spec-proposals/pull/3383),
  which makes the intended destination server name explicit during federation
  authentication. Those proposals strengthen the broader "verify the named
  origin directly when possible" posture which this MSC relies upon, but are not
  prerequisites for the cache and collision rules here.

- This MSC also aligns with earlier federation discovery and transport work:
  [MSC1711](https://github.com/matrix-org/matrix-spec-proposals/pull/1711),
  [MSC1708](https://github.com/matrix-org/matrix-spec-proposals/pull/1708),
  [MSC1831](https://github.com/matrix-org/matrix-spec-proposals/pull/1831), and
  [MSC4045](https://github.com/matrix-org/matrix-spec-proposals/pull/4045).
  Those proposals make federation discovery and transport — server name
  resolution, `.well-known`, SRV, and TLS certificate verification — more robust
  and deployable; this MSC complements that line by defining how key
  observations should be cached and how conflicts should be handled once
  observed.

- It applies to `ed25519` keys today. It will apply equally to future
  server-signing algorithms if accepted into the spec and if this document is
  not superseded by a refined or more encompassing MSC.

## Open questions

- How should moderation tooling (community ban lists, Draunir) treat a server
  locally isolated by a key collision — as a temporary outage, or as a signal
  worth surfacing to operators?

## Backwards compatibility

This proposal introduces no wire-format changes, but does add stricter
receiver-side validation:

- **No protocol wire changes.** No new fields, endpoints, or response formats.
- **Stricter receiver-side validation.** The active-key ceiling, retired-key
  ceiling, and raw-byte duplicate-key rejection mean a payload a pre-MSC
  receiver would have silently tolerated (or handled ambiguously) is now a
  MUST-reject; no conformant, well-behaved origin produces such a payload today.
- **No room version changes.** No changes in auth or state resolution rules.
- **Existing well-configured servers are unaffected.** Servers that already use
  unique key IDs on rotation (the newly-defined behavior) experience no change.
- **Misconfigured servers experience a clarified failure mode.** Servers that
  reuse key IDs with different key bodies will be rejected by peers implementing
  this MSC. This failure already occurs unpredictably today (depending on cache
  state and timing); this MSC makes the behavior expected and codified.

## Future considerations

### Content-addressed key IDs (stricter protocol requirements)

The root cause of key ID collisions is that the `key_id` is currently an
arbitrary, administrator-defined string (e.g., `ed25519:auto`). A future room
version could eliminate this entire class of vulnerabilities by mandating that
the `key_id` must be deterministically derived from the public key body
itself—for example, `ed25519:<base64(SHA256(KeyBody))[:16]>`.

Under this paradigm, a key ID collision becomes exceedingly difficult. If an
administrator regenerates their keys, the new key body structurally enforces a
novel key ID. This entirely mitigates the TOFU poisoning vulnerability (an
attacker cannot assert a new key under an old ID without conducting a
computationally intractable search). It would eliminate the need for out-of-band
collision detection heuristics, enabling enforcement of strict key uniqueness
directly within room version auth rules.

Because this requires changing how PDU signatures are verified and supplants
legacy key formats thoroughly entrenched in the wild, it requires a new room
version and is deferred to a future MSC. Until then, protection must remain
strictly at the local server caching layer as outlined in this proposal.

[MSC4291: Room IDs as hashes of the create event](https://github.com/matrix-org/matrix-spec-proposals/pull/4291)
applies the identical technique to a different identifier: it derives `room_id`
from a hash of the create event to make room-ID collision and forgery
computationally intractable, for the same reason this section proposes deriving
`key_id` from a hash of the key body. If MSC4291 lands first, it would be a
concrete existing precedent for this kind of content-addressed identifier inside
a room version's auth rules.

This is also the closest MSC in the room-version namespace that shows the same
mechanical move this proposal would need for key IDs: derive the identifier from
the content being committed, not from an operator-chosen label.

This is one of several adjacent proposal lines which address the deeper problem
that Matrix currently uses mutable, domain-scoped server signing keys as both a
transport identity and an input to room-event verification.

### Adjacent work

Several other proposals address the deeper problem that Matrix currently uses
mutable, domain-scoped server signing keys as both a transport identity and an
input to room-event verification, but none replaces this MSC in current room
versions:

- [MSC4430: Member Keys](https://github.com/matrix-org/matrix-spec-proposals/pull/4430)
  caps the key body in-band to a future room version, reducing today's
  out-of-band notary model and freeing notary capacity for other functions.
- [MSC4428: Stable identifiers](https://github.com/matrix-org/matrix-spec-proposals/pull/4428)
  and
  [MSC4345: Server key identity and room membership](https://github.com/matrix-org/matrix-spec-proposals/pull/4345)
  weaken the protocol's dependence on domain-scoped identifiers as the only
  stable identity primitive.
- [MSC4100: Scoped signing keys](https://github.com/matrix-org/matrix-spec-proposals/pull/4100)
  narrows which server keys may sign events versus federation requests —
  valuable defense-in-depth, but it does not itself bind a signing key to an
  origin domain.
- [MSC2961: External Signatures](https://github.com/matrix-org/matrix-spec-proposals/pull/2961)
  provides a generic mechanism for attaching non-Matrix signature material,
  which could carry external attestations but does not by itself solve
  federation-domain binding.
