# nix-builder-discovery design draft

Status: early implementation. The two-node VM test passes. The full trust and retry matrix, and the ojuny integration, are still pending.

## 1. What NBD is

nix-builder-discovery (NBD) is a standalone Go service that lets Nix use other
machines on a LAN as remote builders. It discovers peers, pairs devices with an
explicit approval on both machines, and runs each derivation as a job on an idle
builder. A failed job is restarted on another builder.

NBD is independent of nix-cache-discovery. It has its own discovery port, trust
store, and CLI. It does not read or write NCD state and does not require NCD to
be installed, but the two are expected to run together so build inputs and
outputs can move through the LAN cache.

NBD is not a binary cache and does not replace Nix's remote-build support. It
supplies a custom Nix build hook. The hook owns each attempt, so it can retry a
job on another builder instead of failing the derivation.

## 2. Why a build hook, not a byte proxy

Nix's built-in remote builds use a build hook, `nix __build-remote`, configured
through `build-hook` and driven by the `builders` list. The hook protocol is
per-derivation and one-shot: the daemon sends the derivation, the system, the
features, the input paths, and the wanted outputs, and the hook either declines,
postpones, or accepts and then builds.

A byte proxy in front of `ssh-ng://localhost` can hide peer selection, but it
cannot restart a build. Once the worker protocol starts, the stream is stateful
and Nix has already consumed responses. Moving the build would mean replaying
the stream and suppressing duplicate responses, which is a second
implementation of the protocol. A disconnect is a failure.

The job API moves the retry to the layer that owns the build:

- the hook is spawned once per derivation
- the hook submits one job, waits, and reads the result
- a transport failure discards the attempt and starts a new job on another
  builder
- a genuine build failure is reported without retrying

There is no transparency requirement. A lost attempt is discarded, including
any work the builder may still be doing. Most Nix builds are many derivations,
so only the failed derivation is rebuilt.

This also removes the trusted daemon problem. The builder runs `nix build` as an
unprivileged user, the system daemon applies the sandbox, and no client ever
gets a daemon connection. The `trusted-users` entry, the restricted-settings
filter, and the worker-protocol relay are gone.

Nix configuration becomes:

```
build-hook = /run/current-system/sw/bin/nbd-build-hook
```

`builders`, `remote-program`, `fakeSSH`, and `nix.distributedBuilds` are not
used.

References: `src/nix/build-remote/build-remote.cc`,
`src/libstore/build/derivation-building-goal.cc`,
`src/libstore/build/hook-instance.cc`.

## 3. Three planes

The design separates visibility, trust, and building. Deny only affects trust
and building.

### 3.1 Public plane

The public plane is always on when the service is enabled. It is plain HTTP and
carries only public data. Every device on the LAN can read it, including
devices this device has denied.

Endpoint: `GET /.nix-builder-discovery/v1/info` on the info port, default 5056.

Response body:

```
id=<base32 sha256 of the public key>
version=1
hostname=<hostname>
systems=x86_64-linux,aarch64-linux
info-port=5056
build-port=5057
cache-url=<optional binary cache URL>
state=idle|busy
busy-reason=session|local-build|remote-build|cap|battery|window
accepting=0|1
key=<base64 ed25519 public key>
timestamp=<unix seconds>
sig=<base64 ed25519 signature over every preceding byte>
```

The signature covers the exact bytes before the `sig` line, so no
canonicalisation is needed. It proves that the holder of the advertised key
produced the payload and binds the fields to that key. It does not prove the
hostname. The fingerprint is the identity.

Discovery scans configured prefixes for hosts that answer this endpoint, with
the same shape as NCD: configurable ranges or automatic subnet detection,
probe interval, per-probe timeout, worker count, and a public-IP gate for
networks the user explicitly trusts.

A denied device still answers and is still listed. Trust cannot be established
for a device that cannot be seen.

`state` is `idle` only while the idle policy holds. `busy-reason` names the
first condition that made the device busy. `accepting` is `1` only while the
device will consider new jobs: the incoming default is not `deny`, or the
requester is manually trusted, and the connection cap is not reached. All
three fields are selection hints. They never authorize anything.

`cache-url` is optional. When set, the builder's local binary cache can serve
inputs and outputs for jobs.

### 3.2 Trust plane

Trust is stored per device, locally. Records are unilateral: either side can
create one from the public plane without the other agreeing. Pairing is the
point where both sides agree.

Record fields: peer fingerprint, public key, last known hostname and address,
state (`trusted` or `denied`), source (`manual`, `default`, or `peer`), and
timestamps.

Defaults, declared by the NixOS module:

- `defaults.incoming`: what to do when another device asks to build here.
- `defaults.outgoing`: what to do when this device wants to build elsewhere.

Each is `ask`, `allow`, or `deny`. They are the role switch:

| incoming | outgoing | role |
| --- | --- | --- |
| deny | ask or allow | client only |
| ask or allow | deny | builder only |
| ask or allow | ask or allow | full peer |
| deny | deny | isolated but visible |

Precedence, per direction:

1. An explicit manual record wins. A manual trusted record overrides a `deny`
   default, which is the deny-by-default allowlist case.
2. A record created by `allow` is tagged `default`. It keeps the key and
   history, but the live default still gates use, so switching the default to
   deny takes effect on the next rebuild without cleanup. The CLI can revoke
   those records explicitly.
3. A neutral device follows the live default.
4. A denied record always wins. Deny beats allow.

`deny` means no prompt and no job. It never means hidden.

`skip` is not a record. It suppresses one peer for the current build scope.

### 3.3 Build plane

The job API on the build port, default 5057, over TLS. The certificate is the
device identity, self-signed, generated at first start. The client verifies that
the certificate key matches the fingerprint advertised on the public plane,
then pins it after trust.

Client certificates are required. The server reads the client certificate
fingerprint and applies the trust records:

- trusted: accept the job
- denied: close immediately
- neutral: begin pairing if the incoming default is `ask` or `allow`, refuse if
  it is `deny`
- manual trusted on the server side: accept, regardless of the incoming default

TLS is mandatory on the build plane in v1. A plaintext mode would need a signed
challenge in place of the certificate, which is a second transport and not part
of the first release.

## 4. Identity

On first start the service generates an Ed25519 key pair. The private key is
stored in the state directory, owned by the service user, mode 0400. The public
key is the device identity.

- Fingerprint: SHA-256 of the raw public key, base32 without padding.
- Short ID: the first 8 characters of the fingerprint, shown in the CLI and the
  popups.
- TLS certificate: self-signed, generated from the same key at startup, valid
  for the expected lifetime of the device. The certificate does not need a
  hostname; clients compare the key, not the CN.

The user never creates, copies, or edits a key. The only user-facing identity
is the short ID in the approval dialog.

## 5. Pairing

The first time a client uses a builder, both machines show a dialog. The flow
is a two-phase commit so a client cannot save trust that the builder has not
granted.

1. The client discovers the builder on the public plane and verifies the info
   signature with the advertised key.
2. The client applies its outgoing policy. `deny` stops here. `ask` opens a
   prompt. `allow` skips the prompt.
3. The client opens TLS to the build port, requires the certificate key to
   match the advertised key, and presents its own certificate.
4. The server applies its incoming policy. `deny` closes. If the client is
   neutral, the server replies that pairing is available.
5. The client prompt shows hostname, address, systems, and the short ID, with
   three actions: trust, skip, deny. A timeout defaults to skip.
6. On trust, the client sends the pairing request. On skip or deny it closes,
   and skip records a build-scope suppression.
7. The server prompt shows the same information for the client and the same
   three actions. `incoming = allow` skips this prompt.
8. Both trust: each side saves a trusted record and the client receives the
   final acknowledgement. Any other outcome saves nothing on the client, and a
   user deny saves a denied record on the side that clicked it and is reported
   to the other side.
9. The connection proceeds to the job API without a reconnect.

A requester with a manual trusted record starts at step 4 and skips its own
prompt. A server with a manual trusted record accepts the job.

First contact is not authenticated against a known identity. The info signature
proves key possession and the certificate check binds the advertisement to the
listener, but a relay on the LAN can present two different keys and two
readable hostnames. Trust on first use is therefore recognition by short ID and
hostname. An optional matching code derived from both keys can be added to both
dialogs later without changing the state machine.

The approval UI is delivered by a per-user agent. The system service exposes
pairing events and decisions on a local control socket. The ojuny desktop
provides a graphical dialog. Without a session, the CLI shows the request in a
terminal. An unanswered request expires.

## 6. Client hook

`nbd-build-hook` implements Nix's build-hook protocol and becomes the
`build-hook` setting. It is spawned once per derivation and owns the attempt
loop.

The hook is a thin adapter over the local NBD service:

1. Read the job from the daemon: system, derivation path, features, input paths,
   wanted outputs.
2. Ask the local service for a lease. The service applies trust, role, busy,
   idle, and `waitForBuilders`.
3. If no eligible remote exists, write `# decline` and exit. Nix builds locally.
4. If eligible remotes exist but all are busy and waiting is on, write
   `# postpone` and exit. Nix retries the job without building locally.
5. Otherwise write `# accept`, submit the job to the leased builder, stream the
   builder's log to stderr, and wait for the result.
6. On a transport failure, discard the attempt, apply a cooldown to that
   builder, and start a new job on another leased builder, up to the attempt
   limit.
7. On a build failure reported by the builder, write the log and exit non-zero.
   Do not retry.
8. On success, fetch the outputs, import them into the local store, and exit
   zero.

The hook runs as the daemon user, so it can import unsigned outputs into the
local store. It holds no network identity; the local service owns the keys and
the TLS connections.

### 6.1 Availability is never a build failure

A busy, refusing, or unreachable peer is a normal condition. The hook and the
service try the next candidate and never report a peer-specific condition as a
build failure before `# accept`.

- Busy means `state = busy`, `accepting = 0`, or the builder job service is at
  its connection cap. The candidate is skipped without a connection attempt.
- A stale candidate that refuses, times out, presents a key that does not match
  its advertisement, or does not answer a pairing prompt is closed and the next
  candidate is tried.
- Each candidate gets a short connect and handshake budget. The whole selection
  gets a small overall budget, so a LAN full of stale addresses cannot delay a
  local build for long.
- If the candidate list is exhausted, or no peer is eligible, the hook writes
  `# decline`. Nix builds locally.
- Pairing is only attempted while the builder advertises `idle` and `accepting`.
  An unanswered or skipped pairing prompt drops that candidate and continues.

`waitForBuilders` changes only the all-busy case. Off means all-busy is treated
like no remote, so the hook declines and Nix builds locally. On means the hook
writes `# postpone` while at least one eligible remote exists but every one is
at capacity. If no eligible remote exists at all, the hook declines. The wait
ends when a slot frees, a peer becomes ineligible, the wait timeout expires, or
the build is cancelled.

Local fallback requires that the derivation can be built locally. On a system
mismatch with no remote builder available, Nix fails because no capable machine
exists. That is not an availability failure of a peer.

Nix only calls the build hook when the local machine is not available for the
job, either because `max-jobs` is saturated or because the system does not
match. NBD therefore offloads when the client is busy, not on every build. A
client that wants to build everything remotely can set `max-jobs = 0`, at the
cost of losing the local fallback.

### 6.2 Retry, with a reconnect grace

A dropped connection is not a failed attempt. The hook first tries to reattach
to the same job on the same builder for a bounded grace window, so a short
network interruption does not cancel work or force a rebuild.

- The job has a client-generated ID. The builder keeps it alive for
  `reconnectGrace` after the last client connection, default one minute. A
  builder that has not come back within that minute is considered lost.
- During the grace the build keeps running. It is not paused and it is not
  cancelled.
- The hook reconnects with the same TLS identity and asks for the job log from
  its last offset. If the job is still running, log streaming resumes. If it
  finished, the result and outputs are returned.
- If the builder is unreachable for the whole grace, or reports the job gone or
  cancelled, the attempt is discarded and the derivation starts again on
  another builder. The partial work on the first builder is then abandoned.
- The builder cancels the job and frees the slot when the grace expires without
  a client.
- If the builder process itself dies, the job is gone. The client detects the
  loss and retries elsewhere.

Only transport and infrastructure failures are retried or reattached. A build
failure reported by the builder is not retried. It is reported with its log and
fails the derivation.

The attempt count is bounded. The default is three attempts, or the number of
eligible builders, whichever is smaller. The reattach window is part of the
current attempt, not a new one.

Before `# accept` the hook can still decline or postpone, so an unavailable or
busy peer never fails the build. After `# accept` the hook is committed. If
every attempt fails, the derivation fails. A later run can use the local
machine or another peer.

Each attempt is logged with its peer and attempt number. Logs from failed
attempts stay in the build log. A reattach continues the same log. Nothing is
hidden from the user.

The builder job service never resumes a job after the grace expires. There is
no migration of an in-flight build and no unbounded job persistence.

### 6.3 Broker and leases

The hook asks the client-side service for a lease instead of selecting a peer
itself. The service holds the trust store and the discovery snapshot, tracks
active leases, and assigns distinct peers to concurrent jobs. Parallel Nix jobs
therefore fan out across independent builders instead of stacking on one.

The lease is tied to the hook's control connection. When the hook exits, the
lease is released.

## 7. Builder job service

The builder runs `nix-builder-discovery serve` with the job API.

- TLS on the build port, pinned to the paired identity.
- `POST /v1/jobs` with the job ID, derivation path, derivation text, wanted
  outputs, input paths, and system.
- The service validates the derivation path against the derivation text, then
  runs `nix build` as an unprivileged user with a fixed policy: sandbox on, a
  capped `max-jobs` and `cores`, and no client-supplied Nix options.
- The build log is streamed to the client and also kept for the job.
- The final result is a success with output paths, or a build failure with the
  log.
- A dropped client connection does not cancel the job. The job keeps running
  for `reconnectGrace`, default one minute, so the client can reattach to the
  same log and result. When the minute expires without a client, the service
  cancels the build process group and frees the slot.
- Reattach is bound to the client certificate fingerprint and the job ID. A
  different paired client cannot read or continue another client's job.
- A connection cap, an optional time window, and an audit log of peer
  fingerprint, system, derivation, start, end, and result.

The service never gives the client a Nix daemon connection. The client can only
submit derivations, read their logs, and fetch their outputs.

### 7.1 Input and output transfer

The job API carries the request, not the store contents. Two modes:

- **Direct mode.** The builder streams a `nix-store --export` archive for the
  output closure, and the hook imports it with `nbd-import`, a small libstore
  helper. This is the default and needs no cache. Inputs still arrive through
  the builder's substituters unless the cache path is used.

`nbd-import` exists because `nix-store --import` deadlocks against the build
goal's output lock. `LocalStore::addToStore` skips that lock only when the path
is already in `locksHeld`, an exception Nix's own build hook uses. The helper
opens the local store, inserts the output paths, and calls `importPaths`.
- **Cache mode.** When `cacheURL` is set, the builder substitutes inputs through
  the LAN cache and the hook pulls outputs with `nix copy --from`. This is the
  natural ojuny mode with NCD.

The job API is independent of the mode. Direct output transfer is implemented.
Input transfer for a builder with no cache is the remaining gap.

## 8. Busy state and idle policy

`busy` is an explicit state, not a CPU threshold. A device is busy when any of
these holds:

- a local Nix build is running
- a remote build job is running
- the connection cap is reached
- the local session has recent input and the policy requires an idle session
- the battery, power, or time-window policy forbids serving

Once a build starts, the device stays busy until that build ends. Hysteresis
prevents a build's own CPU usage from flipping it back to idle between scans.
CPU load can be an extra guard for unmanaged workloads, but it is not the
primary signal and it cannot override an explicit build state.

Status changes are event driven, on build start and end, session idle changes,
and power or window changes, not only on the discovery scan. Peers see a busy
device before the next scan interval.

A builder accepts at most `maxConnections` jobs, default 1. At the cap it
advertises `accepting = 0` and `busy-reason = cap`, so clients fan out to other
builders instead of queueing on one.

## 9. CLI

```
nix-builder-discovery peers
nix-builder-discovery pending
nix-builder-discovery trust list
nix-builder-discovery trust allow <id>
nix-builder-discovery trust deny <id>
nix-builder-discovery trust revoke <id>
nix-builder-discovery trust revoke --default
nix-builder-discovery status
nix-builder-discovery jobs
nix-builder-discovery serve
nix-builder-discovery hook
```

The CLI talks to the running service over a local control socket. `peers`
includes denied and neutral devices, because visibility is independent of
trust. `trust allow` works for a device that has never prompted, using the
fingerprint from discovery. `jobs` shows active jobs on this device. Commands
that change trust are refused when the service is not running.

The trust store has a single writer, the service. The CLI, the agent, and the
hook read through it.

## 10. NixOS module

The module declares:

- `enable`
- `defaults.incoming` and `defaults.outgoing`, each `ask`, `allow`, or `deny`
- `infoPort`, default 5056
- `buildPort`, default 5057
- `discovery.ranges`, `discovery.auto`, `discovery.interval`, `timeout`,
  `workers`
- `trustedNetworks`, `publicIpUrl`, `trustCheckInterval`
- `idle` policy options
- `maxConnections`
- `waitForBuilders`, `waitTimeout`, `maxAttempts`
- `reconnectGrace`, default one minute
- `cacheUrl`
- `openFirewall`
- `stateDir`, default `/var/lib/nix-builder-discovery`
- `package`
- `extraArgs`

The defaults are declarative. Changing one is a rebuild. The CLI never edits
policy, only records.

The module creates the system user and group, the state directory, the control
socket, and the systemd unit. It sets `nix.settings.build-hook` to the packaged
hook. The firewall opens the info and build ports to private, link-local, and
unique-local prefixes only. The info endpoint is public by design. The build
port is gated by TLS and trust.

The module does not enable SSH and does not add a trusted user.

## 11. ojuny integration

One toggle enables NBD on the device. Two dropdowns select the incoming and
outgoing defaults, labelled "Act as a builder for others" and "Use other devices
as builders". A read-only indicator shows pending pairing requests and links to
the CLI for the rest.

Annotated assignments target the real NBD options and stay in a plain attribute
set or directly inside `lib.mkIf`, per `docs/05-settings-gui-limitations.md`.
The page adds the flake input and the package source wiring in the same shape as
`nix-cache-discovery`.

NCD is not modified.

## 12. Security and threat model

- The public plane is unauthenticated by design. Its data is public and signed.
- Trust is per device, explicit, and revocable. A lost device is revoked on
  every device that trusted it.
- The job API authenticates both sides with certificates pinned to approved
  fingerprints.
- An approved client can ask the builder to run derivations. The builder runs
  them as an unprivileged user with the sandbox on. The client never gets a
  daemon connection, so it cannot change daemon settings or disable the
  sandbox.
- Input-addressed build outputs are trusted wholesale. Nix has no way to verify
  them, and a compromised builder can return wrong results. Content-addressed
  derivations are verifiable by hash. A duplicate-build quorum is possible but
  not part of v1.
- A signature attests who built a path, not that the path is correct.
- A first-contact relay is detectable only by comparing the identity shown on
  both screens. The short ID and hostname are the recognition step.

## 13. Failure modes

- No idle or trusted peer: `# decline`, local build.
- All eligible remotes busy and waiting on: `# postpone`, no local build.
- All eligible remotes busy and waiting off: `# decline`, local build.
- A busy peer is skipped, not failed.
- A stale peer refuses or times out: the hook tries the next candidate, then
  declines if none remain.
- Builder disconnects or crashes during a job: the hook reattaches to the same
  job within `reconnectGrace`, default one minute. A builder that does not come
  back within the minute is treated as lost, the attempt is discarded, and the
  derivation starts again on another builder.
- Every attempt fails after `# accept`: the derivation fails. A later run can
  use local or another peer.
- Builder reports a genuine build failure: no retry, the failure is reported
  with its log.
- NBD service down: the hook declines and Nix builds locally. Pairing and CLI
  commands fail.
- Asymmetric records: one side builds, the other refuses. Intended.
- Clock skew: the info timestamp has a tolerance and is only a replay hint, not
  an authorization decision.

## 14. Testing

Unit tests:

- identity generation, fingerprint stability, key permissions
- info payload signing and verification, including tampering
- discovery scanning and self exclusion
- trust store transitions and precedence
- pairing state machine, timeouts, and two-sided commit
- skip suppression
- broker lease selection, fan-out across peers, and busy hysteresis
- wait policy: no eligible remote declines, all-busy postpones, timeout
  declines
- retry policy: transport failures retry, build failures do not

VM tests, three nodes:

- client and builder pair, a build succeeds
- unpaired client is refused
- client-only device cannot be used as a builder
- builder-only device never initiates
- denied device remains visible on the public plane
- one-sided approval does not persist trust
- skip expires, deny persists, revocation returns to neutral
- default-sourced record stops working when the default becomes deny
- two builders, one busy: the client uses the idle one
- all remotes busy: wait off builds locally, wait on postpones
- builder disconnects mid-build: the derivation restarts on the second builder
- builder returns a build failure: no retry
- a builder is busy for the duration of its job and returns to idle after
- the client never gets a daemon connection

CI gates:

- unpaired job request is refused
- denied device is still listed
- no module option stores a secret
- annotated ojuny options remain plain assignments
- a build failure is not retried

## 15. Non-goals

- SSH transport
- changes to NCD
- a certificate authority
- per-user trust, NBD is device scoped
- Windows and macOS
- a binary cache
- verifying input-addressed build output correctness
- transparency: no reattach, no job resumption, no migration of an in-flight
  build
- exact scoping of a build session; skip uses a TTL because the hook runs under
  the shared daemon and cannot see the originating command

## 16. Open questions

- Direct transfer mode: privileged import helper, private store root, or
  `require-sigs = false`.
- Whether the optional matching code is added to the first dialogs.
- Whether the trust store is JSON or SQLite. JSON with an atomic rename is the
  starting point.
- Default skip TTL, idle timeout, and attempt limit.
- Whether the info and build APIs share a port with protocol detection or stay
  on two ports. Two ports is the starting point.
