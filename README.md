# Idena Legacy Compatibility Stack

## Research disclaimer

This is experimental research software. I cannot guarantee its security, correctness, or fitness for any purpose. Use it at your own risk, take responsibility for your decisions, independently verify changes, and stay vigilant.

This repository defines the reviewed source and artifact set for the
`ubiubi18` Idena compatibility fork. It is a release manifest and verification
tooling repository; it does not define a new chain, genesis, network, protocol,
or consensus upgrade.

`stack-lock.json` is intentionally marked `candidate` until every gate in
`requiredGates` has passed. A green unit-test run alone is not sufficient to
change that status. An `approved` lock must bind every gate to a checked-in,
non-symlink JSON evidence file by its exact SHA-256 digest.

The current `rc16` candidate retains the checked rkyv archive migration across
Wasmer, idena-wasm, the native binding, and the node, with regenerated native
archive digests. The Go toolchain advances to the node's required 1.26.8.
Chain identifiers, consensus rules, and the SDK remain unchanged. The compiled
archive ABI changes from 1 to 2; old compiled archives must be rebuilt from
trusted Wasm. This does not establish blockchain state compatibility.
The node also pins the reviewed DHT fork, preserving normal routing-table
admission while excluding nonpublic addresses from the response diversity
filter. Consumer pins describe the intended candidate stack, not verified
deployment.

## Verify the lock

```sh
python3 scripts/verify-stack-lock.py stack-lock.json
python3 -m unittest discover -s tests -v
```

## Compare legacy and compatibility nodes

Run two nodes against separate data directories and expose both RPC endpoints
only on loopback. API keys must be stored in distinct mode-`0600` files.

```sh
python3 scripts/compare-idena-rpc.py \
  --legacy-rpc-url http://127.0.0.1:9009 \
  --legacy-api-key-file /protected/legacy-api.key \
  --modern-rpc-url http://127.0.0.1:9010 \
  --modern-api-key-file /protected/modern-api.key \
  --from-height 10000000 \
  --to-height 10001000 \
  --quiet
```

The comparator rejects unavailable (`null`) blocks instead of treating two
missing responses as a match. It prints only heights and canonical response
digests. It never prints RPC keys, endpoints, block contents, transactions,
wallet data, or identity addresses. `--quiet` emits one aggregate SHA-256
result suitable for an external gate attestation.

## Recorded smoke evidence

[evidence/rc16-bootstrap-smoke.json](evidence/rc16-bootstrap-smoke.json) records
an isolated comparison of official legacy v1.1.2 and the exact rc16 runtime.
Both returned identical bootstrap-block RPC data at height 4,871,137, admitted
each other as gossip peers, and exchanged IPFS payloads in both directions.
The test used the supported local-discovery profile for private Docker
addresses, with external routing disabled.

[evidence/rc16-historical-prefix-replay.json](evidence/rc16-historical-prefix-replay.json)
records a subsequent full-sync replay of historical blocks 4,871,138 through
4,872,000 using separate legacy and modern databases. All 863 canonical block
RPC responses matched, including the state and identity roots. The test nodes
retrieved historical headers, certificates and IPFS bodies from an existing
node; external P2P access was disabled before comparison. This is bounded
historical coverage, not a replay of the complete chain.

These are supporting test records, not passing release-gate attestations. The
replay covers the stated historical prefix; live block or transaction
propagation and full-chain synchronization remain unqualified. The candidate
lock and gate results remain unchanged.

## Release rule

A compatibility release must preserve all values under `chainInvariants`, use
the exact component revisions and artifact digests in the lock, pass the full
legacy replay and cross-architecture Wasm gates, and be published from an
immutable signed tag. Local database and IPFS repository formats may evolve,
but that is data-directory compatibility and must not be represented as chain
or consensus compatibility.
