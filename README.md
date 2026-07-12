# Idena Legacy Compatibility Stack

This repository defines the reviewed source and artifact set for the
`ubiubi18` Idena compatibility fork. It is a release manifest and verification
tooling repository; it does not define a new chain, genesis, network, protocol,
or consensus upgrade.

`stack-lock.json` is intentionally marked `candidate` until every gate in
`requiredGates` has passed. A green unit-test run alone is not sufficient to
change that status.

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
  --to-height 10001000
```

The comparator prints only heights and canonical response digests. It never
prints RPC keys, endpoints, block contents, transactions, wallet data, or
identity addresses.

## Release rule

A compatibility release must preserve all values under `chainInvariants`, use
the exact component revisions and artifact digests in the lock, pass the full
legacy replay and cross-architecture Wasm gates, and be published from an
immutable signed tag. Local database and IPFS repository formats may evolve,
but that is data-directory compatibility and must not be represented as chain
or consensus compatibility.
