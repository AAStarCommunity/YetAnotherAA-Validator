# aNode DVT — cross-language conformance

The aNode's product is its **protocol contract, not its code**. A Node.js / Go /
Rust implementation is a valid aNode **iff** it reproduces `vectors.json`
byte-for-byte from the same inputs. This directory is the language-neutral
acceptance baseline for that.

## Files

- `reference.mjs` — the **canonical reference** (Node.js / `@noble/curves`).
  Generates and self-verifies `vectors.json`; also checks a foreign
  implementation's output.
- `vectors.json` — the frozen golden vectors (committed). Regenerated only via
  `reference.mjs`.

## What it pins (see `docs/design/dvt-node-protocol.md`)

|               | value                                                                                                |
| ------------- | ---------------------------------------------------------------------------------------------------- |
| curve         | BLS12-381 (sig in G2, pubkey in G1)                                                                  |
| DST           | `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` (RFC 9380; **noble defaults `_NUL_` — must override**) |
| messagePoint  | `hashToCurve(userOpHash, {DST})` (G2)                                                                |
| pubkey / sign | `pk = sk·G1.BASE` ; `sig = sk·messagePoint`                                                          |
| aggregate     | `aggSig = Σ sigᵢ` (G2 add) ; `aggPk = Σ pkᵢ` (G1 add)                                                |
| encode        | EIP-2537 — G1 `x@16 y@80` (128B) ; G2 `x.c0@16 x.c1@80 y.c0@144 y.c1@208` (256B)                     |
| wire          | `[nodeId₀..nodeId_{n-1}][aggSig(256B)]` → `AAStarBLSAlgorithm.validate(userOpHash, wire) == 0`       |

## Usage

```bash
# regenerate + self-verify the canonical vectors (Node.js reference)
node conformance/reference.mjs

# CI guard: committed vectors.json must match the reference
npm run conformance        # = node conformance/reference.mjs --check conformance/vectors.json

# verify a Go/Rust implementation's emitted vectors against the canonical
node conformance/reference.mjs --check path/to/impl-vectors.json
```

## How a Go / Rust port proves conformance

1. Read the same `signers` (secret keys, nodeIds) and `cases[].userOpHash` from
   `vectors.json`.
2. Recompute `messagePoint`, each `signature`, the `aggregateSignature`,
   `aggregatePublicKey`, and `wire` using that language's BLS lib (Go:
   `gnark-crypto` / `kilic/bls12-381`; Rust: `blst` / `arkworks`) — **with the
   DST override and the exact EIP-2537 byte layout above**.
3. Emit a `vectors.json` in the same shape and run `reference.mjs --check`.
   Byte-for-byte match = conformant. The highest-risk step is RFC 9380
   `hash_to_curve` + the `_POP_` DST matching across libraries — validate that
   FIRST, before porting the rest of the service.

> This is `#63` item ④ (BLS library parity pre-validation). It is the anti-drift
> backbone for the planned Node/Go/Rust parallel implementations (see issue #63
> and the #45 master index).
