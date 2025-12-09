# DLC_Bridge-FB-BTC
---

## Overview

This bridge enables atomic swaps between Bitcoin (BTC) and Fractal Bitcoin (FB) using DLCs. The mechanism works bidirectionally: users can swap BTC → FB or FB → BTC using the same protocol. Abd the example below showcases a BTC → FB swap.

The Fractal Bitcoin whitepaper states:

> *"If bitcoins on the host chain can be conditionally locked and unlocked (specifically, Discreet Log Contracts are suitable for this), then the same control mechanism can be used across all BCSP layers."*

This implementation demonstrates that concept using DLCs with adaptor signatures.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Workflow](#workflow)
- [Technical Details](#technical-details)
- [Example Transaction](#example-transaction)
- [Security Properties](#security-properties)

---

## How It Works

### Core Mechanism

The bridge uses **Discreet Log Contracts (DLCs)** with **adaptor signatures** instead of traditional hash-based contracts (HTLCs). This provides enhanced privacy since no preimage secrets are revealed on-chain.

| Aspect | HTLC | DLC with Adaptor Signatures |
|--------|------|----------------------------|
| Secret reveal | Preimage visible on-chain | Only adaptor signature visible |
| Privacy | Lower | Higher |
| Verification | Hash operations | Signature verification |

### Shared Adaptor Point

Both Bitcoin and Fractal Bitcoin use identical cryptographic primitives (Taproot, Schnorr signatures, secp256k1). This allows creating two separate contracts—one on each chain—that share a mathematical link through an adaptor point.

When one party claims funds on their chain, they reveal an adaptor signature. The counterparty can extract the secret from that signature and use it to claim funds on the other chain, creating an atomic link without external systems.

---

## Architecture

```
                       ┌─────────────────────────────────────────────────────────────┐
                       │                    Bitcoin Chain (BTC)                      │
                       │                                                             │
                       │  ┌─────────────────────────────────────────────────────┐    │
                       │  │              DLC-A (Taproot Script)                 │    │
                       │  │                                                     │    │
                       │  │  Success Path: Adaptor Sig + Receiver Sig           │    │
                       │  │  Refund Path:  Timeout (CLTV) + Sender Sig          │    │
                       │  │                                                     │    │
                       │  │  Adaptor Point: P = s·G                             │    │
                       │  │  Locks: User A's BTC funds                          │    │
                       │  └─────────────────────────────────────────────────────┘    │
                       │                             ↕                               │
                       │                    Shared Adaptor Point                     │
                       │                    (P = s·G)                                │
                       │                             ↕                               │
                       └─────────────────────────────────────────────────────────────┘
                                                     ↕
                                           (Cryptographic Link)
                                                              ↕
                       ┌─────────────────────────────────────────────────────────────┐
                       │                 Fractal Bitcoin Chain (FB)                  │
                       │                                                             │
                       │  ┌─────────────────────────────────────────────────────┐    │
                       │  │              DLC-B (Taproot Script)                 │    │
                       │  │                                                     │    │
                       │  │  Success Path: Adaptor Sig + Receiver Sig           │    │
                       │  │  Refund Path:  Timeout (CLTV) + Sender Sig          │    │
                       │  │                                                     │    │
                       │  │  Adaptor Point: P = s·G (same as DLC-A)             │    │
                       │  │  Locks: User B's FB funds                           │    │
                       │  └─────────────────────────────────────────────────────┘    │
                       │                                                             │
                       │  Common cryptographic primitives:                           │
                       │  • Taproot (BIP-341)                                        │
                       │  • Schnorr Signatures (BIP-340)                             │
                       │  • secp256k1 elliptic curve                                 │
                       │                                                             │
                       │  Enables identical contract structure on both chains        │
                       └─────────────────────────────────────────────────────────────┘

```

### Components

1. **DLC-A**: Locks funds on the source chain (Bitcoin in this example)
2. **DLC-B**: Locks funds on the destination chain (Fractal Bitcoin in this example)
3. **Shared Adaptor Point**: Mathematical link (`P = s·G`) referenced by both contracts
4. **Adaptor Signature**: Cryptographic proof that enables secret extraction

**Note**: The bridge works bidirectionally. For FB → BTC swaps, DLC-A would be on Fractal Bitcoin and DLC-B on Bitcoin, but the mechanism remains identical.

---

## Workflow

### 1. Setup

```
User A (BTC)                       User B (FB)
   │                                   │
   │  1. Generate adaptor secret s     │
   │  2. Compute adaptor point P = s·G │
   │                                   │
   │  ───────────────────────────>│Share adaptor point P
   │                                   │
```

- User A generates a random 32-byte secret `s`
- Computes the adaptor point `P = s·G` (where G is the generator point)
- Shares `P` with User B (keeps `s` secret)

### 2. Contract Creation

```
User A (BTC)                              User B (FB)
   │                                           │
   │  3. Create DLC-A on Bitcoin               │
   │     • Success: Adaptor Sig + User B Sig   │  
   │     • Refund:  Timeout + User A Sig       │
   │                                           │
   │                                           │  4. Create DLC-B on Fractal Bitcoin
   │                                           │     • Success: Adaptor Sig + User A Sig
   │                                           │     • Refund:  Timeout + User B Sig
   │                                           │
```

- Both contracts reference the same adaptor point `P`
- Each contract has two spending paths: success (with adaptor signature) and refund (after timeout)
- Contracts are created but not yet funded

### 3. Funding

```
User A (BTC)                    User B (FB)
   │                                │
   │  5. Fund DLC-A                 │
   │     Send BTC to DLC-A address  │
   │                                │
   │  ─────────────────────────────>│ 6. Fund DLC-B
   │                                │    Send FB to DLC-B address
   │                                │
```

- User A sends Bitcoin to the DLC-A Taproot address
- User B sends Fractal Bitcoin to the DLC-B Taproot address
- Both transactions are confirmed on their respective chains
- Funds are locked in both contracts

### 4. Claiming

```
User A (BTC)                    User B (FB)
   │                                │
   │                                │  7. Claim DLC-B
   │                                │     • Create adaptor signature using s
   │                                │     • Broadcast transaction
   │                                │
   │              ││────────────────────────────────────
   │              ││                │
   │              \/                │
   │  8. Observe adaptor signature  │
   │     Extract secret s           │
   │                                │
   │  9. Claim DLC-A                │
   │     • Use extracted s          │
   │     • Complete the swap        │
   │                                │
```

**Process:**
1. User B claims DLC-B by creating an adaptor signature (they know `s` from the initial setup)
2. The adaptor signature is broadcast on the Fractal Bitcoin chain
3. User A observes the adaptor signature and extracts the secret `s` using cryptographic extraction
4. User A uses the extracted `s` to create an adaptor signature and claim DLC-A
5. Swap complete: both parties have received their funds

### 5. Refund Path

If either party doesn't claim within the timeout period:

```
User A (BTC)                  User B (FB)
   │                              │
   │  10. Timeout reached         │
   │      Refund DLC-A            │
   │      (using timeout path)    │
   │                              │
   │                              │  11. Timeout reached
   │                              │      Refund DLC-B
   │                              │      (using timeout path)
```

- After the timeout block height, either party can refund their own contract
- No adaptor signature needed—just a regular signature with the timeout condition
- Both parties receive their funds back

---

## Technical Details

### Adaptor Signatures

An adaptor signature is a cryptographic primitive that enables atomic swaps without revealing secrets on-chain.

**Components:**
- Adaptor secret: `s` (32-byte scalar)
- Adaptor point: `P = s·G` (public point on the curve)
- Adaptor signature: A signature that reveals `s` when completed

**Property**: When the adaptor signature is broadcast, anyone can extract `s` from it, but only someone who knows `s` can create the adaptor signature initially.

### Taproot Script Structure

Both DLC-A and DLC-B use Taproot scripts with two spending paths:

```
Taproot Output (P2TR)
│
├── Success Path (Script Leaf)
│   ├── Verify adaptor signature matches adaptor point P
│   └── Verify receiver's signature
│
└── Refund Path (Script Leaf)
    ├── Verify block height >= timeout
    └── Verify sender's signature
```

**Benefits:**
- **Efficiency**: Only the executed path is revealed
- **Privacy**: On-chain, it appears as a regular Taproot spend
- **Flexibility**: Additional conditions can be added in the future

### Atomicity

The atomicity guarantee comes from the shared adaptor point:

1. Both contracts reference the same `P`
2. To claim DLC-B, User B must reveal an adaptor signature
3. This adaptor signature contains `s` (extractable)
4. User A can extract `s` and use it to claim DLC-A
5. **Result**: Both claims happen atomically, or both refund

### Dependencies

This implementation requires:
- Bitcoin and Fractal Bitcoin chains
- Cryptographic proofs (adaptor signatures)
- No oracles
- No relay chains
- No external validators
- No preimage secrets

---

## Example Transaction

The following example demonstrates a BTC → FB swap. The reverse direction (FB → BTC) follows the same process with the roles reversed.

### Swap Parameters
- **Direction**: BTC → FB
- **Amount**: 1,000 sats (BTC) → 235,293,176 sats (FB)
- **Status**: Completed

### Transaction Sequence

#### 1. BTC Funding (DLC-A)
**Transaction**: [6609890c7c65d38a29f61a099ed0055ee37a2e183016703d07612d5236477415](https://mempool.space/tx/6609890c7c65d38a29f61a099ed0055ee37a2e183016703d07612d5236477415)

- User A locks 1,000 sats in a Taproot DLC-A contract
- Contract includes adaptor point and CLTV timeout
- Funds are locked and cannot be spent without the adaptor signature

#### 2. FB Funding (DLC-B)
**Transaction**: [5aa38176b9cc1c8af5a04e68bd660035317bbeea2228a442760f08836abb99c9](https://mempool.fractalbitcoin.io/tx/5aa38176b9cc1c8af5a04e68bd660035317bbeea2228a442760f08836abb99c9)

- User B locks 235,293,176 sats in a Taproot DLC-B contract
- Uses the same adaptor point as DLC-A
- Mirrored script structure with opposite roles

#### 3. User A Claim on FB (DLC-B Success)
**Transaction**: [b478af862692ac4d7c56c75514795fa55db58c0772952af85c23fe0742958e36](https://mempool.fractalbitcoin.io/tx/b478af862692ac4d7c56c75514795fa55db58c0772952af85c23fe0742958e36)

- User A claims DLC-B using adaptor signature
- The Schnorr signature revealed here completes the adaptor relation
- This provides User B with the discrete-log scalar (`s`) needed to unlock DLC-A

#### 4. User B Claim on BTC (DLC-A Success)
**Transaction**: [0af54f6ee0b1833d71581c3829bddf45f9721cd4709c0734993750888e6d46be](https://mempool.space/tx/0af54f6ee0b1833d71581c3829bddf45f9721cd4709c0734993750888e6d46be)

- User B extracts `s` from the adaptor signature in step 3
- Uses `s` to create adaptor signature and claim DLC-A
- Swap complete: both parties have their funds

### On-Chain Appearance

To an observer, these transactions appear as normal Taproot script-path spends:
- No preimage hash visible
- No oracle attestation
- No relay chain involvement
- Standard Taproot script execution

The atomic link is established through the cryptographic relationship between the adaptor signatures.

---

## Security Properties

### Atomicity
- **Guarantee**: Either both sides complete or both refund
- **Mechanism**: Shared adaptor point creates cryptographic link
- **Failure Mode**: If one party doesn't claim, both can refund after timeout

### Trustlessness
- **No Intermediaries**: Direct peer-to-peer swaps
- **No Oracles**: No external data sources required
- **No Relay Chains**: No third-party validation needed
- **Self-Executing**: Contracts execute based solely on cryptographic proofs

### Privacy
- **No Secret Reveal**: Adaptor signatures don't directly reveal the secret
- **Taproot Privacy**: Only executed path is revealed on-chain
- **Standard Transactions**: On-chain, swaps appear as normal Taproot spends

### Timeout Protection
- **Fair Refunds**: Both parties can refund after timeout
- **Block-Based**: Timeouts use block height (not wall-clock time)
- **Chain-Aware**: Timeouts account for different block times (BTC ~10min, FB ~30sec)

---

## Bidirectional Operation

The bridge operates bidirectionally:

- **BTC → FB**: User A funds DLC-A on Bitcoin, User B funds DLC-B on Fractal Bitcoin
- **FB → BTC**: User A funds DLC-A on Fractal Bitcoin, User B funds DLC-B on Bitcoin

The mechanism is identical in both directions—only the chain assignments change. The example above demonstrates BTC → FB, but the reverse follows the same process.

---

### Potential/Theoretical Applications

The Fractal Bitcoin whitepaper proposes a mechanism for preserving Ordinals when bridging:

> *"Recognizing that the value of Ordinals is closely tied not only to the stored data but also directly related to the unique satoshis (and their numbering), a mechanism is proposed to lock and map specific satoshis on the main chain to the instance. This allows the circulation of Ordinals there and, when needed, unlocking and returning the specific satoshis along with their corresponding inscriptions."*

**How it could work:**
1. Lock the UTXO containing the Ordinal in a DLC on Bitcoin (preserving the specific satoshi)
2. Extract and include the inscription data in the bridge transaction metadata
3. Create a corresponding UTXO on Fractal Bitcoin with the inscription data re-inscribed
4. Maintain a mapping between the Bitcoin satoshi and the Fractal Bitcoin representation
5. Use the same DLC mechanism to unlock and return the satoshi with its inscription

**Challenges:**
- Satoshi numbering is chain-specific (Bitcoin's satoshi #12345 ≠ FB's satoshi #12345)
- Requires inscription data extraction and re-inscription on the destination chain, or data preservation if possible.
- Needs coordination with indexers for BRC-20 balance tracking
- Requires metadata preservation and verification mechanisms

**Feasibility:** The DLC mechanism can lock UTXOs containing Ordinals, and the inscription data can be preserved in transaction metadata. The main challenge is maintaining the satoshi identity mapping and coordinating with off-chain indexers correctly.

### BRC-20 and Token Transfers

BRC-20 token transfers would require:
- Off-chain indexer coordination to track token balances
- Metadata preservation in bridge transactions
- Verification mechanisms to ensure token supply integrity
- Coordination between Bitcoin and Fractal Bitcoin indexers
---

## Notes

- This document provides an overview of the bridge mechanism
- Implementation details and code will be published separately
- All examples here use real mainnet transactions
- The mechanism requires careful timeout configuration for production use

---

## Implementation Note

This implementation demonstrates a DLC-based atomic swap bridge between Bitcoin and Fractal Bitcoin using adaptor signatures.

**Technical Approach:** This implementation applies the theoretical "Elevator" bridging primitive described in the Fractal Bitcoin whitepaper, demonstrating:
- DLC-based atomic swaps between Bitcoin and Fractal Bitcoin
- Adaptor signature-based secret extraction across chains
- Taproot script construction for cross-chain DLC coordination
- Real-world mainnet transaction examples

This work builds on open-source Bitcoin primitives (Taproot, Schnorr signatures, DLCs) and the Fractal Bitcoin whitepaper. If you build upon this implementation, we ask that you provide appropriate attribution.

---

**Built for Bitcoin/Fractal Bitcoin**

*This README explains the bridge mechanism. For implementation details, code, and deployment instructions, please reach out in telegram group at https://t.me/FractalBits or X : https://x.com/Fractal_TLB .*
