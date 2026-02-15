# NexumBit Recovery & Signing Tool

Standalone, self-sovereign tool for recovering funds from NexumBit DLC bridge swaps **without** relying on the NexumBit backend.

## When You Need This

- The NexumBit platform is down or unreachable
- You have a funded DLC swap and need to claim or refund independently
- You want to verify and sign PSBTs offline before broadcasting

## Requirements

```
pip install embit base58 httpx
```

| Package | Required | Purpose |
|---------|----------|---------|
| `embit` | Yes | Schnorr signatures, key derivation, address parsing |
| `base58` | Yes | WIF private key decoding |
| `httpx` | No | Broadcasting transactions (can broadcast manually without it) |

## Usage

```
python signer.py
```

The tool offers two modes:

### Mode 1 — Sign Existing PSBT

Use this when you already have a PSBT hex (e.g., from the NexumBit frontend or another tool).

1. Select network (btc / fb)
2. Paste the PSBT hex
3. Enter your private key (WIF or 64-char raw hex)
4. Enter adaptor secret if needed (the tool detects whether one is required)
5. Optionally broadcast

### Mode 2 — Recover from Recovery Kit

Use this when the NexumBit platform is down and you have a recovery kit JSON.

1. Provide the recovery kit (file path or paste JSON)
2. Review the swap summary
3. Choose an action:
   - **[R] Refund** — build and sign a refund PSBT for your locked DLC A funds (available after timeout)
   - **[C] Claim** — build and sign a claim PSBT for your incoming DLC B funds (adaptor sig auto-embedded)
   - **[SR] Sign pre-built refund PSBT** — sign the refund PSBT that was pre-built into the kit
   - **[SC] Sign pre-built claim PSBT** — sign the claim PSBT that was pre-built into the kit
4. Enter your private key
5. Optionally broadcast

## Recovery Kit

The recovery kit is a JSON file you can download from the NexumBit platform while it's running. It contains everything needed to independently complete or exit your swap:

- DLC contract descriptors (Taproot scripts, control blocks, internal keys)
- Funding transaction details (txid, vout, value)
- Timeout block heights
- Adaptor secret (only included when both DLCs are funded and confirmed)
- Pre-built PSBTs for refund and claim (ready to sign)

**Save your recovery kit as soon as your swap is matched and funded.** If the platform goes down later, you'll have everything you need.

### Getting Your Recovery Kit

While the platform is running, click the "Recovery Kit" button on any active swap, or call the API directly:

```
GET /v1/swap/{swap_id}/recovery-kit?address={your_wallet_address}
```

Save the JSON response to a file.

## Private Key

The tool accepts private keys in two formats:

- **WIF** (Wallet Import Format): starts with `K`, `L`, or `5`
- **Raw hex**: 64 hexadecimal characters (32 bytes)

### How to Get Your Private Key

If you use **UniSat Wallet**, your private key is derived from your seed phrase. To extract it:

1. Use a BIP39-compatible tool to derive keys from your seed phrase
2. Use the derivation path matching your address type:
   - Native SegWit (bc1q...): `m/84'/0'/0'/0/0`
   - Taproot (bc1p...): `m/86'/0'/0'/0/0`
3. The resulting private key can be entered as raw hex

**Security warning**: Never share your private key or seed phrase with anyone. Only enter it into this tool running on your own machine.

## How It Works

### Refund (DLC A)

Your DLC A contains funds you locked. The refund script requires only your signature after the timeout block height:

```
<timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <your_pubkey> OP_CHECKSIG
```

The tool builds a transaction with `nLockTime = timeout`, signs it with your key, and the network will accept it once the block height is reached.

### Claim (DLC B)

Your DLC B contains funds from your counterparty. The claim script requires two signatures — the adaptor secret and your receiver key:

```
<adaptor_point> OP_CHECKSIGVERIFY <your_pubkey> OP_CHECKSIG
```

The tool uses the adaptor secret from your recovery kit to compute the adaptor signature, embeds it in the PSBT, and you sign with your receiver key.

## Security Notes

- The adaptor secret is only included in the recovery kit when **both** DLCs are funded and confirmed. This prevents claiming before the counterparty has locked their funds.
- Having the adaptor secret does **not** let you steal the counterparty's funds. Each DLC's claim script requires a different private key.
- The refund path does **not** require the adaptor secret — only your own key and the timeout.
- Timelock ordering (DLC A timeout > DLC B timeout) ensures both parties have time to claim before refunds become available.

## Manual Broadcasting

If you don't have `httpx` installed, you can broadcast the signed raw transaction manually:

```bash
# Bitcoin
curl -X POST https://mempool.space/api/tx -d '<raw_tx_hex>'

# Fractal Bitcoin
curl -X POST https://mempool.fractalbitcoin.io/api/tx -d '<raw_tx_hex>'
```

## License

This tool is provided as part of the NexumBit open protocol specification. Use at your own risk.
