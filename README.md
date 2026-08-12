# cosmos-nixpool

A Cosmos SDK **privacy pool**: a shielded UTXO set of Poseidon2 note
commitments with nullifier-based spends, verifying Noir/UltraHonk proofs
natively in Go. Drops into any Cosmos SDK chain, with optional auditor
compliance data enforced once an auditor key is configured.

This is the Cosmos implementation of nixpool. For the *account-model* approach —
balances as ElGamal ciphertexts rather than a UTXO set — see
[`confidential-module`](https://github.com/nixprotocol/confidential-module).

## Quick Start

```bash
go get github.com/nixprotocol/cosmos-nixpool@v0.1.2
```

> **Use v0.1.2 or later on Go 1.26.** Earlier versions pinned the required
> `bytedance/sonic` fix with a `replace` directive, which Go honours only in the
> main module and ignores for imported packages — so consumers resolved the
> broken version and failed to compile.

## Features

- **5 messages**: Register, Deposit, Transact, UpdateParams, SetVerificationKey
- **3 circuits**: deposit, registration, transact (2-in/2-out)
- **Multi-tree forest**: Auto-expanding note trees (2^20 leaves per tree)
- **Withdrawal via Transact**: Set `withdraw_amount > 0` (no separate claim message)
- **UltraHonk verification**: Noir-compatible proof system over BN254
- **Auditor compliance**: ECIES-encrypted data, required on every transaction
  once `auditor_pub_key` is set (unset by default, in which case none is required)
- **Relayer support**: Built-in relayer fee mechanism

## Integration

Wire into your `app.go`:

```go
import (
    nixmodule "github.com/nixprotocol/cosmos-nixpool/module"
    nixkeeper "github.com/nixprotocol/cosmos-nixpool/keeper"
    nixtypes "github.com/nixprotocol/cosmos-nixpool/types"
)

// In NewApp:
app.NixpoolKeeper = nixkeeper.NewKeeper(
    runtime.NewKVStoreService(keys[nixtypes.StoreKey]),
    appCodec,
    app.AccountKeeper.AddressCodec(),
    authtypes.NewModuleAddress(govtypes.ModuleName), // authority, as []byte
    app.BankKeeper,
)

app.ModuleManager.Modules[nixtypes.ModuleName] = nixmodule.NewAppModule(
    appCodec, app.NixpoolKeeper, app.BankKeeper,
)
```

## Module Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `tree_depth` | 20 | Depth of note Merkle trees (2^20 leaves per tree) |
| `reg_tree_depth` | 20 | Depth of registration tree |
| `auditor_pub_key` | nil | Grumpkin public key for auditor (64 bytes) |
| `supported_denoms` | ["anix"] | Whitelisted token denominations |
| `chain_binding` | nil | Poseidon2 hash of chainId for replay protection |

## Messages

| Message | Description |
|---------|-------------|
| `MsgRegister` | Register identity with ZK proof |
| `MsgDeposit` | Shield tokens into the pool |
| `MsgTransact` | 2-in/2-out private transfer (optionally with withdrawal) |
| `MsgUpdateParams` | Governance-only parameter updates |
| `MsgSetVerificationKey` | Governance-only VK updates |

## Queries

| Query | Description |
|-------|-------------|
| `Root` | Current active tree Merkle root |
| `NullifierStatus` | Check if nullifier is spent |
| `TreeInfo` | Forest metadata (tree count, active tree, next index) |
| `Params` | Module parameters |
| `RegistrationRoot` | Registration tree root |
| `AuditorKey` | Current auditor public key |
| `SupportedDenoms` | List of supported denominations |

## Known Limitations

- No ZK-level denom binding (enforced at handler level for v1)
- No chainId binding in circuits (enforced at handler level via ChainBinding param)
- No verification key is embedded in the binary. All three circuits load their
  VK from state, so every one must be supplied via genesis or a
  `MsgSetVerificationKey` governance proposal before that message type works.
- `chain_binding` must be set before the pool is usable. Register and Transact
  fail closed without it, and Deposit now does too — otherwise a pool could
  escrow coins it had no way to release.
- Client-side proof generation requires JS/WASM SDK (not included)
