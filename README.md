# nix-cosmos-sdk

Reusable privacy module for Cosmos SDK chains. Provides a working privacy pool
with ZK proof verification, shielded transfers, and mandatory auditor compliance.

## Quick Start

```bash
go get github.com/nixprotocol/cosmos-nixpool
```

## Features

- **5 messages**: Register, Deposit, Transact, UpdateParams, SetVerificationKey
- **3 circuits**: deposit, registration, transact (2-in/2-out)
- **Multi-tree forest**: Auto-expanding note trees (2^20 leaves per tree)
- **Withdrawal via Transact**: Set `withdraw_amount > 0` (no separate claim message)
- **UltraHonk verification**: Noir-compatible proof system over BN254
- **Auditor compliance**: Mandatory ECIES-encrypted data for all transactions
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
    appCodec,
    runtime.NewKVStoreService(keys[nixtypes.StoreKey]),
    app.BankKeeper,
    authtypes.NewModuleAddress(govtypes.ModuleName).String(),
)

app.ModuleManager.Modules[nixtypes.ModuleName] = nixmodule.NewAppModule(
    appCodec, app.NixpoolKeeper,
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
- Transact/registration VKs must be set via governance (only deposit VK is hardcoded)
- Client-side proof generation requires JS/WASM SDK (not included)
