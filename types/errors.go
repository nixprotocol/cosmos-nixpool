package types

import "cosmossdk.io/errors"

var (
	ErrInvalidProof        = errors.Register(ModuleName, 2, "invalid ZK proof")
	ErrNullifierSpent      = errors.Register(ModuleName, 3, "nullifier already spent")
	ErrInvalidMerkleRoot   = errors.Register(ModuleName, 4, "invalid Merkle root")
	ErrTreeFull            = errors.Register(ModuleName, 5, "Merkle tree is full")
	ErrInvalidCommitment   = errors.Register(ModuleName, 6, "invalid commitment")
	ErrInsufficientFunds   = errors.Register(ModuleName, 7, "insufficient funds for deposit")
	ErrInvalidDenom        = errors.Register(ModuleName, 8, "unsupported token denomination")
	ErrInvalidAuditorKey   = errors.Register(ModuleName, 9, "invalid auditor public key")
	ErrAuditorDataMissing  = errors.Register(ModuleName, 10, "auditor encrypted data missing")
	ErrVKNotFound          = errors.Register(ModuleName, 11, "verification key not found")
	ErrInvalidPublicInputs = errors.Register(ModuleName, 12, "invalid public inputs")
	ErrNotRegistered       = errors.Register(ModuleName, 13, "account not registered")
	ErrAuditorDataTooLarge = errors.Register(ModuleName, 14, "auditor encrypted data too large")
	ErrDuplicateCommitment = errors.Register(ModuleName, 15, "duplicate note commitment")
	ErrInvalidNullifier    = errors.Register(ModuleName, 16, "invalid nullifier")
	ErrInvalidWithdraw     = errors.Register(ModuleName, 17, "invalid withdrawal parameters")
)
