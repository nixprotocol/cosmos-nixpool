package types

const (
	EventTypeDeposit  = "nixpool_deposit"
	EventTypeTransact = "nixpool_transact"
	EventTypeRegister = "nixpool_register"

	AttributeKeyCommitment     = "commitment"
	AttributeKeyNullifier      = "nullifier"
	AttributeKeyMerkleRoot     = "merkle_root"
	AttributeKeyLeafIndex      = "leaf_index"
	AttributeKeyTreeId         = "tree_id"
	AttributeKeyWithdrawAmount = "withdraw_amount"
	AttributeKeyWithdrawAddr   = "withdraw_address"
	AttributeKeyRelayerFee     = "relayer_fee"
)
