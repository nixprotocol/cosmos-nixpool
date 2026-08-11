package keeper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	"github.com/nixprotocol/cosmos-nixpool/types"
)

type msgServer struct {
	Keeper
}

// NewMsgServerImpl returns an implementation of the MsgServer interface.
func NewMsgServerImpl(keeper Keeper) types.MsgServer {
	return &msgServer{Keeper: keeper}
}

var _ types.MsgServer = msgServer{}

// enforceAuditor checks that auditor data is provided when an auditor key is configured.
func (k msgServer) enforceAuditor(ctx context.Context, hasAuditorData bool) error {
	params, err := k.GetParams(ctx)
	if err != nil {
		return err
	}
	if len(params.AuditorPubKey) > 0 && !hasAuditorData {
		return types.ErrAuditorDataMissing.Wrap("required when auditor key is set")
	}
	return nil
}

// checkDenom validates that the denom is in the supported denoms list.
func (k msgServer) checkDenom(ctx context.Context, denom string) error {
	params, err := k.GetParams(ctx)
	if err != nil {
		return err
	}
	for _, d := range params.SupportedDenoms {
		if d == denom {
			return nil
		}
	}
	return types.ErrInvalidDenom.Wrapf("denom %q not in supported denoms", denom)
}

var isZero32 [32]byte

func isZeroBytes(b []byte) bool {
	return bytes.Equal(b, isZero32[:])
}

// Register handles user identity registration.
func (k msgServer) Register(goCtx context.Context, msg *types.MsgRegister) (*types.MsgRegisterResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if err := k.enforceAuditor(goCtx, len(msg.AuditorEncryptedData) > 0); err != nil {
		return nil, err
	}

	publicInputs, err := ParsePublicInputs(msg.PublicInputs)
	if err != nil {
		return nil, types.ErrInvalidPublicInputs.Wrap(err.Error())
	}

	params, err := k.GetParams(ctx)
	if err != nil {
		return nil, err
	}

	// Bind the proof to the commitment being inserted, to this chain, and to
	// the configured auditor key, before spending gas on verification.
	if err := VerifyRegisterPublicInputs(publicInputs, msg.IdentityCommitment, params); err != nil {
		return nil, err
	}

	if err := k.VerifyProof(ctx, "registration", msg.Proof, publicInputs); err != nil {
		return nil, err
	}

	root, leafIndex, err := k.InsertRegCommitment(ctx, msg.IdentityCommitment)
	if err != nil {
		return nil, err
	}

	if len(msg.AuditorEncryptedData) > 0 {
		txHash := sha256.Sum256(ctx.TxBytes())
		if err := k.StoreAuditorData(ctx, txHash[:], msg.AuditorEncryptedData); err != nil {
			return nil, err
		}
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeRegister,
			sdk.NewAttribute(types.AttributeKeyCommitment, fmt.Sprintf("%x", msg.IdentityCommitment)),
			sdk.NewAttribute(types.AttributeKeyMerkleRoot, fmt.Sprintf("%x", root)),
			sdk.NewAttribute(types.AttributeKeyLeafIndex, fmt.Sprintf("%d", leafIndex)),
		),
	)

	return &types.MsgRegisterResponse{
		LeafIndex:  leafIndex,
		MerkleRoot: root,
	}, nil
}

// Deposit handles shielding tokens from x/bank into the private tree.
func (k msgServer) Deposit(goCtx context.Context, msg *types.MsgDeposit) (*types.MsgDepositResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if err := k.enforceAuditor(goCtx, len(msg.AuditorEncryptedData) > 0); err != nil {
		return nil, err
	}

	publicInputs, err := ParsePublicInputs(msg.PublicInputs)
	if err != nil {
		return nil, types.ErrInvalidPublicInputs.Wrap(err.Error())
	}

	amt, ok := math.NewIntFromString(msg.Amount)
	if !ok {
		return nil, types.ErrInsufficientFunds.Wrap("invalid amount")
	}

	params, err := k.GetParams(ctx)
	if err != nil {
		return nil, err
	}

	// Bind the proof to the message fields and the configured auditor key
	// before spending gas on verification.
	if err := VerifyDepositPublicInputs(publicInputs, msg.NoteCommitment, amt, msg.Denom, params); err != nil {
		return nil, err
	}

	if err := k.VerifyProof(ctx, "deposit", msg.Proof, publicInputs); err != nil {
		return nil, err
	}

	if err := k.checkDenom(goCtx, msg.Denom); err != nil {
		return nil, err
	}

	sender, err := sdk.AccAddressFromBech32(msg.Sender)
	if err != nil {
		return nil, err
	}

	coin := msg.Coin()
	err = k.bankKeeper.SendCoinsFromAccountToModule(
		ctx,
		sender,
		types.ModuleAccountName,
		sdk.NewCoins(coin),
	)
	if err != nil {
		return nil, types.ErrInsufficientFunds.Wrap(err.Error())
	}

	root, leafIndex, _, err := k.InsertNote(ctx, msg.NoteCommitment)
	if err != nil {
		return nil, err
	}

	if len(msg.AuditorEncryptedData) > 0 {
		txHash := sha256.Sum256(ctx.TxBytes())
		if err := k.StoreAuditorData(ctx, txHash[:], msg.AuditorEncryptedData); err != nil {
			return nil, err
		}
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeDeposit,
			sdk.NewAttribute(types.AttributeKeyCommitment, fmt.Sprintf("%x", msg.NoteCommitment)),
			sdk.NewAttribute(types.AttributeKeyMerkleRoot, fmt.Sprintf("%x", root)),
			sdk.NewAttribute(types.AttributeKeyLeafIndex, fmt.Sprintf("%d", leafIndex)),
		),
	)

	return &types.MsgDepositResponse{
		LeafIndex:  leafIndex,
		MerkleRoot: root,
	}, nil
}

// Transact handles 2-in/2-out private transfers with optional withdrawal.
// This replaces the old MsgClaim — withdrawal is now a mode of Transact (withdrawAmount > 0).
func (k msgServer) Transact(goCtx context.Context, msg *types.MsgTransact) (*types.MsgTransactResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// 1. Validate registration root is known
	validRegRoot, err := k.IsValidRegRoot(ctx, msg.RegistrationRoot)
	if err != nil {
		return nil, err
	}
	if !validRegRoot {
		return nil, types.ErrInvalidMerkleRoot.Wrap("unknown registration root")
	}

	// 2. For each non-zero nullifier: check not spent, mark spent, verify merkle root
	for i := 0; i < 2; i++ {
		if isZeroBytes(msg.Nullifiers[i]) {
			continue
		}

		spent, err := k.IsNullifierSpent(ctx, msg.Nullifiers[i])
		if err != nil {
			return nil, err
		}
		if spent {
			return nil, types.ErrNullifierSpent.Wrapf("nullifier %d already spent", i)
		}

		valid, err := k.IsValidRootAnyTree(ctx, msg.MerkleRoots[i])
		if err != nil {
			return nil, err
		}
		if !valid {
			return nil, types.ErrInvalidMerkleRoot.Wrapf("merkle root %d not found in any tree", i)
		}

		if err := k.MarkNullifierSpent(ctx, msg.Nullifiers[i]); err != nil {
			return nil, err
		}

		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypeTransact,
				sdk.NewAttribute(types.AttributeKeyNullifier, fmt.Sprintf("%x", msg.Nullifiers[i])),
			),
		)
	}

	// 3. Assemble and verify proof
	params, err := k.GetParams(ctx)
	if err != nil {
		return nil, err
	}

	moduleAccAddr := sdk.AccAddress(authtypes.NewModuleAddress(types.ModuleAccountName))
	assembled, err := AssembleTransactPublicInputs(msg, params, moduleAccAddr)
	if err != nil {
		return nil, types.ErrInvalidPublicInputs.Wrap(err.Error())
	}

	if err := k.VerifyProof(ctx, "transact", msg.Proof, assembled); err != nil {
		return nil, err
	}

	// 4. Insert non-zero output noteHashes into Merkle tree
	var leafIndices []uint64
	var lastRoot []byte

	for i := 0; i < 2; i++ {
		if isZeroBytes(msg.Outputs[i].NoteHash) {
			continue
		}

		root, leafIndex, _, err := k.InsertNote(ctx, msg.Outputs[i].NoteHash)
		if err != nil {
			return nil, err
		}
		leafIndices = append(leafIndices, leafIndex)
		lastRoot = root

		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypeTransact,
				sdk.NewAttribute(types.AttributeKeyCommitment, fmt.Sprintf("%x", msg.Outputs[i].NoteHash)),
				sdk.NewAttribute(types.AttributeKeyMerkleRoot, fmt.Sprintf("%x", root)),
				sdk.NewAttribute(types.AttributeKeyLeafIndex, fmt.Sprintf("%d", leafIndex)),
			),
		)
	}

	// 5. If withdraw_amount > 0: execute withdrawal
	if msg.WithdrawAmount != "" && msg.WithdrawAmount != "0" {
		withdrawAmt, ok := math.NewIntFromString(msg.WithdrawAmount)
		if !ok || !withdrawAmt.IsPositive() {
			return nil, types.ErrInvalidWithdraw.Wrap("invalid withdraw amount")
		}

		if msg.Denom == "" {
			return nil, types.ErrInvalidDenom.Wrap("denom required for withdrawal")
		}
		if err := k.checkDenom(goCtx, msg.Denom); err != nil {
			return nil, err
		}

		recipient, err := sdk.AccAddressFromBech32(msg.WithdrawAddress)
		if err != nil {
			return nil, types.ErrInvalidWithdraw.Wrapf("invalid withdraw address: %v", err)
		}

		coin := sdk.NewCoin(msg.Denom, withdrawAmt)
		err = k.bankKeeper.SendCoinsFromModuleToAccount(
			ctx,
			types.ModuleAccountName,
			recipient,
			sdk.NewCoins(coin),
		)
		if err != nil {
			return nil, err
		}

		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypeTransact,
				sdk.NewAttribute(types.AttributeKeyWithdrawAmount, msg.WithdrawAmount),
				sdk.NewAttribute(types.AttributeKeyWithdrawAddr, msg.WithdrawAddress),
			),
		)
	}

	// 6. If relayer_fee > 0: pay relayer
	if msg.RelayerFee != "" && msg.RelayerFee != "0" {
		relayerFee, ok := math.NewIntFromString(msg.RelayerFee)
		if !ok || !relayerFee.IsPositive() {
			return nil, types.ErrInvalidWithdraw.Wrap("invalid relayer fee")
		}

		if msg.Denom == "" {
			return nil, types.ErrInvalidDenom.Wrap("denom required for relayer fee")
		}
		// Mirror the withdraw path. The denom is bound as a public input and
		// notes only exist for supported denoms, so this is defence in depth
		// rather than a live hole — but a fee-only transact should not be the
		// one payout path that skips the check.
		if err := k.checkDenom(goCtx, msg.Denom); err != nil {
			return nil, err
		}

		relayer, err := sdk.AccAddressFromBech32(msg.Sender)
		if err != nil {
			return nil, err
		}

		coin := sdk.NewCoin(msg.Denom, relayerFee)
		err = k.bankKeeper.SendCoinsFromModuleToAccount(
			ctx,
			types.ModuleAccountName,
			relayer,
			sdk.NewCoins(coin),
		)
		if err != nil {
			return nil, err
		}

		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypeTransact,
				sdk.NewAttribute(types.AttributeKeyRelayerFee, msg.RelayerFee),
			),
		)
	}

	return &types.MsgTransactResponse{
		LeafIndices: leafIndices,
		MerkleRoot:  lastRoot,
	}, nil
}

// UpdateParams handles governance parameter updates.
func (k msgServer) UpdateParams(goCtx context.Context, msg *types.MsgUpdateParams) (*types.MsgUpdateParamsResponse, error) {
	authorityAddr, err := k.addressCodec.StringToBytes(msg.Authority)
	if err != nil {
		return nil, fmt.Errorf("invalid authority address: %w", err)
	}
	if !bytes.Equal(authorityAddr, k.GetAuthority()) {
		expectedStr, _ := k.addressCodec.BytesToString(k.GetAuthority())
		return nil, fmt.Errorf("unauthorized: expected %s, got %s", expectedStr, msg.Authority)
	}
	if msg.Params == nil {
		return nil, fmt.Errorf("params cannot be nil")
	}
	if err := msg.Params.Validate(); err != nil {
		return nil, err
	}
	if err := k.SetParams(goCtx, *msg.Params); err != nil {
		return nil, err
	}
	return &types.MsgUpdateParamsResponse{}, nil
}

// SetVerificationKey handles governance VK updates.
func (k msgServer) SetVerificationKey(goCtx context.Context, msg *types.MsgSetVerificationKey) (*types.MsgSetVerificationKeyResponse, error) {
	authorityAddr, err := k.addressCodec.StringToBytes(msg.Authority)
	if err != nil {
		return nil, fmt.Errorf("invalid authority address: %w", err)
	}
	if !bytes.Equal(authorityAddr, k.GetAuthority()) {
		expectedStr, _ := k.addressCodec.BytesToString(k.GetAuthority())
		return nil, fmt.Errorf("unauthorized: expected %s, got %s", expectedStr, msg.Authority)
	}
	if !validCircuitNames[msg.CircuitName] {
		return nil, fmt.Errorf("invalid circuit name %q: must be one of deposit, transact, registration", msg.CircuitName)
	}
	canonical, err := NormalizeVKData(msg.VkData)
	if err != nil {
		return nil, fmt.Errorf("invalid VK data: %w", err)
	}
	if err := k.Keeper.SetVerificationKey(goCtx, msg.CircuitName, canonical); err != nil {
		return nil, err
	}
	return &types.MsgSetVerificationKeyResponse{}, nil
}
