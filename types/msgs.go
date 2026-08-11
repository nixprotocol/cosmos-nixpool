package types

import (
	"fmt"
	"math/big"

	"cosmossdk.io/math"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

var isZero32 [32]byte

// ---------- MsgRegister ----------

func (msg *MsgRegister) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(msg.Sender); err != nil {
		return err
	}
	if err := validateFieldBytes(msg.IdentityCommitment, "identity commitment"); err != nil {
		return ErrInvalidCommitment.Wrap(err.Error())
	}
	if len(msg.Proof) == 0 {
		return ErrInvalidProof.Wrap("proof cannot be empty")
	}
	if len(msg.PublicInputs) < 32 {
		return ErrInvalidPublicInputs.Wrap("public inputs must contain at least one field element (32 bytes)")
	}
	if len(msg.AuditorEncryptedData) > MaxAuditorDataSize {
		return ErrAuditorDataTooLarge.Wrapf("auditor data %d bytes exceeds max %d", len(msg.AuditorEncryptedData), MaxAuditorDataSize)
	}
	return nil
}

func (msg *MsgRegister) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(msg.Sender)
	return []sdk.AccAddress{addr}
}

var _ sdk.Msg = &MsgRegister{}

// ---------- MsgDeposit ----------

func (msg *MsgDeposit) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(msg.Sender); err != nil {
		return err
	}
	if err := sdk.ValidateDenom(msg.Denom); err != nil {
		return ErrInvalidDenom.Wrap(err.Error())
	}
	amt, ok := math.NewIntFromString(msg.Amount)
	if !ok || !amt.IsPositive() {
		return ErrInsufficientFunds.Wrap("deposit amount must be a positive integer")
	}
	if err := validateFieldBytes(msg.NoteCommitment, "note commitment"); err != nil {
		return ErrInvalidCommitment.Wrap(err.Error())
	}
	if len(msg.Proof) == 0 {
		return ErrInvalidProof.Wrap("proof cannot be empty")
	}
	if len(msg.PublicInputs) < 32 {
		return ErrInvalidPublicInputs.Wrap("public inputs must contain at least one field element (32 bytes)")
	}
	if len(msg.AuditorEncryptedData) > MaxAuditorDataSize {
		return ErrAuditorDataTooLarge.Wrapf("auditor data %d bytes exceeds max %d", len(msg.AuditorEncryptedData), MaxAuditorDataSize)
	}
	return nil
}

// Coin returns the deposit amount as an sdk.Coin.
func (msg *MsgDeposit) Coin() sdk.Coin {
	amt, _ := math.NewIntFromString(msg.Amount)
	return sdk.NewCoin(msg.Denom, amt)
}

func (msg *MsgDeposit) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(msg.Sender)
	return []sdk.AccAddress{addr}
}

var _ sdk.Msg = &MsgDeposit{}

// ---------- MsgTransact (2-in/2-out) ----------

// validateFieldBytes checks that b is a 32-byte field element in CANONICAL
// form, i.e. strictly less than the BN254 scalar modulus.
//
// Length alone is not enough. Circuit public inputs are parsed with
// fr.Element.SetBytes, which reduces mod p, so N, N+p, N+2p ... are all the
// same value to a proof but different byte strings to anything that keys off
// the raw bytes. Rejecting non-canonical encodings here means a single value
// has exactly one accepted wire form.
func validateFieldBytes(b []byte, what string) error {
	if len(b) != 32 {
		return fmt.Errorf("%s must be 32 bytes, got %d", what, len(b))
	}
	if new(big.Int).SetBytes(b).Cmp(fr.Modulus()) >= 0 {
		return fmt.Errorf("%s is not a canonical field element (>= modulus)", what)
	}
	return nil
}

// validateAmount checks a decimal-string amount is non-negative and fits in 64
// bits.
//
// The circuit range-checks amounts to 64 bits, and AssembleTransactPublicInputs
// binds them via SetBigInt, which reduces mod p — so an amount at or above the
// modulus would be bound as its reduced value while the handler pays out the
// full math.Int. Same reduce-vs-pay shape as the nullifier bug. Not reachable
// today (it needs an amount above ~2.19e76, far beyond any supply), but the
// range the circuit actually proves should be the range accepted here.
func validateAmount(sVal string, what string) error {
	amt, ok := math.NewIntFromString(sVal)
	if !ok || amt.IsNegative() {
		return fmt.Errorf("invalid %s", what)
	}
	if !amt.IsUint64() {
		return fmt.Errorf("%s exceeds the 64-bit range the circuit proves", what)
	}
	return nil
}

func (msg *MsgTransact) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(msg.Sender); err != nil {
		return err
	}

	// Exactly 2 nullifiers
	if len(msg.Nullifiers) != 2 {
		return ErrInvalidNullifier.Wrap("exactly 2 nullifiers required")
	}
	for i, n := range msg.Nullifiers {
		if err := validateFieldBytes(n, "nullifier"); err != nil {
			return ErrInvalidNullifier.Wrapf("nullifier %d: %v", i, err)
		}
	}

	// Exactly 2 merkle roots
	if len(msg.MerkleRoots) != 2 {
		return ErrInvalidMerkleRoot.Wrap("exactly 2 merkle roots required")
	}
	for i, r := range msg.MerkleRoots {
		if err := validateFieldBytes(r, "merkle root"); err != nil {
			return ErrInvalidMerkleRoot.Wrapf("merkle root %d: %v", i, err)
		}
	}

	// Exactly 2 outputs
	if len(msg.Outputs) != 2 {
		return ErrInvalidCommitment.Wrap("exactly 2 output notes required")
	}
	for i, o := range msg.Outputs {
		if err := validateFieldBytes(o.NoteHash, "note_hash"); err != nil {
			return ErrInvalidCommitment.Wrapf("output %d: %v", i, err)
		}
	}

	// Registration root
	if err := validateFieldBytes(msg.RegistrationRoot, "registration root"); err != nil {
		return ErrInvalidMerkleRoot.Wrap(err.Error())
	}

	// Withdraw amount (can be 0)
	if msg.WithdrawAmount != "" && msg.WithdrawAmount != "0" {
		if err := validateAmount(msg.WithdrawAmount, "withdraw amount"); err != nil {
			return ErrInvalidWithdraw.Wrap(err.Error())
		}
		amt, _ := math.NewIntFromString(msg.WithdrawAmount)
		if amt.IsPositive() {
			if _, err := sdk.AccAddressFromBech32(msg.WithdrawAddress); err != nil {
				return ErrInvalidWithdraw.Wrap("invalid withdraw address")
			}
		}
	}

	// Denom
	if msg.Denom != "" {
		if err := sdk.ValidateDenom(msg.Denom); err != nil {
			return ErrInvalidDenom.Wrap(err.Error())
		}
	}

	// Relayer fee (can be 0 or empty)
	if msg.RelayerFee != "" && msg.RelayerFee != "0" {
		if err := validateAmount(msg.RelayerFee, "relayer fee"); err != nil {
			return ErrInvalidWithdraw.Wrap(err.Error())
		}
	}

	if len(msg.Proof) == 0 {
		return ErrInvalidProof.Wrap("proof cannot be empty")
	}

	return nil
}

func (msg *MsgTransact) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(msg.Sender)
	return []sdk.AccAddress{addr}
}

var _ sdk.Msg = &MsgTransact{}

// ---------- MsgUpdateParams ----------

func (msg *MsgUpdateParams) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(msg.Authority); err != nil {
		return err
	}
	if msg.Params == nil {
		return ErrInvalidCommitment.Wrap("params cannot be nil")
	}
	return msg.Params.Validate()
}

func (msg *MsgUpdateParams) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(msg.Authority)
	return []sdk.AccAddress{addr}
}

var _ sdk.Msg = &MsgUpdateParams{}

// ---------- MsgSetVerificationKey ----------

func (msg *MsgSetVerificationKey) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(msg.Authority); err != nil {
		return err
	}
	if msg.CircuitName == "" {
		return ErrVKNotFound.Wrap("circuit name cannot be empty")
	}
	if len(msg.VkData) == 0 {
		return ErrVKNotFound.Wrap("vk data cannot be empty")
	}
	return nil
}

func (msg *MsgSetVerificationKey) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(msg.Authority)
	return []sdk.AccAddress{addr}
}

var _ sdk.Msg = &MsgSetVerificationKey{}
