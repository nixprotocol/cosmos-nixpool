package keeper

import (
	"bytes"
	"context"
	"fmt"
	"math/big"

	"cosmossdk.io/math"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/nixprotocol/cosmos-nixpool/types"
	poseidon2 "github.com/nixprotocol/poseidon2-go"
	ultrahonk "github.com/nixprotocol/ultrahonk-go"
)

// GasUltraHonkVerify prices one UltraHonk proof verification.
//
// Cosmos meters store access and transaction bytes, never CPU. Proof
// verification is therefore invisible to the gas meter unless charged
// explicitly, and until this constant existed it was: a transaction carrying a
// deliberately invalid proof paid only for its ~14.6KB of bytes while forcing
// every validator through a full verification that then failed. Register is the
// cheapest such vector, needing no funds and no note ownership.
//
// Measured with ultrahonk-go's BenchmarkVerify: ~1,900μs/op (1.88-2.00ms over
// three runs, Apple M-series). The cost is essentially fixed per proof rather
// than per circuit -- verification always runs a 28-round sumcheck and an MSM
// over 70 commitments -- so one constant covers deposit, registration, and
// transact alike.
//
// Priced at ~200 gas/μs to match the sibling confidential-module, whose Schnorr
// verifications sit in a 132-325 gas/μs band (see its keeper/verify.go). 1,900μs
// x 200 = 380,000, rounded up. Underpricing is the direction that hurts, so this
// deliberately sits at the top of that band: an UltraHonk verify is roughly 5x
// the wall-clock of that module's most expensive Schnorr proof.
const GasUltraHonkVerify = 400_000

// Circuit public input counts
const (
	DepositPICount  = 8  // deposit circuit: 8 public inputs
	TransactPICount = 23 // transact circuit: 23 public inputs
	RegisterPICount = 9  // registration circuit: 9 public inputs
)

// Deposit public input indices
const (
	DepositPICommitment       = 0
	DepositPIAmount           = 1
	DepositPITokenAddress     = 2
	DepositPIAuditorPkX       = 3
	DepositPIAuditorPkY       = 4
	DepositPIAuditorEncCommit = 5
	DepositPIAuditorAuthKeyX  = 6
	DepositPIAuditorAuthKeyY  = 7
)

// Transact public input indices (23 elements, matching NixPool.sol lines 290-320)
const (
	TransactPINullifier1       = 0
	TransactPINullifier2       = 1
	TransactPIMerkleRoot1      = 2
	TransactPIMerkleRoot2      = 3
	TransactPINewNoteHash1     = 4
	TransactPINewNoteHash2     = 5
	TransactPIWithdrawAmount   = 6
	TransactPIWithdrawAddress  = 7
	TransactPITokenAddress     = 8
	TransactPIChainId          = 9
	TransactPIPoolAddress      = 10
	TransactPIRelayerFee       = 11
	TransactPIAuditorEnc1      = 12
	TransactPIAuditorAuthKey1X = 13
	TransactPIAuditorAuthKey1Y = 14
	TransactPIAuditorEnc2      = 15
	TransactPIAuditorAuthKey2X = 16
	TransactPIAuditorAuthKey2Y = 17
	TransactPIAuditorPkX       = 18
	TransactPIAuditorPkY       = 19
	TransactPIRegistrationRoot = 20
	TransactPIAuditorEncRecip1 = 21
	TransactPIAuditorEncRecip2 = 22
)

// Register public input indices
const (
	RegisterPICommitment    = 0
	RegisterPIChainId       = 1
	RegisterPIAuditorPkX    = 2
	RegisterPIAuditorPkY    = 3
	RegisterPIEphemeralX    = 4
	RegisterPIEphemeralY    = 5
	RegisterPIEncryptedAddr = 6
	RegisterPIEncryptedPkX  = 7
	RegisterPIEncryptedPkY  = 8
)

// validCircuitNames defines the set of circuit names that can have VKs stored.
var validCircuitNames = map[string]bool{
	"deposit":      true,
	"transact":     true,
	"registration": true,
}

// NormalizeVKData accepts VK bytes in multiple formats and returns the canonical
// format expected by ultrahonk.DeserializeVK (1752 bytes: 3×uint64 + 27×G1).
//
// Supported input formats:
//   - 1752 bytes: already canonical (3×uint64 header + 27 G1 points)
//   - 1760 bytes: bb write_vk output (4×uint64 header + 27 G1 points) — via DeserializeVKFromBarretenberg
func NormalizeVKData(data []byte) ([]byte, error) {
	switch len(data) {
	case ultrahonk.VKSerializedSize: // 1752 — already canonical
		if _, err := ultrahonk.DeserializeVK(data); err != nil {
			return nil, fmt.Errorf("invalid VK data: %w", err)
		}
		return data, nil

	case ultrahonk.BBVKSize: // 1760 — bb write_vk format (4×uint64 header)
		vk, err := ultrahonk.DeserializeVKFromBarretenberg(data)
		if err != nil {
			return nil, fmt.Errorf("invalid VK data (bb format): %w", err)
		}
		canonical, err := ultrahonk.SerializeVK(vk)
		if err != nil {
			return nil, fmt.Errorf("VK re-serialization failed: %w", err)
		}
		return canonical, nil

	default:
		return nil, fmt.Errorf("unsupported VK size %d bytes (expected %d or %d)",
			len(data), ultrahonk.VKSerializedSize, ultrahonk.BBVKSize)
	}
}

// VerifyProof loads a verification key from on-chain state
// and runs UltraHonk proof verification.
func (k Keeper) VerifyProof(ctx context.Context, circuitName string, proof []byte, publicInputs []fr.Element) error {
	vk, err := k.getVerificationKey(ctx, circuitName)
	if err != nil {
		return err
	}

	// Charge before verifying, not after: an invalid proof costs a validator the
	// same CPU as a valid one, and the caller must pay for it either way.
	sdk.UnwrapSDKContext(ctx).GasMeter().ConsumeGas(GasUltraHonkVerify, "ultrahonk proof verification")

	verified, err := ultrahonk.Verify(vk, proof, publicInputs)
	if err != nil {
		return types.ErrInvalidProof.Wrapf("verification error: %v", err)
	}
	if !verified {
		return types.ErrInvalidProof.Wrap("proof verification failed")
	}

	return nil
}

// getVerificationKey retrieves the VK for the given circuit from on-chain state.
// VKs must be set via MsgSetVerificationKey (governance) or genesis before use.
func (k Keeper) getVerificationKey(ctx context.Context, circuitName string) (*ultrahonk.VerificationKey, error) {
	vkData, err := k.GetVerificationKeyFromState(ctx, circuitName)
	if err != nil {
		return nil, err
	}
	if vkData == nil {
		return nil, types.ErrVKNotFound.Wrapf("no verification key for circuit: %s (set via governance or genesis)", circuitName)
	}
	return ultrahonk.DeserializeVK(vkData)
}

// ParsePublicInputs extracts fr.Element values from raw public input bytes.
// Each public input is a 32-byte big-endian field element in canonical form.
//
// Non-canonical encodings are rejected rather than reduced. fr.Element.SetBytes
// silently reduces mod p, so N, N+p, N+2p ... are the same value to the
// verifier but different byte strings on the wire — the proof verifies
// identically under all of them. That is the same shape as the nullifier
// double-spend (one value, several encodings), so every field element gets
// exactly one accepted wire form here too.
func ParsePublicInputs(data []byte) ([]fr.Element, error) {
	if len(data)%32 != 0 {
		return nil, fmt.Errorf("public inputs length %d not a multiple of 32", len(data))
	}
	n := len(data) / 32
	inputs := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		chunk := data[i*32 : (i+1)*32]
		if new(big.Int).SetBytes(chunk).Cmp(fr.Modulus()) >= 0 {
			return nil, fmt.Errorf("public input %d is not a canonical field element (>= modulus)", i)
		}
		inputs[i].SetBytes(chunk)
	}
	return inputs, nil
}

// stringToFieldElement deterministically maps an arbitrary-length string to a
// BN254 field element.
//
// The bytes are split into 31-byte limbs so every limb is smaller than the
// field modulus, and the byte length is absorbed first so strings differing
// only by leading NUL bytes cannot collide. Poseidon2 folds the input count
// into its IV, so limb sequences of different lengths stay distinct.
//
// Passing a string longer than 32 bytes straight to fr.Element.SetBytes would
// instead reduce it mod p, silently mapping distinct strings (two bech32
// addresses, or two "ibc/..." denoms) onto the same field element.
func stringToFieldElement(s string) fr.Element {
	b := []byte(s)

	const limbSize = 31
	limbs := make([]fr.Element, 0, 2+len(b)/limbSize)

	var lenElem fr.Element
	lenElem.SetUint64(uint64(len(b)))
	limbs = append(limbs, lenElem)

	for i := 0; i < len(b); i += limbSize {
		end := i + limbSize
		if end > len(b) {
			end = len(b)
		}
		var limb fr.Element
		limb.SetBytes(b[i:end])
		limbs = append(limbs, limb)
	}

	return poseidon2.Hash(limbs)
}

// DenomToFieldElement deterministically maps a Cosmos denom string to a BN254 field element.
func DenomToFieldElement(denom string) fr.Element {
	return stringToFieldElement(denom)
}

// AddressToFieldElement deterministically maps a bech32 address to a BN254
// field element. Addresses are ~45 bytes, so they must be hashed rather than
// reduced.
func AddressToFieldElement(addr string) fr.Element {
	return stringToFieldElement(addr)
}

// verifyAuditorPublicInputs checks that the auditor public key committed to by
// a proof is the auditor key currently configured in params.
//
// Without this the prover picks the auditor key themselves, encrypts the
// auditor payload under a key they control, and the real auditor is left with
// ciphertext it cannot read — silently defeating the auditability the circuits
// exist to provide.
func verifyAuditorPublicInputs(piX, piY fr.Element, auditorPubKey []byte) error {
	if len(auditorPubKey) == 0 {
		// No auditor configured: nothing to bind against. Unlike chain binding,
		// "no auditor yet" is a legitimate deployment state — governance sets
		// the key after launch — and enforceAuditor already requires auditor
		// data once a key exists.
		return nil
	}
	if len(auditorPubKey) < 64 {
		return types.ErrInvalidPublicInputs.Wrapf(
			"configured auditor public key must be 64 bytes, got %d", len(auditorPubKey))
	}

	var expectedX, expectedY fr.Element
	expectedX.SetBytes(auditorPubKey[:32])
	expectedY.SetBytes(auditorPubKey[32:64])

	if piX != expectedX || piY != expectedY {
		return types.ErrInvalidPublicInputs.Wrap("public input auditor key does not match configured auditor key")
	}
	return nil
}

// VerifyRegisterPublicInputs checks that a registration proof is bound to the
// commitment actually being inserted, to this chain, and to the configured
// auditor key.
//
// Registration proofs are public once a transaction lands, so without the
// commitment binding anyone could replay someone else's proof while inserting a
// commitment of their own — entering the registration tree without ever
// encrypting their identity to the auditor.
func VerifyRegisterPublicInputs(publicInputs []fr.Element, identityCommitment []byte, params types.Params) error {
	if len(publicInputs) != RegisterPICount {
		return types.ErrInvalidPublicInputs.Wrapf(
			"registration circuit requires %d public inputs, got %d", RegisterPICount, len(publicInputs))
	}

	// Bind commitment: publicInputs[0] must equal the commitment being inserted.
	piCommitmentBytes := publicInputs[RegisterPICommitment].Bytes()
	if !bytes.Equal(piCommitmentBytes[:], identityCommitment) {
		return types.ErrInvalidPublicInputs.Wrap("public input commitment does not match identity_commitment")
	}

	// Bind chain_id: prevents replaying a registration across deployments.
	//
	// This fails closed. Treating an unset ChainBinding as "nothing to check"
	// would silently disable the binding in exactly the configuration where it
	// is easiest to forget — the default one — leaving registration proofs
	// replayable across deployments. Every deployment has a chain identity, so
	// there is no legitimate unset case.
	if len(params.ChainBinding) == 0 {
		return types.ErrInvalidPublicInputs.Wrap(
			"chain binding not configured; set params.chain_binding before accepting registrations")
	}
	var expectedChain fr.Element
	expectedChain.SetBytes(params.ChainBinding)
	if publicInputs[RegisterPIChainId] != expectedChain {
		return types.ErrInvalidPublicInputs.Wrap("public input chain_id does not match chain binding")
	}

	// Bind auditor key.
	return verifyAuditorPublicInputs(
		publicInputs[RegisterPIAuditorPkX],
		publicInputs[RegisterPIAuditorPkY],
		params.AuditorPubKey,
	)
}

// VerifyDepositPublicInputs checks that the proof's public inputs match the
// message fields, preventing a valid proof from being used with mismatched amounts.
func VerifyDepositPublicInputs(publicInputs []fr.Element, noteCommitment []byte, amount math.Int, denom string, params types.Params) error {
	if len(publicInputs) != DepositPICount {
		return types.ErrInvalidPublicInputs.Wrapf(
			"deposit circuit requires %d public inputs, got %d", DepositPICount, len(publicInputs))
	}

	// Bind commitment: publicInputs[0] must equal noteCommitment
	piCommitmentBytes := publicInputs[DepositPICommitment].Bytes()
	if !bytes.Equal(piCommitmentBytes[:], noteCommitment) {
		return types.ErrInvalidPublicInputs.Wrap("public input commitment does not match note_commitment")
	}

	// Bind amount: publicInputs[1] must equal amount
	var expectedAmount fr.Element
	expectedAmount.SetBigInt(amount.BigInt())
	if publicInputs[DepositPIAmount] != expectedAmount {
		return types.ErrInvalidPublicInputs.Wrap("public input amount does not match message amount")
	}

	// Bind token_address: publicInputs[2] must equal DenomToFieldElement(denom)
	expectedDenom := DenomToFieldElement(denom)
	if publicInputs[DepositPITokenAddress] != expectedDenom {
		return types.ErrInvalidPublicInputs.Wrap("public input token_address does not match denom")
	}

	// Bind auditor key: publicInputs[3..4] must equal the configured auditor key.
	return verifyAuditorPublicInputs(
		publicInputs[DepositPIAuditorPkX],
		publicInputs[DepositPIAuditorPkY],
		params.AuditorPubKey,
	)
}

// AssembleTransactPublicInputs constructs the 23-element public input array
// in the exact circuit order for transact proof verification.
func AssembleTransactPublicInputs(msg *types.MsgTransact, params types.Params, moduleAccAddr []byte) ([]fr.Element, error) {
	pi := make([]fr.Element, TransactPICount)

	// [0-1] nullifiers
	pi[TransactPINullifier1].SetBytes(msg.Nullifiers[0])
	pi[TransactPINullifier2].SetBytes(msg.Nullifiers[1])

	// [2-3] merkle roots
	pi[TransactPIMerkleRoot1].SetBytes(msg.MerkleRoots[0])
	pi[TransactPIMerkleRoot2].SetBytes(msg.MerkleRoots[1])

	// [4-5] new note hashes
	pi[TransactPINewNoteHash1].SetBytes(msg.Outputs[0].NoteHash)
	pi[TransactPINewNoteHash2].SetBytes(msg.Outputs[1].NoteHash)

	// [6] withdraw amount
	if msg.WithdrawAmount != "" && msg.WithdrawAmount != "0" {
		amt, ok := math.NewIntFromString(msg.WithdrawAmount)
		if !ok {
			return nil, fmt.Errorf("invalid withdraw amount")
		}
		pi[TransactPIWithdrawAmount].SetBigInt(amt.BigInt())
	}

	// [7] withdraw address (hashed — a bech32 address does not fit in a field element)
	if msg.WithdrawAddress != "" {
		pi[TransactPIWithdrawAddress] = AddressToFieldElement(msg.WithdrawAddress)
	}

	// [8] token address
	if msg.Denom != "" {
		pi[TransactPITokenAddress] = DenomToFieldElement(msg.Denom)
	}

	// [9] chain_id (from params)
	//
	// Fails closed for the same reason as VerifyRegisterPublicInputs: leaving
	// this at zero when the param is unset would silently accept proofs built
	// for any deployment.
	if len(params.ChainBinding) == 0 {
		return nil, fmt.Errorf(
			"chain binding not configured; set params.chain_binding before accepting transactions")
	}
	pi[TransactPIChainId].SetBytes(params.ChainBinding)

	// [10] pool_address — module account address as field element
	if len(moduleAccAddr) > 0 {
		pi[TransactPIPoolAddress].SetBytes(moduleAccAddr)
	}

	// [11] relayer fee
	if msg.RelayerFee != "" && msg.RelayerFee != "0" {
		fee, ok := math.NewIntFromString(msg.RelayerFee)
		if !ok {
			return nil, fmt.Errorf("invalid relayer fee")
		}
		pi[TransactPIRelayerFee].SetBigInt(fee.BigInt())
	}

	// [12-17] auditor encrypted data per output
	pi[TransactPIAuditorEnc1].SetBytes(msg.Outputs[0].AuditorEnc)
	pi[TransactPIAuditorAuthKey1X].SetBytes(msg.Outputs[0].AuditorAuthKeyX)
	pi[TransactPIAuditorAuthKey1Y].SetBytes(msg.Outputs[0].AuditorAuthKeyY)
	pi[TransactPIAuditorEnc2].SetBytes(msg.Outputs[1].AuditorEnc)
	pi[TransactPIAuditorAuthKey2X].SetBytes(msg.Outputs[1].AuditorAuthKeyX)
	pi[TransactPIAuditorAuthKey2Y].SetBytes(msg.Outputs[1].AuditorAuthKeyY)

	// [18-19] auditor public key
	if len(params.AuditorPubKey) >= 64 {
		pi[TransactPIAuditorPkX].SetBytes(params.AuditorPubKey[:32])
		pi[TransactPIAuditorPkY].SetBytes(params.AuditorPubKey[32:64])
	}

	// [20] registration root
	pi[TransactPIRegistrationRoot].SetBytes(msg.RegistrationRoot)

	// [21-22] auditor enc recipient per output
	pi[TransactPIAuditorEncRecip1].SetBytes(msg.Outputs[0].AuditorEncRecipient)
	pi[TransactPIAuditorEncRecip2].SetBytes(msg.Outputs[1].AuditorEncRecipient)

	return pi, nil
}

// Transact deliberately has no VerifyTransactPublicInputs counterpart: the
// handler builds the public input vector itself via AssembleTransactPublicInputs
// and hands that to the verifier, so there is nothing caller-supplied left to
// cross-check. Deposit and Register accept a caller-supplied public input
// vector (it carries auditor ciphertext the chain cannot recompute) and so must
// verify the constrained subset explicitly.
