package keeper

import (
	"bytes"
	"testing"

	"cosmossdk.io/math"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"

	"github.com/nixprotocol/cosmos-nixpool/types"
)

// auditorKey returns a 64-byte auditor key and the two field elements a proof
// must carry to match it.
func auditorKey() ([]byte, fr.Element, fr.Element) {
	raw := make([]byte, 64)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	var x, y fr.Element
	x.SetBytes(raw[:32])
	y.SetBytes(raw[32:64])
	return raw, x, y
}

// TestVerifyRegisterPublicInputs_BindsCommitment is the regression test for the
// registration binding hole.
//
// Registration proofs are public once a transaction lands. Without this check
// anyone could replay someone else's proof while inserting a commitment of their
// own choosing — entering the registration tree without ever encrypting their
// identity to the auditor, which is the entire point of the circuit.
func TestVerifyRegisterPublicInputs_BindsCommitment(t *testing.T) {
	auditorRaw, ax, ay := auditorKey()
	params := types.Params{AuditorPubKey: auditorRaw, ChainBinding: []byte{0x42}}

	honest := bytes.Repeat([]byte{0x11}, 32)
	pi := make([]fr.Element, RegisterPICount)
	pi[RegisterPICommitment].SetBytes(honest)
	pi[RegisterPIChainId].SetBytes(params.ChainBinding)
	pi[RegisterPIAuditorPkX] = ax
	pi[RegisterPIAuditorPkY] = ay

	require.NoError(t, VerifyRegisterPublicInputs(pi, honest, params))

	// The real proof, replayed with an attacker-chosen commitment.
	attacker := bytes.Repeat([]byte{0xAB}, 32)
	err := VerifyRegisterPublicInputs(pi, attacker, params)
	require.Error(t, err, "commitment unrelated to the proof must be rejected")
	require.ErrorIs(t, err, types.ErrInvalidPublicInputs)
}

func TestVerifyRegisterPublicInputs_BindsChainAndAuditor(t *testing.T) {
	auditorRaw, ax, ay := auditorKey()
	params := types.Params{AuditorPubKey: auditorRaw, ChainBinding: []byte{0x42}}
	commitment := bytes.Repeat([]byte{0x11}, 32)

	build := func() []fr.Element {
		pi := make([]fr.Element, RegisterPICount)
		pi[RegisterPICommitment].SetBytes(commitment)
		pi[RegisterPIChainId].SetBytes(params.ChainBinding)
		pi[RegisterPIAuditorPkX] = ax
		pi[RegisterPIAuditorPkY] = ay
		return pi
	}

	// A proof produced for another deployment.
	wrongChain := build()
	wrongChain[RegisterPIChainId].SetUint64(999)
	require.Error(t, VerifyRegisterPublicInputs(wrongChain, commitment, params))

	// An auditor key the prover picked themselves, so the real auditor cannot
	// decrypt the identity payload.
	wrongAuditor := build()
	wrongAuditor[RegisterPIAuditorPkX].SetUint64(7)
	require.Error(t, VerifyRegisterPublicInputs(wrongAuditor, commitment, params))

	// Wrong number of public inputs.
	require.Error(t, VerifyRegisterPublicInputs(build()[:RegisterPICount-1], commitment, params))

	// Fails closed when the chain binding was never configured, rather than
	// silently skipping the check in the default configuration.
	noBinding := types.Params{AuditorPubKey: auditorRaw}
	err := VerifyRegisterPublicInputs(build(), commitment, noBinding)
	require.Error(t, err, "unset chain binding must be rejected, not skipped")
	require.ErrorIs(t, err, types.ErrInvalidPublicInputs)
}

// TestVerifyDepositPublicInputs_BindsAuditor checks that a depositor cannot name
// their own auditor key and hand the real auditor ciphertext it cannot read.
func TestVerifyDepositPublicInputs_BindsAuditor(t *testing.T) {
	auditorRaw, ax, ay := auditorKey()
	params := types.Params{AuditorPubKey: auditorRaw}

	commitment := bytes.Repeat([]byte{0x22}, 32)
	amount := math.NewInt(500)

	build := func() []fr.Element {
		pi := make([]fr.Element, DepositPICount)
		pi[DepositPICommitment].SetBytes(commitment)
		pi[DepositPIAmount].SetBigInt(amount.BigInt())
		pi[DepositPITokenAddress] = DenomToFieldElement("anix")
		pi[DepositPIAuditorPkX] = ax
		pi[DepositPIAuditorPkY] = ay
		return pi
	}

	require.NoError(t, VerifyDepositPublicInputs(build(), commitment, amount, "anix", params))

	rogue := build()
	rogue[DepositPIAuditorPkY].SetUint64(1234)
	err := VerifyDepositPublicInputs(rogue, commitment, amount, "anix", params)
	require.Error(t, err, "attacker-chosen auditor key must be rejected")
	require.ErrorIs(t, err, types.ErrInvalidPublicInputs)

	// With no auditor configured there is nothing to bind against.
	require.NoError(t, VerifyDepositPublicInputs(rogue, commitment, amount, "anix", types.Params{}))
}

// TestStringToFieldElementIsInjective covers the encoding used for denoms and
// withdraw addresses. Feeding a >32-byte string to fr.Element.SetBytes reduces
// it mod p, which silently maps distinct strings onto the same element.
func TestStringToFieldElementIsInjective(t *testing.T) {
	// Two bech32-length addresses differing only in the final character.
	a := "cosmos1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqa"
	b := "cosmos1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqb"
	require.NotEqual(t, AddressToFieldElement(a), AddressToFieldElement(b))

	// Two long IBC denoms.
	d1 := "ibc/" + string(bytes.Repeat([]byte{'A'}, 64))
	d2 := "ibc/" + string(bytes.Repeat([]byte{'B'}, 64))
	require.NotEqual(t, DenomToFieldElement(d1), DenomToFieldElement(d2))

	// Length is absorbed, so a leading NUL is not swallowed by big-endian
	// interpretation.
	require.NotEqual(t, AddressToFieldElement("ab"), AddressToFieldElement("\x00ab"))

	// Still deterministic.
	require.Equal(t, DenomToFieldElement("anix"), DenomToFieldElement("anix"))
}
