package keeper

import (
	"os"
	"path/filepath"
	"testing"

	storetypes "cosmossdk.io/store/types"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"
)

// TestUltraHonkVerifyIsGasMetered pins the requirement that SNARK verification
// is charged for.
//
// Cosmos meters store access and transaction bytes, never CPU. An UltraHonk
// verify costs roughly 1.9ms of validator time (ultrahonk-go BenchmarkVerify)
// and is invisible to the gas meter unless charged explicitly. For a while it
// was not: this module had no ConsumeGas call anywhere, so a transaction
// carrying a deliberately invalid proof paid only for its bytes while forcing
// every validator through a full verification.
//
// The charge must happen BEFORE verification, so that a proof which fails still
// pays for the work it caused. That is what this test checks: gas is consumed
// even on the failure path.
func TestUltraHonkVerifyIsGasMetered(t *testing.T) {
	k, _, ctx := setupKeeper(t)

	// A VK must exist, or VerifyProof returns before it ever reaches the meter.
	// The fixture carries an 8-byte header, so normalize as the msg handler does.
	rawVK, err := os.ReadFile(filepath.Join(testdataDir(), "deposit", "vk"))
	require.NoError(t, err)
	vkData, err := NormalizeVKData(rawVK)
	require.NoError(t, err)
	vkCtx := ctx.WithGasMeter(storetypes.NewInfiniteGasMeter())
	require.NoError(t, k.SetVerificationKey(vkCtx, "deposit", vkData))

	meter := storetypes.NewGasMeter(10_000_000)
	ctx = ctx.WithGasMeter(meter)
	before := meter.GasConsumed()

	// Deliberately invalid proof: verification must fail, but must still charge.
	badProof := make([]byte, 14592)
	publicInputs := make([]fr.Element, DepositPICount)

	err = k.VerifyProof(ctx, "deposit", badProof, publicInputs)
	require.Error(t, err, "a garbage proof must not verify")

	charged := meter.GasConsumed() - before
	require.GreaterOrEqual(t, charged, uint64(GasUltraHonkVerify),
		"verification was not gas metered: an attacker could force ~1.9ms of "+
			"validator CPU per message while paying only for transaction bytes")
}

// TestGasConstantIsCalibrated guards the constant against being lowered without
// thought. It is priced at ~200 gas/us against a measured ~1,900us verify, to
// sit in the same band as confidential-module's Schnorr proofs (132-325 gas/us).
// Underpricing is the direction that hurts, so a large reduction here should
// require deliberately updating this test.
func TestGasConstantIsCalibrated(t *testing.T) {
	const measuredMicroseconds = 1_900
	const minGasPerMicrosecond = 100 // half the intended 200, generous floor

	require.GreaterOrEqual(t, uint64(GasUltraHonkVerify),
		uint64(measuredMicroseconds*minGasPerMicrosecond),
		"GasUltraHonkVerify has drifted below %d gas/us against a measured "+
			"%dus verify; re-benchmark before lowering it",
		minGasPerMicrosecond, measuredMicroseconds)
}
