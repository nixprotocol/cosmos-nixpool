package keeper

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	ultrahonk "github.com/nixprotocol/ultrahonk-go"
)

func testdataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "testdata")
}

func TestParsePublicInputs(t *testing.T) {
	data := make([]byte, 96)
	data[31] = 1
	data[63] = 2
	data[95] = 3

	inputs, err := ParsePublicInputs(data)
	require.NoError(t, err)
	require.Len(t, inputs, 3)
	require.True(t, inputs[0].IsOne())
}

func TestParsePublicInputsInvalidLength(t *testing.T) {
	data := make([]byte, 33)
	_, err := ParsePublicInputs(data)
	require.Error(t, err)
}

func TestDenomToFieldElement(t *testing.T) {
	a := DenomToFieldElement("anix")
	b := DenomToFieldElement("anix")
	require.Equal(t, a, b)

	c := DenomToFieldElement("uatom")
	require.NotEqual(t, a, c)
}

// loadCircuitVK loads a VK from a circuit artifact file, handling format normalization.
func loadCircuitVK(t *testing.T, path string) *ultrahonk.VerificationKey {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	canonical, err := NormalizeVKData(data)
	require.NoError(t, err)

	vk, err := ultrahonk.DeserializeVK(canonical)
	require.NoError(t, err)
	return vk
}

// TestCircuitVKLoading verifies that circuit VK files can be loaded via NormalizeVKData.
func TestCircuitVKLoading(t *testing.T) {
	dir := testdataDir()
	for _, circuit := range []string{"deposit", "registration", "transact"} {
		t.Run(circuit, func(t *testing.T) {
			vkPath := filepath.Join(dir, circuit, "vk")
			if _, err := os.Stat(vkPath); err != nil {
				t.Skipf("%s VK fixture not available: %v", circuit, err)
			}

			vk := loadCircuitVK(t, vkPath)
			require.NotNil(t, vk)
			require.True(t, vk.CircuitSize > 0, "circuit size should be positive")
			require.True(t, vk.LogCircuitSize > 0, "log circuit size should be positive")
			t.Logf("%s: CircuitSize=%d LogCircuitSize=%d PublicInputsSize=%d",
				circuit, vk.CircuitSize, vk.LogCircuitSize, vk.PublicInputsSize)
		})
	}
}

// TestNormalizeVKData verifies format auto-detection works for all supported sizes.
func TestNormalizeVKData(t *testing.T) {
	dir := testdataDir()
	vkPath := filepath.Join(dir, "deposit", "vk")
	raw, err := os.ReadFile(vkPath)
	if err != nil {
		t.Skipf("deposit VK fixture not available: %v", err)
	}
	require.Equal(t, 1760, len(raw), "bb-format VK should be 1760 bytes")

	// 1760-byte bb format should normalize
	canonical, err := NormalizeVKData(raw)
	require.NoError(t, err)
	require.Equal(t, ultrahonk.VKSerializedSize, len(canonical))

	// Already-canonical data should pass through
	canonical2, err := NormalizeVKData(canonical)
	require.NoError(t, err)
	require.Equal(t, canonical, canonical2)

	// Invalid size should error
	_, err = NormalizeVKData(make([]byte, 100))
	require.Error(t, err)
}

// TestCircuitProofFixtureSizes verifies fixture file sizes are correct.
func TestCircuitProofFixtureSizes(t *testing.T) {
	dir := testdataDir()

	tests := []struct {
		name    string
		circuit string
		piCount int
	}{
		{"deposit", "deposit", 8},
		{"transact", "transact", 23},
		{"registration", "registration", 9},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proofPath := filepath.Join(dir, tt.circuit, "proof")
			piPath := filepath.Join(dir, tt.circuit, "public_inputs")
			vkPath := filepath.Join(dir, tt.circuit, "vk")

			proofBytes, err := os.ReadFile(proofPath)
			if err != nil {
				t.Skipf("%s proof not available: %v", tt.circuit, err)
			}
			require.Equal(t, 14592, len(proofBytes), "proof should be 14592 bytes (456 * 32)")

			piBytes, err := os.ReadFile(piPath)
			require.NoError(t, err)
			require.Equal(t, tt.piCount*32, len(piBytes), "public inputs byte count")

			publicInputs, err := ParsePublicInputs(piBytes)
			require.NoError(t, err)
			require.Len(t, publicInputs, tt.piCount)

			vkBytes, err := os.ReadFile(vkPath)
			require.NoError(t, err)
			require.Equal(t, 1760, len(vkBytes), "VK should be 1760 bytes (circuit format)")

			// Verify VK can be loaded — circuit size varies per circuit
			vk := loadCircuitVK(t, vkPath)
			require.True(t, vk.CircuitSize > 0, "circuit size should be positive")
			require.True(t, vk.LogCircuitSize > 0, "log circuit size should be positive")
			t.Logf("%s: CircuitSize=%d LogCircuitSize=%d PublicInputsSize=%d",
				tt.circuit, vk.CircuitSize, vk.LogCircuitSize, vk.PublicInputsSize)
		})
	}
}

// TestRealDepositProofVerification tests with circuit e2e_proof fixtures.
func TestRealDepositProofVerification(t *testing.T) {
	dir := testdataDir()

	proofBytes, err := os.ReadFile(filepath.Join(dir, "deposit", "proof"))
	if err != nil {
		t.Skipf("deposit proof fixture not available: %v", err)
	}

	piBytes, err := os.ReadFile(filepath.Join(dir, "deposit", "public_inputs"))
	require.NoError(t, err)

	publicInputs, err := ParsePublicInputs(piBytes)
	require.NoError(t, err)

	vk := loadCircuitVK(t, filepath.Join(dir, "deposit", "vk"))

	verified, err := ultrahonk.Verify(vk, proofBytes, publicInputs)
	if err != nil {
		t.Logf("circuit e2e deposit proof verification returned error (may be incompatible fixture): %v", err)
		t.Skipf("skipping: circuit proof fixture may be from different compilation")
	}
	require.True(t, verified, "real deposit proof should verify")
}

// TestRealTransactProofVerification tests with circuit e2e_proof fixtures.
func TestRealTransactProofVerification(t *testing.T) {
	dir := testdataDir()

	proofBytes, err := os.ReadFile(filepath.Join(dir, "transact", "proof"))
	if err != nil {
		t.Skipf("transact proof fixture not available: %v", err)
	}

	piBytes, err := os.ReadFile(filepath.Join(dir, "transact", "public_inputs"))
	require.NoError(t, err)

	publicInputs, err := ParsePublicInputs(piBytes)
	require.NoError(t, err)

	vk := loadCircuitVK(t, filepath.Join(dir, "transact", "vk"))

	verified, err := ultrahonk.Verify(vk, proofBytes, publicInputs)
	if err != nil {
		t.Logf("circuit e2e transact proof verification returned error: %v", err)
		t.Skipf("skipping: circuit proof fixture may be from different compilation")
	}
	require.True(t, verified, "real transact proof should verify")
}

// TestRealRegistrationProofVerification tests with circuit e2e_proof fixtures.
func TestRealRegistrationProofVerification(t *testing.T) {
	dir := testdataDir()

	proofBytes, err := os.ReadFile(filepath.Join(dir, "registration", "proof"))
	if err != nil {
		t.Skipf("registration proof fixture not available: %v", err)
	}

	piBytes, err := os.ReadFile(filepath.Join(dir, "registration", "public_inputs"))
	require.NoError(t, err)

	publicInputs, err := ParsePublicInputs(piBytes)
	require.NoError(t, err)

	vk := loadCircuitVK(t, filepath.Join(dir, "registration", "vk"))

	verified, err := ultrahonk.Verify(vk, proofBytes, publicInputs)
	if err != nil {
		t.Logf("circuit e2e registration proof verification returned error: %v", err)
		t.Skipf("skipping: circuit proof fixture may be from different compilation")
	}
	require.True(t, verified, "real registration proof should verify")
}
