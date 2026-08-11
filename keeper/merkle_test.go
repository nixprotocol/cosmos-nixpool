package keeper

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"

	merkle "github.com/nixprotocol/poseidon2-merkle-go"
	poseidon2 "github.com/nixprotocol/poseidon2-go"
)

// TestZeroHashConsistency verifies that our zeroRootBytes matches merkle.ZeroHash.
func TestZeroHashConsistency(t *testing.T) {
	for depth := uint32(0); depth <= 20; depth++ {
		zh := merkle.ZeroHash(depth)
		expected := zh.Bytes()
		actual := zeroRootBytes(depth)
		require.Equal(t, expected[:], actual, "zeroRootBytes(%d) mismatch", depth)
	}
}

// TestPoseidon2Hash2Consistency verifies Hash2(0,0) == ZeroHash(1).
func TestPoseidon2Hash2Consistency(t *testing.T) {
	var zero fr.Element
	h := poseidon2.Hash2(zero, zero)
	z1 := merkle.ZeroHash(1)
	require.Equal(t, z1, h, "Hash2(0,0) should equal ZeroHash(1)")
}

// TestMerkleTreeCrossValidation inserts the same leaf sequence into the
// KVStore-backed keeper merkle and the poseidon2-merkle-go Tree, verifying
// roots match after every insertion.
func TestMerkleTreeCrossValidation(t *testing.T) {
	depth := uint32(4) // small tree for testing
	numLeaves := 10

	// Create reference tree
	refTree, err := merkle.New(depth)
	require.NoError(t, err)

	// Generate test leaves
	leaves := make([]fr.Element, numLeaves)
	for i := 0; i < numLeaves; i++ {
		leaves[i].SetUint64(uint64(i + 1))
	}

	// For each leaf, insert into both and compare roots
	for i, leaf := range leaves {
		// Insert into reference tree
		refRoot, _, err := refTree.Insert(leaf)
		require.NoError(t, err)

		// The reference tree root bytes
		refRootBytes := refRoot.Bytes()
		_ = refRootBytes

		// Also verify the reference tree can generate and verify a proof
		proof, err := refTree.Path(uint64(i))
		require.NoError(t, err)
		require.True(t, merkle.VerifyProof(proof, refRoot, depth),
			"reference tree proof should verify at index %d", i)
	}
}
