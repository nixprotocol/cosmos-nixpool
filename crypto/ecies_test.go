package crypto

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	grumpkin "github.com/consensys/gnark-crypto/ecc/grumpkin"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	// Generate a key pair: sk * G = pk
	sk := big.NewInt(42)
	var pk grumpkin.G1Affine
	pk.ScalarMultiplicationBase(sk)

	// Value to encrypt
	var value fr.Element
	value.SetUint64(1000)

	randomness := big.NewInt(7)

	ct, err := Encrypt(value, randomness, pk)
	require.NoError(t, err)

	// Reconstruct authKey point from X,Y
	var authKey grumpkin.G1Affine
	authKey.X.SetBigInt(ct.AuthKeyX.BigInt(new(big.Int)))
	authKey.Y.SetBigInt(ct.AuthKeyY.BigInt(new(big.Int)))

	decrypted := Decrypt(sk, authKey, ct.Encrypted)
	require.Equal(t, value, decrypted, "decrypt should recover original value")
}

func TestEncryptZeroRandomnessFails(t *testing.T) {
	var pk grumpkin.G1Affine
	pk.ScalarMultiplicationBase(big.NewInt(1))

	var value fr.Element
	value.SetUint64(100)

	_, err := Encrypt(value, big.NewInt(0), pk)
	require.Error(t, err, "zero randomness should fail")
}

func TestCounterModeRoundtrip(t *testing.T) {
	sk := big.NewInt(123)
	var pk grumpkin.G1Affine
	pk.ScalarMultiplicationBase(sk)

	values := make([]fr.Element, 3)
	values[0].SetUint64(100)
	values[1].SetUint64(200)
	values[2].SetUint64(300)

	randomness := big.NewInt(77)

	ephemeral, ciphertexts, err := EncryptCounterMode(values, randomness, pk)
	require.NoError(t, err)
	require.Len(t, ciphertexts, 3)

	decrypted := DecryptCounterMode(sk, ephemeral, ciphertexts)
	require.Len(t, decrypted, 3)

	for i := 0; i < 3; i++ {
		require.Equal(t, values[i], decrypted[i], "counter mode value %d mismatch", i)
	}
}

func TestCounterModeZeroRandomnessFails(t *testing.T) {
	var pk grumpkin.G1Affine
	pk.ScalarMultiplicationBase(big.NewInt(1))

	values := []fr.Element{{}}

	_, _, err := EncryptCounterMode(values, big.NewInt(0), pk)
	require.Error(t, err)
}

func TestDifferentKeysDifferentCiphertexts(t *testing.T) {
	sk1 := big.NewInt(10)
	sk2 := big.NewInt(20)

	var pk1, pk2 grumpkin.G1Affine
	pk1.ScalarMultiplicationBase(sk1)
	pk2.ScalarMultiplicationBase(sk2)

	var value fr.Element
	value.SetUint64(500)

	randomness := big.NewInt(5)

	ct1, err := Encrypt(value, randomness, pk1)
	require.NoError(t, err)

	ct2, err := Encrypt(value, randomness, pk2)
	require.NoError(t, err)

	require.NotEqual(t, ct1.Encrypted, ct2.Encrypted, "different keys should produce different ciphertexts")
}
