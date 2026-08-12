// Package crypto provides ECIES encryption over the Grumpkin curve.
//
// This implements the same ECIES scheme used in NixProtocol's Noir circuits,
// using Poseidon2 for key derivation and the Grumpkin embedded curve
// (which is defined over the BN254 scalar field).
package crypto

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	grumpkin "github.com/consensys/gnark-crypto/ecc/grumpkin"

	poseidon2 "github.com/nixprotocol/poseidon2-go"
)

// ECIESCiphertext contains the encrypted value and ephemeral key.
type ECIESCiphertext struct {
	AuthKeyX  fr.Element
	AuthKeyY  fr.Element
	Encrypted fr.Element
}

// Encrypt encrypts a single field element value under the receiver's Grumpkin public key.
//
//	authKey = randomness * G  (ephemeral public key)
//	shared  = randomness * receiverPk  (ECDH)
//	key     = Poseidon2([shared.x, shared.y])
//	encrypted = value + key (mod P)
func Encrypt(value fr.Element, randomness *big.Int, receiverPk grumpkin.G1Affine) (ECIESCiphertext, error) {
	if randomness.Sign() == 0 {
		return ECIESCiphertext{}, fmt.Errorf("randomness must be non-zero")
	}

	// authKey = randomness * G
	var authKey grumpkin.G1Affine
	authKey.ScalarMultiplicationBase(randomness)

	// shared = randomness * receiverPk
	var shared grumpkin.G1Affine
	shared.ScalarMultiplication(&receiverPk, randomness)

	// key = Poseidon2([shared.x, shared.y])
	var sharedX, sharedY fr.Element
	sharedX.SetBigInt(shared.X.BigInt(new(big.Int)))
	sharedY.SetBigInt(shared.Y.BigInt(new(big.Int)))

	key := poseidon2.Hash2(sharedX, sharedY)

	// encrypted = value + key
	var encrypted fr.Element
	encrypted.Add(&value, &key)

	var authKeyX, authKeyY fr.Element
	authKeyX.SetBigInt(authKey.X.BigInt(new(big.Int)))
	authKeyY.SetBigInt(authKey.Y.BigInt(new(big.Int)))

	return ECIESCiphertext{
		AuthKeyX:  authKeyX,
		AuthKeyY:  authKeyY,
		Encrypted: encrypted,
	}, nil
}

// Decrypt decrypts a single ECIES ciphertext using the receiver's private key.
//
//	shared = sk * authKey  (ECDH)
//	key    = Poseidon2([shared.x, shared.y])
//	value  = encrypted - key (mod P)
func Decrypt(sk *big.Int, authKey grumpkin.G1Affine, encrypted fr.Element) fr.Element {
	// shared = sk * authKey
	var shared grumpkin.G1Affine
	shared.ScalarMultiplication(&authKey, sk)

	var sharedX, sharedY fr.Element
	sharedX.SetBigInt(shared.X.BigInt(new(big.Int)))
	sharedY.SetBigInt(shared.Y.BigInt(new(big.Int)))

	key := poseidon2.Hash2(sharedX, sharedY)

	// value = encrypted - key
	var value fr.Element
	value.Sub(&encrypted, &key)
	return value
}

// EncryptCounterMode encrypts multiple field elements using ECIES counter mode.
// Each key_i = Poseidon2([shared.x, shared.y, i]) for i=0,1,2...
//
// Returns (ephemeral public key, ciphertexts).
func EncryptCounterMode(values []fr.Element, randomness *big.Int, receiverPk grumpkin.G1Affine) (grumpkin.G1Affine, []fr.Element, error) {
	if randomness.Sign() == 0 {
		return grumpkin.G1Affine{}, nil, fmt.Errorf("randomness must be non-zero")
	}

	// ephemeral = randomness * G
	var ephemeral grumpkin.G1Affine
	ephemeral.ScalarMultiplicationBase(randomness)

	// shared = randomness * receiverPk
	var shared grumpkin.G1Affine
	shared.ScalarMultiplication(&receiverPk, randomness)

	var sharedX, sharedY fr.Element
	sharedX.SetBigInt(shared.X.BigInt(new(big.Int)))
	sharedY.SetBigInt(shared.Y.BigInt(new(big.Int)))

	ciphertexts := make([]fr.Element, len(values))
	for i, val := range values {
		// key_i = Poseidon2([shared.x, shared.y, i])
		var counter fr.Element
		counter.SetUint64(uint64(i))
		key := poseidon2.Hash([]fr.Element{sharedX, sharedY, counter})

		// ciphertext_i = value_i + key_i
		ciphertexts[i].Add(&val, &key)
	}

	return ephemeral, ciphertexts, nil
}

// DecryptCounterMode decrypts multiple ECIES counter-mode ciphertexts.
func DecryptCounterMode(sk *big.Int, ephemeral grumpkin.G1Affine, ciphertexts []fr.Element) []fr.Element {
	// shared = sk * ephemeral
	var shared grumpkin.G1Affine
	shared.ScalarMultiplication(&ephemeral, sk)

	var sharedX, sharedY fr.Element
	sharedX.SetBigInt(shared.X.BigInt(new(big.Int)))
	sharedY.SetBigInt(shared.Y.BigInt(new(big.Int)))

	values := make([]fr.Element, len(ciphertexts))
	for i, ct := range ciphertexts {
		var counter fr.Element
		counter.SetUint64(uint64(i))
		key := poseidon2.Hash([]fr.Element{sharedX, sharedY, counter})

		values[i].Sub(&ct, &key)
	}

	return values
}
