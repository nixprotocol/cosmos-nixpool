// Package crypto provides Grumpkin elliptic-curve key types for the Nix privacy layer.
//
// The Grumpkin curve is the cycle-companion of BN254, widely used in ZK proof
// systems. This file ports the key types from grumpkin-go into nixpool
// to avoid the cosmos-sdk v0.50 dependency conflict.
package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/grumpkin"
	grumpkinecdsa "github.com/consensys/gnark-crypto/ecc/grumpkin/ecdsa"

	poseidon2 "github.com/nixprotocol/poseidon2-go"
)

const (
	// PubKeySize is the uncompressed public key size: 32 bytes X + 32 bytes Y.
	PubKeySize = 64
	// PrivKeySize is the full serialized size: compressed pubkey (32) || scalar (32).
	PrivKeySize = 64
	// KeyType is the key type identifier.
	KeyType = "grumpkin"
)

// GrumpkinPubKey wraps a Grumpkin elliptic-curve public key stored as raw
// X (32 bytes) || Y (32 bytes) in uncompressed form.
type GrumpkinPubKey struct {
	Key []byte `json:"key"` // 64 bytes: X (32) || Y (32)
}

// GrumpkinPrivKey wraps a gnark-crypto Grumpkin ECDSA private key.
// The key is stored as compressed pubkey (32 bytes) || scalar (32 bytes).
type GrumpkinPrivKey struct {
	Key []byte `json:"key"` // 64 bytes: compressed pubkey (32) || scalar (32)
}

// NewGrumpkinPubKey creates a GrumpkinPubKey from the given bytes after
// validating length and that it represents a valid Grumpkin curve point.
func NewGrumpkinPubKey(key []byte) (*GrumpkinPubKey, error) {
	if len(key) != PubKeySize {
		return nil, fmt.Errorf("grumpkin pubkey must be %d bytes, got %d", PubKeySize, len(key))
	}
	if _, err := PointFromRawXY(key); err != nil {
		return nil, fmt.Errorf("grumpkin pubkey bytes are not a valid curve point: %w", err)
	}
	return &GrumpkinPubKey{Key: key}, nil
}

// PointFromRawXY reconstructs a G1Affine point from raw X||Y bytes and
// validates it lies on the curve.
func PointFromRawXY(key []byte) (*grumpkin.G1Affine, error) {
	var p grumpkin.G1Affine
	p.X.SetBytes(key[:32])
	p.Y.SetBytes(key[32:])
	if !p.IsOnCurve() {
		return nil, fmt.Errorf("point is not on the Grumpkin curve")
	}
	return &p, nil
}

// RawXYFromPoint serializes a G1Affine point to raw X (32) || Y (32).
func RawXYFromPoint(p *grumpkin.G1Affine) []byte {
	xBytes := p.X.Bytes()
	yBytes := p.Y.Bytes()
	out := make([]byte, PubKeySize)
	copy(out[:32], xBytes[:])
	copy(out[32:], yBytes[:])
	return out
}

// Address returns the Poseidon2(pk.X, pk.Y) hash truncated to 20 bytes.
func (pk *GrumpkinPubKey) Address() []byte {
	if len(pk.Key) != PubKeySize {
		return nil
	}
	var x, y fr.Element
	x.SetBytes(pk.Key[:32])
	y.SetBytes(pk.Key[32:])

	hash := poseidon2.Hash2(x, y)
	hashBytes := hash.Bytes()
	addr := make([]byte, 20)
	copy(addr, hashBytes[12:32])
	return addr
}

// Commitment returns the full Poseidon2(pk.X, pk.Y) hash as an fr.Element.
func (pk *GrumpkinPubKey) Commitment() fr.Element {
	var x, y fr.Element
	x.SetBytes(pk.Key[:32])
	y.SetBytes(pk.Key[32:])
	return poseidon2.Hash2(x, y)
}

// Equals reports whether pk and other represent the same public key.
func (pk *GrumpkinPubKey) Equals(other *GrumpkinPubKey) bool {
	return subtle.ConstantTimeCompare(pk.Key, other.Key) == 1
}

// GenerateKey generates a new random Grumpkin private key.
func GenerateKey() (*GrumpkinPrivKey, error) {
	privKey, err := grumpkinecdsa.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	bz := privKey.Bytes()
	key := make([]byte, PrivKeySize)
	copy(key, bz[:PrivKeySize])
	return &GrumpkinPrivKey{Key: key}, nil
}

// PrivKeyFromScalar constructs a full 64-byte Grumpkin private key
// (compressed pubkey || scalar) from a field element scalar.
func PrivKeyFromScalar(scalar fr.Element) ([]byte, error) {
	scalarBytes := scalar.Bytes()
	scalarInt := new(big.Int).SetBytes(scalarBytes[:])

	var pubPoint grumpkin.G1Affine
	pubPoint.ScalarMultiplicationBase(scalarInt)

	pubBytes := pubPoint.Bytes()
	fullKey := make([]byte, PrivKeySize)
	copy(fullKey[:32], pubBytes[:])
	copy(fullKey[32:], scalarBytes[:])

	return fullKey, nil
}

// PrivKeyFromScalarBytes constructs a Grumpkin private key from raw scalar bytes (32 bytes).
func PrivKeyFromScalarBytes(scalarBytes []byte) (*GrumpkinPrivKey, error) {
	if len(scalarBytes) != 32 {
		return nil, fmt.Errorf("scalar must be 32 bytes, got %d", len(scalarBytes))
	}
	var scalar fr.Element
	scalar.SetBytes(scalarBytes)
	if scalar.IsZero() {
		return nil, fmt.Errorf("scalar must be non-zero")
	}

	fullKey, err := PrivKeyFromScalar(scalar)
	if err != nil {
		return nil, err
	}
	return &GrumpkinPrivKey{Key: fullKey}, nil
}

// PubKey derives the corresponding GrumpkinPubKey from this private key.
func (sk *GrumpkinPrivKey) PubKey() (*GrumpkinPubKey, error) {
	var privKey grumpkinecdsa.PrivateKey
	if _, err := privKey.SetBytes(sk.Key); err != nil {
		return nil, fmt.Errorf("failed to deserialize grumpkin private key: %w", err)
	}
	pubBytes := RawXYFromPoint(&privKey.PublicKey.A)
	return &GrumpkinPubKey{Key: pubBytes}, nil
}

// ScalarBytes returns the 32-byte scalar portion of the private key.
func (sk *GrumpkinPrivKey) ScalarBytes() []byte {
	return sk.Key[32:]
}

// Equals reports whether sk and other represent the same private key.
func (sk *GrumpkinPrivKey) Equals(other *GrumpkinPrivKey) bool {
	return subtle.ConstantTimeCompare(sk.Key, other.Key) == 1
}
