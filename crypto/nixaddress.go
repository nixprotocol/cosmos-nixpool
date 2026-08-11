package crypto

import (
	"fmt"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// EncodeNixAddress returns the nix address string for a public key.
// Format: "nix:<commitment>:<pk.x>:<pk.y>"
// where commitment, pk.x, pk.y are 64-char zero-padded hex strings.
func EncodeNixAddress(pubKey *GrumpkinPubKey) string {
	commitment := pubKey.Commitment()
	commitmentBytes := commitment.Bytes()

	return fmt.Sprintf("nix:%064x:%064x:%064x",
		commitmentBytes,
		pubKey.Key[:32],
		pubKey.Key[32:],
	)
}

// DecodeNixAddress parses a "nix:<commitment>:<pk.x>:<pk.y>" string,
// validates the public key is on-curve, and verifies the commitment.
func DecodeNixAddress(address string) (*GrumpkinPubKey, error) {
	if !strings.HasPrefix(address, "nix:") {
		return nil, fmt.Errorf("nix address must start with \"nix:\"")
	}
	parts := strings.Split(address[4:], ":")
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected format nix:<commitment>:<pk.x>:<pk.y>")
	}

	// Parse commitment
	var commitment fr.Element
	commitmentBytes, err := hexToBytes32(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid commitment hex: %w", err)
	}
	commitment.SetBytes(commitmentBytes[:])

	// Parse public key coordinates
	pkxBytes, err := hexToBytes32(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid pk.x hex: %w", err)
	}
	pkyBytes, err := hexToBytes32(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid pk.y hex: %w", err)
	}

	// Construct and validate public key (on-curve check)
	keyBytes := make([]byte, PubKeySize)
	copy(keyBytes[:32], pkxBytes[:])
	copy(keyBytes[32:], pkyBytes[:])

	pubKey, err := NewGrumpkinPubKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("public key is not on the Grumpkin curve: %w", err)
	}

	// Validate commitment matches Poseidon2(pk.x, pk.y)
	expectedCommitment := pubKey.Commitment()
	if !commitment.Equal(&expectedCommitment) {
		return nil, fmt.Errorf("commitment does not match public key")
	}

	return pubKey, nil
}

// NixAddressFromPrivKey derives the nix address from a private key.
func NixAddressFromPrivKey(privKey *GrumpkinPrivKey) (string, error) {
	pubKey, err := privKey.PubKey()
	if err != nil {
		return "", err
	}
	return EncodeNixAddress(pubKey), nil
}

// hexToBytes32 parses a hex string (with or without 0x prefix) into exactly 32 bytes.
func hexToBytes32(s string) ([32]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	// Pad to 64 hex chars if shorter
	for len(s) < 64 {
		s = "0" + s
	}
	if len(s) != 64 {
		return [32]byte{}, fmt.Errorf("hex string too long: %d chars", len(s))
	}
	var result [32]byte
	for i := 0; i < 32; i++ {
		b, err := hexByte(s[i*2], s[i*2+1])
		if err != nil {
			return [32]byte{}, err
		}
		result[i] = b
	}
	return result, nil
}

// hexByte converts two hex characters to a byte.
func hexByte(hi, lo byte) (byte, error) {
	h, err := hexNibble(hi)
	if err != nil {
		return 0, err
	}
	l, err := hexNibble(lo)
	if err != nil {
		return 0, err
	}
	return h<<4 | l, nil
}

// hexNibble converts a single hex character to its value.
func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex character: %c", c)
	}
}
