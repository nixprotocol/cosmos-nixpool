package types

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// nonCanonicalEncodings returns every distinct 32-byte string that reduces to
// the same field element as n: n, n+p, n+2p, ... while they still fit.
func nonCanonicalEncodings(n *big.Int) [][]byte {
	p := fr.Modulus()
	var out [][]byte
	for i := 0; ; i++ {
		v := new(big.Int).Add(n, new(big.Int).Mul(big.NewInt(int64(i)), p))
		if v.BitLen() > 256 {
			break
		}
		var b [32]byte
		v.FillBytes(b[:])
		out = append(out, b[:])
	}
	return out
}

// TestNullifierKeyIsCanonical is the regression test for a double-spend.
//
// A nullifier is bound into the transact proof via fr.Element.SetBytes, which
// reduces mod p. If the spent-nullifier set were keyed on the raw 32 bytes, the
// six distinct encodings of one value (floor(2^256/p) = 5, so n .. n+5p all fit)
// would each occupy an independent "not yet spent" slot while a single proof
// re-verified against all of them — six withdrawals from one deposited note.
func TestNullifierKeyIsCanonical(t *testing.T) {
	encodings := nonCanonicalEncodings(big.NewInt(12345))
	if len(encodings) < 2 {
		t.Fatalf("expected multiple encodings to exist, got %d", len(encodings))
	}
	t.Logf("%d distinct 32-byte encodings of one field element", len(encodings))

	// Every encoding is the same value to a proof.
	var want fr.Element
	want.SetBytes(encodings[0])
	for i, e := range encodings {
		var got fr.Element
		got.SetBytes(e)
		if !got.Equal(&want) {
			t.Fatalf("encoding %d reduces differently; the premise no longer holds", i)
		}
	}

	// So they must all collapse to one spent-set slot.
	keys := map[string]bool{}
	for _, e := range encodings {
		keys[string(NullifierKey(e))] = true
	}
	if len(keys) != 1 {
		t.Fatalf("double-spend: one note yields %d independent spent-set slots", len(keys))
	}

	// Same requirement for the commitment used-sets.
	for name, fn := range map[string]func([]byte) []byte{
		"CommitmentUsedKey":    CommitmentUsedKey,
		"RegCommitmentUsedKey": RegCommitmentUsedKey,
	} {
		seen := map[string]bool{}
		for _, e := range encodings {
			seen[string(fn(e))] = true
		}
		if len(seen) != 1 {
			t.Fatalf("%s: one commitment yields %d slots", name, len(seen))
		}
	}
}

// TestValidateBasicRejectsNonCanonicalFieldBytes checks the second layer: a
// non-canonical encoding is refused at the message boundary, so it fails loudly
// rather than relying solely on key canonicalisation downstream.
func TestValidateBasicRejectsNonCanonicalFieldBytes(t *testing.T) {
	enc := nonCanonicalEncodings(big.NewInt(12345))
	canonical, overflowed := enc[0], enc[1]

	if err := validateFieldBytes(canonical, "x"); err != nil {
		t.Fatalf("canonical encoding rejected: %v", err)
	}
	if err := validateFieldBytes(overflowed, "x"); err == nil {
		t.Fatal("non-canonical encoding (n+p) was accepted")
	}
	if err := validateFieldBytes(make([]byte, 31), "x"); err == nil {
		t.Fatal("short input was accepted")
	}

	// And through the real message validator.
	msg := &MsgTransact{
		Sender:           "cosmos1v9kxjcm9ta047h6lta047h6lta047h6l33fvfn",
		Nullifiers:       [][]byte{overflowed, make([]byte, 32)},
		MerkleRoots:      [][]byte{make([]byte, 32), make([]byte, 32)},
		Outputs:          []*OutputNote{{NoteHash: make([]byte, 32)}, {NoteHash: make([]byte, 32)}},
		RegistrationRoot: make([]byte, 32),
		Proof:            []byte{1},
	}
	if err := msg.ValidateBasic(); err == nil {
		t.Fatal("MsgTransact accepted a non-canonical nullifier")
	}
}

// TestValidateAmountRejectsOversized covers the reduce-vs-pay class for
// amounts: the circuit proves a 64-bit range and the public input is bound via
// SetBigInt (which reduces mod p), so anything wider must not be accepted.
func TestValidateAmountRejectsOversized(t *testing.T) {
	if err := validateAmount("1000", "x"); err != nil {
		t.Fatalf("ordinary amount rejected: %v", err)
	}
	// 2^64 - 1 is the largest the circuit proves.
	if err := validateAmount("18446744073709551615", "x"); err != nil {
		t.Fatalf("max uint64 rejected: %v", err)
	}
	// 2^64 exceeds it.
	if err := validateAmount("18446744073709551616", "x"); err == nil {
		t.Fatal("2^64 was accepted")
	}
	// At the field modulus, SetBigInt would reduce to 0 while the handler pays
	// the full value.
	if err := validateAmount(fr.Modulus().String(), "x"); err == nil {
		t.Fatal("field modulus was accepted as an amount")
	}
	if err := validateAmount("-1", "x"); err == nil {
		t.Fatal("negative amount was accepted")
	}
}
