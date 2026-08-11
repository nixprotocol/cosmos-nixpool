package keeper

import (
	"bytes"
	"context"
	"math/big"
	"sort"
	"testing"

	"cosmossdk.io/core/store"
	storetypes "cosmossdk.io/store/types"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/nixprotocol/cosmos-nixpool/types"
)

// ---------------------------------------------------------------------------
// Minimal in-memory keeper harness
// ---------------------------------------------------------------------------

type memStore struct{ data map[string][]byte }

func (s *memStore) Get(k []byte) ([]byte, error) { return s.data[string(k)], nil }
func (s *memStore) Has(k []byte) (bool, error)   { _, ok := s.data[string(k)]; return ok, nil }
func (s *memStore) Set(k, v []byte) error {
	s.data[string(k)] = append([]byte(nil), v...)
	return nil
}
func (s *memStore) Delete(k []byte) error { delete(s.data, string(k)); return nil }
func (s *memStore) Iterator(start, end []byte) (store.Iterator, error) {
	return newMemIter(s.data, start, end, true), nil
}
func (s *memStore) ReverseIterator(start, end []byte) (store.Iterator, error) {
	return newMemIter(s.data, start, end, false), nil
}

type memIter struct {
	keys       []string
	vals       [][]byte
	pos        int
	start, end []byte
}

func newMemIter(data map[string][]byte, start, end []byte, asc bool) *memIter {
	var keys []string
	for k := range data {
		kb := []byte(k)
		if start != nil && bytes.Compare(kb, start) < 0 {
			continue
		}
		if end != nil && bytes.Compare(kb, end) >= 0 {
			continue
		}
		keys = append(keys, k)
	}
	if asc {
		sort.Strings(keys)
	} else {
		sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	}
	vals := make([][]byte, len(keys))
	for i, k := range keys {
		vals[i] = data[k]
	}
	return &memIter{keys: keys, vals: vals, start: start, end: end}
}

func (it *memIter) Domain() ([]byte, []byte) { return it.start, it.end }
func (it *memIter) Valid() bool              { return it.pos < len(it.keys) }
func (it *memIter) Next()                    { it.pos++ }
func (it *memIter) Key() []byte              { return []byte(it.keys[it.pos]) }
func (it *memIter) Value() []byte            { return it.vals[it.pos] }
func (it *memIter) Error() error             { return nil }
func (it *memIter) Close() error             { return nil }

type memStoreSvc struct{ s *memStore }

func (m *memStoreSvc) OpenKVStore(_ context.Context) store.KVStore { return m.s }

type testAddrCodec struct{}

func (testAddrCodec) StringToBytes(t string) ([]byte, error) { return sdk.AccAddressFromBech32(t) }
func (testAddrCodec) BytesToString(b []byte) (string, error) { return sdk.AccAddress(b).String(), nil }

type noopBank struct{}

func (noopBank) SendCoinsFromAccountToModule(context.Context, sdk.AccAddress, string, sdk.Coins) error {
	return nil
}
func (noopBank) SendCoinsFromModuleToAccount(context.Context, string, sdk.AccAddress, sdk.Coins) error {
	return nil
}
func (noopBank) SpendableCoins(context.Context, sdk.AccAddress) sdk.Coins { return sdk.NewCoins() }

func setupKeeper(t *testing.T) (Keeper, types.MsgServer, sdk.Context) {
	t.Helper()
	svc := &memStoreSvc{s: &memStore{data: map[string][]byte{}}}
	k := NewKeeper(svc, nil, testAddrCodec{}, sdk.AccAddress([]byte("authority___________")), noopBank{})
	ctx := sdk.Context{}.
		WithContext(context.Background()).
		WithChainID("test-chain-1").
		WithEventManager(sdk.NewEventManager()).
		WithGasMeter(storetypes.NewInfiniteGasMeter())

	require.NoError(t, k.SetParams(ctx, types.Params{
		TreeDepth: types.DefaultTreeDepth, RegTreeDepth: types.DefaultRegTreeDepth,
		SupportedDenoms: []string{"anix"}, ChainBinding: []byte{0x42},
	}))
	return k, NewMsgServerImpl(k), ctx
}

// encodingsOf returns every distinct 32-byte string that reduces to the same
// field element as n: n, n+p, n+2p, ... while they still fit in 32 bytes.
func encodingsOf(n *big.Int) [][]byte {
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

// transactMsg builds a MsgTransact whose registration and note roots are the
// valid empty-tree roots, so execution reaches the nullifier logic. Outputs are
// dummies (zero note hashes), so nothing is inserted.
func transactMsg(t *testing.T, k Keeper, ctx sdk.Context, n1, n2 []byte) *types.MsgTransact {
	t.Helper()
	regRoot, err := k.GetRegMerkleRoot(ctx)
	require.NoError(t, err)
	noteRoot := zeroRootBytes(types.DefaultTreeDepth)

	return &types.MsgTransact{
		Sender:           sdk.AccAddress([]byte("sender______________")).String(),
		Nullifiers:       [][]byte{n1, n2},
		MerkleRoots:      [][]byte{noteRoot, noteRoot},
		Outputs:          []*types.OutputNote{{NoteHash: make([]byte, 32)}, {NoteHash: make([]byte, 32)}},
		RegistrationRoot: regRoot,
		Denom:            "anix",
		Proof:            []byte{1}, // never reached: the nullifier loop runs first
	}
}

// ---------------------------------------------------------------------------
// Double-spend tests
// ---------------------------------------------------------------------------

// TestTransact_DoubleSpend drives the real Transact handler. The nullifier
// check runs before proof verification, so these exercise the spend-tracking
// logic end-to-end without needing a valid UltraHonk proof.
func TestTransact_DoubleSpend(t *testing.T) {
	enc := encodingsOf(big.NewInt(0xC0FFEE))
	require.GreaterOrEqual(t, len(enc), 2, "need at least two encodings for this test")
	canonical, malleated := enc[0], enc[1]

	t.Run("control: a fresh nullifier passes the spend check", func(t *testing.T) {
		k, srv, ctx := setupKeeper(t)
		_, err := srv.Transact(ctx, transactMsg(t, k, ctx, canonical, make([]byte, 32)))
		// It must get PAST the spend check and fail later, at proof verification.
		// If this ever fails with ErrNullifierSpent the other cases prove nothing.
		require.Error(t, err)
		require.NotErrorIs(t, err, types.ErrNullifierSpent)

		spent, err := k.IsNullifierSpent(ctx, canonical)
		require.NoError(t, err)
		require.True(t, spent, "nullifier should have been marked spent")
	})

	t.Run("same nullifier twice in one transaction", func(t *testing.T) {
		k, srv, ctx := setupKeeper(t)
		_, err := srv.Transact(ctx, transactMsg(t, k, ctx, canonical, canonical))
		require.ErrorIs(t, err, types.ErrNullifierSpent,
			"spending the same note twice in one tx must be rejected")
	})

	// The regression for the critical finding. Both slots name the SAME note --
	// the encodings differ but reduce to one field element, so the proof cannot
	// tell them apart. Keying the spent-set on raw bytes made this a 2x spend
	// inside a single transaction, and 6x across transactions.
	t.Run("same nullifier under two encodings in one transaction", func(t *testing.T) {
		k, srv, ctx := setupKeeper(t)
		_, err := srv.Transact(ctx, transactMsg(t, k, ctx, canonical, malleated))
		require.ErrorIs(t, err, types.ErrNullifierSpent,
			"a re-encoded nullifier is the same note and must be rejected")
	})

	t.Run("re-spending across transactions, canonical encoding", func(t *testing.T) {
		k, srv, ctx := setupKeeper(t)
		require.NoError(t, k.MarkNullifierSpent(ctx, canonical))

		_, err := srv.Transact(ctx, transactMsg(t, k, ctx, canonical, make([]byte, 32)))
		require.ErrorIs(t, err, types.ErrNullifierSpent)
	})

	t.Run("re-spending across transactions, every alternative encoding", func(t *testing.T) {
		k, srv, ctx := setupKeeper(t)
		require.NoError(t, k.MarkNullifierSpent(ctx, canonical))

		for i, e := range enc[1:] {
			_, err := srv.Transact(ctx, transactMsg(t, k, ctx, e, make([]byte, 32)))
			require.ErrorIs(t, err, types.ErrNullifierSpent,
				"encoding %d (n+%dp) was accepted as an unspent nullifier", i+1, i+1)
		}
		t.Logf("all %d alternative encodings correctly rejected as already spent", len(enc)-1)
	})
}

// TestNullifierSpentSetIsEncodingIndependent checks the keeper's spend-tracking
// directly: marking one encoding must mark the note, not merely that byte
// string.
func TestNullifierSpentSetIsEncodingIndependent(t *testing.T) {
	k, _, ctx := setupKeeper(t)

	enc := encodingsOf(big.NewInt(12345))
	require.NoError(t, k.MarkNullifierSpent(ctx, enc[0]))

	for i, e := range enc {
		spent, err := k.IsNullifierSpent(ctx, e)
		require.NoError(t, err)
		require.True(t, spent, "encoding %d reported unspent after the note was spent", i)
	}

	// A genuinely different note is of course still unspent.
	other := encodingsOf(big.NewInt(999))[0]
	spent, err := k.IsNullifierSpent(ctx, other)
	require.NoError(t, err)
	require.False(t, spent, "an unrelated nullifier must not read as spent")
}
