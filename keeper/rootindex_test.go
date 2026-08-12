package keeper

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/nixprotocol/cosmos-nixpool/types"
)

// commitmentAt produces a distinct 32-byte note commitment per index.
func commitmentAt(i uint64) []byte {
	c := make([]byte, 32)
	binary.BigEndian.PutUint64(c[24:], i+1) // +1: never the all-zero leaf
	return c
}

// scanIsValidRootAnyTree is the pre-index implementation, kept as an oracle.
// It reads the authoritative root slots directly, so agreeing with it is what
// "the index is correct" means.
func scanIsValidRootAnyTree(t *testing.T, k Keeper, ctx context.Context, root []byte) bool {
	t.Helper()
	count, err := k.GetTreeCount(ctx)
	require.NoError(t, err)
	if count == 0 {
		return bytesEqualZeroRoot(root)
	}
	for treeId := uint64(0); treeId < count; treeId++ {
		known, err := k.IsKnownRoot(ctx, treeId, root)
		require.NoError(t, err)
		if known {
			return true
		}
	}
	return false
}

func bytesEqualZeroRoot(root []byte) bool {
	z := zeroRootBytes(types.DefaultTreeDepth)
	if len(z) != len(root) {
		return false
	}
	for i := range z {
		if z[i] != root[i] {
			return false
		}
	}
	return true
}

// TestRootIndexAgreesWithScan checks the O(1) index against the O(n) scan it
// replaced, over every root the tree passes through plus roots that never
// existed. Equivalence is the property that matters: the index is only a
// performance change if it answers identically.
func TestRootIndexAgreesWithScan(t *testing.T) {
	k, _, ctx := setupKeeper(t)

	var seen [][]byte
	for i := uint64(0); i < 25; i++ {
		root, _, _, err := k.InsertNote(ctx, commitmentAt(i))
		require.NoError(t, err)
		seen = append(seen, append([]byte(nil), root...))

		// Every root observed so far, checked both ways.
		for j, r := range seen {
			viaIndex, err := k.IsValidRootAnyTree(ctx, r)
			require.NoError(t, err)
			require.Equal(t, scanIsValidRootAnyTree(t, k, ctx, r), viaIndex,
				"index and scan disagree on root %d after %d inserts", j, i+1)
		}
	}

	// Roots that were never a tree state must be rejected by both.
	for i := uint64(0); i < 5; i++ {
		bogus := commitmentAt(9000 + i)
		viaIndex, err := k.IsValidRootAnyTree(ctx, bogus)
		require.NoError(t, err)
		require.Equal(t, scanIsValidRootAnyTree(t, k, ctx, bogus), viaIndex)
		require.False(t, viaIndex, "a root that never existed must not validate")
	}
}

// TestRootExpiresWhenRingBufferWraps is the soundness test, and the reason this
// change needed care.
//
// MaxRootHistory is not a cache size. It is what makes an old root EXPIRE, so a
// spend can only prove against a recent tree state. An index that recorded roots
// without evicting them would make every root ever observed valid forever --
// turning bounded lookback into unbounded while every other test still passed.
//
// So: a root must remain valid for MaxRootHistory inserts and must stop being
// valid once its ring buffer slot is overwritten.
func TestRootExpiresWhenRingBufferWraps(t *testing.T) {
	k, _, ctx := setupKeeper(t)

	firstRoot, _, _, err := k.InsertNote(ctx, commitmentAt(0))
	require.NoError(t, err)

	valid, err := k.IsValidRootAnyTree(ctx, firstRoot)
	require.NoError(t, err)
	require.True(t, valid, "a freshly created root must be valid")

	// Fill the rest of the ring. The first root occupied slot 0, so it survives
	// until insert number MaxRootHistory reuses that slot.
	for i := uint64(1); i < types.MaxRootHistory; i++ {
		_, _, _, err := k.InsertNote(ctx, commitmentAt(i))
		require.NoError(t, err)
	}

	valid, err = k.IsValidRootAnyTree(ctx, firstRoot)
	require.NoError(t, err)
	require.True(t, valid,
		"root must still be valid at the edge of the window (%d inserts)", types.MaxRootHistory-1)

	// One more insert wraps onto slot 0 and evicts the first root.
	_, _, _, err = k.InsertNote(ctx, commitmentAt(types.MaxRootHistory))
	require.NoError(t, err)

	valid, err = k.IsValidRootAnyTree(ctx, firstRoot)
	require.NoError(t, err)
	require.False(t, valid,
		"root outlived its history slot: the index is not evicting, which silently "+
			"converts bounded root lookback into unbounded and lets a spend prove "+
			"against arbitrarily stale tree state")

	// And the scan agrees it is gone -- the index did not merely lose track of a
	// root that is still reachable in the authoritative slots.
	require.False(t, scanIsValidRootAnyTree(t, k, ctx, firstRoot),
		"scan and index must agree that the root expired")
}

// TestRootIndexRefcountsSharedRoots covers why the index counts references
// instead of storing a set. One insert writes the same root to both the tree's
// current-root slot and a history slot, so a single decrement must not drop a
// root that is still live elsewhere.
func TestRootIndexRefcountsSharedRoots(t *testing.T) {
	k, _, ctx := setupKeeper(t)

	root, _, _, err := k.InsertNote(ctx, commitmentAt(0))
	require.NoError(t, err)

	n, err := k.rootRefCount(ctx, root)
	require.NoError(t, err)
	require.Equal(t, uint64(2), n,
		"a new root occupies the current-root slot and a history slot")

	// The next insert displaces it as current root but leaves it in history.
	_, _, _, err = k.InsertNote(ctx, commitmentAt(1))
	require.NoError(t, err)

	n, err = k.rootRefCount(ctx, root)
	require.NoError(t, err)
	require.Equal(t, uint64(1), n, "still held by its history slot")

	valid, err := k.IsValidRootAnyTree(ctx, root)
	require.NoError(t, err)
	require.True(t, valid, "a root still in history must remain spendable-against")
}

// TestRebuildRootIndexReconstructsState covers the in-place upgrade path: a
// chain whose state predates the index must be able to rebuild it, or
// IsValidRootAnyTree would reject every root the chain knows and halt Transact.
func TestRebuildRootIndexReconstructsState(t *testing.T) {
	k, _, ctx := setupKeeper(t)

	var roots [][]byte
	for i := uint64(0); i < 10; i++ {
		r, _, _, err := k.InsertNote(ctx, commitmentAt(i))
		require.NoError(t, err)
		roots = append(roots, append([]byte(nil), r...))
	}

	// Simulate pre-index state by dropping every index entry.
	store := k.storeService.OpenKVStore(ctx)
	for _, r := range roots {
		require.NoError(t, store.Delete(types.RootIndexKey(r)))
	}
	valid, err := k.IsValidRootAnyTree(ctx, roots[len(roots)-1])
	require.NoError(t, err)
	require.False(t, valid, "precondition: index cleared")

	require.NoError(t, k.RebuildRootIndex(ctx))

	for i, r := range roots {
		viaIndex, err := k.IsValidRootAnyTree(ctx, r)
		require.NoError(t, err)
		require.Equal(t, scanIsValidRootAnyTree(t, k, ctx, r), viaIndex,
			"rebuilt index disagrees with scan on root %d", i)
		require.True(t, viaIndex, "root %d should be valid after rebuild", i)
	}

	// Rebuilding again must converge, not accumulate.
	before, err := k.rootRefCount(ctx, roots[len(roots)-1])
	require.NoError(t, err)
	require.NoError(t, k.RebuildRootIndex(ctx))
	after, err := k.rootRefCount(ctx, roots[len(roots)-1])
	require.NoError(t, err)
	require.Equal(t, before, after, "RebuildRootIndex must be idempotent")
}

// TestRebuildRootIndexRemovesOrphans covers the case that makes rebuilding
// worth having at all: an index entry for a root held in no slot.
//
// Recounting only the roots found in slots is not enough. An orphaned entry
// would survive, and an orphan keeps a root valid after its history slot was
// reused -- unbounded lookback reached by a different route than a missing
// decrement. A rebuild is only a repair if the result depends solely on the
// authoritative slots, which means discarding the old index rather than
// overwriting parts of it.
func TestRebuildRootIndexRemovesOrphans(t *testing.T) {
	k, _, ctx := setupKeeper(t)

	for i := uint64(0); i < 5; i++ {
		_, _, _, err := k.InsertNote(ctx, commitmentAt(i))
		require.NoError(t, err)
	}

	// A root that is in no tree slot, as a partial write or interrupted upgrade
	// could leave behind.
	orphan := commitmentAt(4242)
	require.NoError(t, k.rootIndexIncr(ctx, orphan))

	valid, err := k.IsValidRootAnyTree(ctx, orphan)
	require.NoError(t, err)
	require.True(t, valid, "precondition: the orphan is currently accepted")
	require.False(t, scanIsValidRootAnyTree(t, k, ctx, orphan),
		"precondition: no tree slot actually holds it")

	require.NoError(t, k.RebuildRootIndex(ctx))

	valid, err = k.IsValidRootAnyTree(ctx, orphan)
	require.NoError(t, err)
	require.False(t, valid,
		"rebuild left an index entry for a root no slot holds; such an entry keeps "+
			"a root valid forever regardless of the history window")

	// The legitimate roots must survive the clear.
	for i := uint64(0); i < 5; i++ {
		root, err := k.GetTreeRoot(ctx, 0)
		require.NoError(t, err)
		ok, err := k.IsValidRootAnyTree(ctx, root)
		require.NoError(t, err)
		require.True(t, ok, "rebuild must not drop roots that are genuinely held")
	}
}

// TestGenesisRoundTripPreservesRootValidity exercises export -> import on a
// fresh store, which is the migration path for this change and had no coverage.
//
// The index is derived state and is deliberately not exported. That is only
// correct if InitGenesis rebuilds it while writing the root slots; if it wrote
// them raw, an imported chain would come up rejecting every root it knows and
// Transact would fail on a chain that looked healthy.
func TestGenesisRoundTripPreservesRootValidity(t *testing.T) {
	src, _, srcCtx := setupKeeper(t)

	var roots [][]byte
	for i := uint64(0); i < 8; i++ {
		r, _, _, err := src.InsertNote(srcCtx, commitmentAt(i))
		require.NoError(t, err)
		roots = append(roots, append([]byte(nil), r...))
	}

	exported, err := src.ExportGenesis(srcCtx)
	require.NoError(t, err)

	// Import into a completely separate store.
	dst, _, dstCtx := setupKeeper(t)
	require.NoError(t, dst.InitGenesis(dstCtx, exported))

	for i, r := range roots {
		viaIndex, err := dst.IsValidRootAnyTree(dstCtx, r)
		require.NoError(t, err)
		require.Equal(t, scanIsValidRootAnyTree(t, dst, dstCtx, r), viaIndex,
			"imported chain: index and slots disagree on root %d", i)
	}

	// The most recent root must certainly still be spendable-against.
	last := roots[len(roots)-1]
	ok, err := dst.IsValidRootAnyTree(dstCtx, last)
	require.NoError(t, err)
	require.True(t, ok,
		"imported chain rejects its own current root: InitGenesis wrote root slots "+
			"without populating the index that validation reads")

	// And a root that never existed is still rejected after import.
	bogus := commitmentAt(7777)
	ok, err = dst.IsValidRootAnyTree(dstCtx, bogus)
	require.NoError(t, err)
	require.False(t, ok, "import must not make unknown roots valid")
}
