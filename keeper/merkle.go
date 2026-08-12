package keeper

import (
	"bytes"
	"context"
	"encoding/binary"

	storetypes "cosmossdk.io/store/types"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/nixprotocol/cosmos-nixpool/types"
	poseidon2 "github.com/nixprotocol/poseidon2-go"
	merkle "github.com/nixprotocol/poseidon2-merkle-go"
)

// ---------- Multi-tree note forest ----------

// GetActiveTreeId returns the currently active tree ID.
func (k Keeper) GetActiveTreeId(ctx context.Context) (uint64, error) {
	store := k.storeService.OpenKVStore(ctx)
	bz, err := store.Get(types.ActiveTreeIdKey())
	if err != nil {
		return 0, err
	}
	if bz == nil {
		return 0, nil
	}
	return binary.BigEndian.Uint64(bz), nil
}

func (k Keeper) setActiveTreeId(ctx context.Context, id uint64) error {
	store := k.storeService.OpenKVStore(ctx)
	bz := make([]byte, 8)
	binary.BigEndian.PutUint64(bz, id)
	return store.Set(types.ActiveTreeIdKey(), bz)
}

// GetTreeCount returns the total number of trees.
func (k Keeper) GetTreeCount(ctx context.Context) (uint64, error) {
	store := k.storeService.OpenKVStore(ctx)
	bz, err := store.Get(types.TreeCountKey())
	if err != nil {
		return 0, err
	}
	if bz == nil {
		return 0, nil
	}
	return binary.BigEndian.Uint64(bz), nil
}

func (k Keeper) setTreeCount(ctx context.Context, count uint64) error {
	store := k.storeService.OpenKVStore(ctx)
	bz := make([]byte, 8)
	binary.BigEndian.PutUint64(bz, count)
	return store.Set(types.TreeCountKey(), bz)
}

// GetTreeRoot returns the current root of a specific tree.
func (k Keeper) GetTreeRoot(ctx context.Context, treeId uint64) ([]byte, error) {
	store := k.storeService.OpenKVStore(ctx)
	bz, err := store.Get(types.TreeRootKey(treeId))
	if err != nil {
		return nil, err
	}
	if bz == nil {
		return zeroRootBytes(types.DefaultTreeDepth), nil
	}
	return bz, nil
}

// GetTreeNextIndex returns the next leaf index for a specific tree.
func (k Keeper) GetTreeNextIndex(ctx context.Context, treeId uint64) (uint64, error) {
	store := k.storeService.OpenKVStore(ctx)
	bz, err := store.Get(types.TreeNextIndexKey(treeId))
	if err != nil {
		return 0, err
	}
	if bz == nil {
		return 0, nil
	}
	return binary.BigEndian.Uint64(bz), nil
}

// CreateTree initializes a new tree with empty frontier. Returns the new tree ID.
func (k Keeper) CreateTree(ctx context.Context) (uint64, error) {
	count, err := k.GetTreeCount(ctx)
	if err != nil {
		return 0, err
	}

	treeId := count
	store := k.storeService.OpenKVStore(ctx)

	// Initialize frontier with zero hashes (empty subtree roots)
	params, err := k.GetParams(ctx)
	if err != nil {
		return 0, err
	}
	depth := params.TreeDepth
	if depth == 0 {
		depth = types.DefaultTreeDepth
	}

	for level := uint32(0); level < depth; level++ {
		zh := merkle.ZeroHash(level)
		zb := zh.Bytes()
		if err := store.Set(types.FrontierKey(treeId, level), zb[:]); err != nil {
			return 0, err
		}
	}

	// Set initial root to zero root. Indexed like any other root write: several
	// empty trees share this value, which is exactly why the index refcounts.
	emptyRoot := zeroRootBytes(depth)
	if err := k.setTreeRootIndexed(ctx, treeId, emptyRoot); err != nil {
		return 0, err
	}

	// Set next index to 0
	bz := make([]byte, 8)
	if err := store.Set(types.TreeNextIndexKey(treeId), bz); err != nil {
		return 0, err
	}

	// Update count and active tree
	if err := k.setTreeCount(ctx, count+1); err != nil {
		return 0, err
	}
	if err := k.setActiveTreeId(ctx, treeId); err != nil {
		return 0, err
	}

	return treeId, nil
}

// EnsureTreeExists ensures at least one tree exists, creating one if needed.
func (k Keeper) EnsureTreeExists(ctx context.Context) error {
	count, err := k.GetTreeCount(ctx)
	if err != nil {
		return err
	}
	if count == 0 {
		_, err = k.CreateTree(ctx)
		return err
	}
	return nil
}

// InsertNote inserts a note hash into the active tree. If the tree is full,
// creates a new tree and inserts there. Returns (root, leafIndex, treeId, error).
func (k Keeper) InsertNote(ctx context.Context, commitment []byte) (root []byte, leafIndex uint64, treeId uint64, err error) {
	// Ensure at least one tree exists
	if err := k.EnsureTreeExists(ctx); err != nil {
		return nil, 0, 0, err
	}

	// Check for duplicate commitment
	store := k.storeService.OpenKVStore(ctx)
	usedKey := types.CommitmentUsedKey(commitment)
	has, err := store.Has(usedKey)
	if err != nil {
		return nil, 0, 0, err
	}
	if has {
		return nil, 0, 0, types.ErrDuplicateCommitment.Wrap("commitment already exists in the tree")
	}

	treeId, err = k.GetActiveTreeId(ctx)
	if err != nil {
		return nil, 0, 0, err
	}

	params, err := k.GetParams(ctx)
	if err != nil {
		return nil, 0, 0, err
	}
	depth := params.TreeDepth
	if depth == 0 {
		depth = types.DefaultTreeDepth
	}

	// Check if active tree is full
	nextIdx, err := k.GetTreeNextIndex(ctx, treeId)
	if err != nil {
		return nil, 0, 0, err
	}
	maxLeaves := uint64(1) << depth
	if nextIdx >= maxLeaves {
		// Create new tree
		treeId, err = k.CreateTree(ctx)
		if err != nil {
			return nil, 0, 0, err
		}
		nextIdx = 0
	}

	root, leafIndex, err = k.insertLeafIntoTree(ctx, treeId, commitment, depth)
	if err != nil {
		return nil, 0, 0, err
	}

	// Mark commitment as used
	if err := store.Set(usedKey, []byte{1}); err != nil {
		return nil, 0, 0, err
	}

	return root, leafIndex, treeId, nil
}

// insertLeafIntoTree inserts a leaf into a specific tree using the frontier approach.
func (k Keeper) insertLeafIntoTree(ctx context.Context, treeId uint64, commitment []byte, depth uint32) ([]byte, uint64, error) {
	store := k.storeService.OpenKVStore(ctx)

	// Read next index
	bz, err := store.Get(types.TreeNextIndexKey(treeId))
	if err != nil {
		return nil, 0, err
	}
	var index uint64
	if bz != nil {
		index = binary.BigEndian.Uint64(bz)
	}

	maxLeaves := uint64(1) << depth
	if index >= maxLeaves {
		return nil, 0, types.ErrTreeFull
	}

	// Store the leaf commitment
	if err := store.Set(types.CommitmentKey(treeId, index), commitment); err != nil {
		return nil, 0, err
	}

	// Walk up the tree using the frontier approach
	var current fr.Element
	current.SetBytes(commitment)

	idx := index
	for level := uint32(0); level < depth; level++ {
		if idx%2 == 0 {
			// Left child: store current as frontier, hash with zero sibling
			currentBytes := current.Bytes()
			if err := store.Set(types.FrontierKey(treeId, level), currentBytes[:]); err != nil {
				return nil, 0, err
			}
			current = poseidon2.Hash2(current, merkle.ZeroHash(level))
		} else {
			// Right child: hash with stored frontier (left sibling)
			frontierBytes, err := store.Get(types.FrontierKey(treeId, level))
			if err != nil {
				return nil, 0, err
			}
			var left fr.Element
			if frontierBytes != nil {
				left.SetBytes(frontierBytes)
			}
			current = poseidon2.Hash2(left, current)
		}
		idx >>= 1
	}

	rootBytes := current.Bytes()
	newRoot := rootBytes[:]

	// Store new root, and record it in the history ring buffer. Both go through
	// the indexed setters so the reverse index tracks the roots they displace --
	// in particular the ring buffer slot, whose overwrite is what expires an old
	// root.
	if err := k.setTreeRootIndexed(ctx, treeId, newRoot); err != nil {
		return nil, 0, err
	}
	if err := k.setRootHistoryIndexed(ctx, treeId, index%types.MaxRootHistory, newRoot); err != nil {
		return nil, 0, err
	}

	// Increment index
	nextBz := make([]byte, 8)
	binary.BigEndian.PutUint64(nextBz, index+1)
	if err := store.Set(types.TreeNextIndexKey(treeId), nextBz); err != nil {
		return nil, 0, err
	}

	return newRoot, index, nil
}

// GetMerkleRoot returns the current root of the active tree.
func (k Keeper) GetMerkleRoot(ctx context.Context) ([]byte, error) {
	treeId, err := k.GetActiveTreeId(ctx)
	if err != nil {
		return nil, err
	}
	return k.GetTreeRoot(ctx, treeId)
}

// GetNextIndex returns the next leaf index of the active tree.
func (k Keeper) GetNextIndex(ctx context.Context) (uint64, error) {
	treeId, err := k.GetActiveTreeId(ctx)
	if err != nil {
		return 0, err
	}
	return k.GetTreeNextIndex(ctx, treeId)
}

// ---------- Registration tree (single tree) ----------

func (k Keeper) GetRegMerkleRoot(ctx context.Context) ([]byte, error) {
	store := k.storeService.OpenKVStore(ctx)
	bz, err := store.Get(types.RegRootKeyBytes())
	if err != nil {
		return nil, err
	}
	if bz == nil {
		return zeroRootBytes(types.DefaultRegTreeDepth), nil
	}
	return bz, nil
}

func (k Keeper) InsertRegCommitment(ctx context.Context, commitment []byte) (root []byte, leafIndex uint64, err error) {
	// Reject a commitment already in the registration tree, mirroring InsertNote.
	// Re-registering the same identity only consumes tree slots.
	store := k.storeService.OpenKVStore(ctx)
	usedKey := types.RegCommitmentUsedKey(commitment)
	has, err := store.Has(usedKey)
	if err != nil {
		return nil, 0, err
	}
	if has {
		return nil, 0, types.ErrDuplicateCommitment.Wrap("identity commitment already registered")
	}

	root, leafIndex, err = k.insertLeafSingleTree(ctx, commitment, types.DefaultRegTreeDepth,
		func(idx uint64) []byte { return types.RegCommitmentKey(idx) },
		func(level uint32) []byte { return types.RegFrontierKey(level) },
		types.RegRootKeyBytes(), types.RegNextIndexKeyBytes(),
		false)
	if err != nil {
		return nil, 0, err
	}

	if err := store.Set(usedKey, []byte{1}); err != nil {
		return nil, 0, err
	}
	return root, leafIndex, nil
}

// insertLeafSingleTree is the original single-tree insert for the registration tree.
func (k Keeper) insertLeafSingleTree(
	ctx context.Context,
	commitment []byte,
	depth uint32,
	commitmentKeyFn func(uint64) []byte,
	frontierKeyFn func(uint32) []byte,
	rootStoreKey []byte,
	nextIndexStoreKey []byte,
	recordRootHistory bool,
) ([]byte, uint64, error) {
	store := k.storeService.OpenKVStore(ctx)

	bz, err := store.Get(nextIndexStoreKey)
	if err != nil {
		return nil, 0, err
	}
	var index uint64
	if bz != nil {
		index = binary.BigEndian.Uint64(bz)
	}

	maxLeaves := uint64(1) << depth
	if index >= maxLeaves {
		return nil, 0, types.ErrTreeFull
	}

	if err := store.Set(commitmentKeyFn(index), commitment); err != nil {
		return nil, 0, err
	}

	var current fr.Element
	current.SetBytes(commitment)

	idx := index
	for level := uint32(0); level < depth; level++ {
		if idx%2 == 0 {
			currentBytes := current.Bytes()
			if err := store.Set(frontierKeyFn(level), currentBytes[:]); err != nil {
				return nil, 0, err
			}
			current = poseidon2.Hash2(current, merkle.ZeroHash(level))
		} else {
			frontierBytes, err := store.Get(frontierKeyFn(level))
			if err != nil {
				return nil, 0, err
			}
			var left fr.Element
			if frontierBytes != nil {
				left.SetBytes(frontierBytes)
			}
			current = poseidon2.Hash2(left, current)
		}
		idx >>= 1
	}

	rootBytes := current.Bytes()
	newRoot := rootBytes[:]

	if err := store.Set(rootStoreKey, newRoot); err != nil {
		return nil, 0, err
	}

	nextBz := make([]byte, 8)
	binary.BigEndian.PutUint64(nextBz, index+1)
	if err := store.Set(nextIndexStoreKey, nextBz); err != nil {
		return nil, 0, err
	}

	return newRoot, index, nil
}

// ---------- Nullifier management ----------

func (k Keeper) IsNullifierSpent(ctx context.Context, nullifier []byte) (bool, error) {
	store := k.storeService.OpenKVStore(ctx)
	return store.Has(types.NullifierKey(nullifier))
}

func (k Keeper) MarkNullifierSpent(ctx context.Context, nullifier []byte) error {
	store := k.storeService.OpenKVStore(ctx)
	return store.Set(types.NullifierKey(nullifier), []byte{1})
}

// ---------- Root reverse index ----------
//
// The index maps a root to the number of slots currently holding it, across
// every tree's current-root slot and every root-history slot. It is maintained
// by the four places that write a root: CreateTree, insertLeafIntoTree (which
// writes both a current root and a history slot), and genesis import.
//
// Reference counting is not incidental. One root value legitimately occupies
// several slots at once -- an insert writes the same root to the tree's current
// slot and to a history slot, and every freshly created tree starts at the
// shared empty root -- so a plain set could not tell when the last live
// reference disappeared.
//
// Getting the decrement right is the whole point. MaxRootHistory is a soundness
// bound, not a cache size: it is what makes old roots expire, so a spend can
// only prove against a recent tree state. An index that grew without evicting
// would make every root ever observed valid forever, quietly turning bounded
// lookback into unbounded.

// rootRefCount returns the number of live slots holding root.
func (k Keeper) rootRefCount(ctx context.Context, root []byte) (uint64, error) {
	if len(root) == 0 {
		return 0, nil
	}
	bz, err := k.storeService.OpenKVStore(ctx).Get(types.RootIndexKey(root))
	if err != nil {
		return 0, err
	}
	if bz == nil {
		return 0, nil
	}
	return binary.BigEndian.Uint64(bz), nil
}

// rootIndexIncr records one more slot holding root.
func (k Keeper) rootIndexIncr(ctx context.Context, root []byte) error {
	if len(root) == 0 {
		return nil
	}
	n, err := k.rootRefCount(ctx, root)
	if err != nil {
		return err
	}
	bz := make([]byte, 8)
	binary.BigEndian.PutUint64(bz, n+1)
	return k.storeService.OpenKVStore(ctx).Set(types.RootIndexKey(root), bz)
}

// rootIndexDecr releases one slot's hold on root, deleting the entry when the
// last reference goes. Callers pass the value being overwritten, which is empty
// for a slot that was never written; that is not an error, just nothing to
// release.
func (k Keeper) rootIndexDecr(ctx context.Context, root []byte) error {
	if len(root) == 0 {
		return nil
	}
	n, err := k.rootRefCount(ctx, root)
	if err != nil {
		return err
	}
	store := k.storeService.OpenKVStore(ctx)
	if n <= 1 {
		// Last reference (or an untracked value, e.g. state written before the
		// index existed). Either way the root is no longer reachable.
		return store.Delete(types.RootIndexKey(root))
	}
	bz := make([]byte, 8)
	binary.BigEndian.PutUint64(bz, n-1)
	return store.Set(types.RootIndexKey(root), bz)
}

// setTreeRootIndexed writes a tree's current root, keeping the index in step
// with the value it displaces.
func (k Keeper) setTreeRootIndexed(ctx context.Context, treeId uint64, newRoot []byte) error {
	store := k.storeService.OpenKVStore(ctx)
	old, err := store.Get(types.TreeRootKey(treeId))
	if err != nil {
		return err
	}
	if bytes.Equal(old, newRoot) {
		return nil // no net change; avoid decrementing to zero and back
	}
	if err := store.Set(types.TreeRootKey(treeId), newRoot); err != nil {
		return err
	}
	if err := k.rootIndexIncr(ctx, newRoot); err != nil {
		return err
	}
	return k.rootIndexDecr(ctx, old)
}

// setRootHistoryIndexed writes a root-history slot, releasing whatever root the
// ring buffer is overwriting. This is the eviction path that makes old roots
// expire.
func (k Keeper) setRootHistoryIndexed(ctx context.Context, treeId, slot uint64, newRoot []byte) error {
	store := k.storeService.OpenKVStore(ctx)
	key := types.RootHistoryKey(treeId, slot)
	old, err := store.Get(key)
	if err != nil {
		return err
	}
	if bytes.Equal(old, newRoot) {
		return nil
	}
	if err := store.Set(key, newRoot); err != nil {
		return err
	}
	if err := k.rootIndexIncr(ctx, newRoot); err != nil {
		return err
	}
	return k.rootIndexDecr(ctx, old)
}

// RebuildRootIndex reconstructs the reverse index from the authoritative root
// slots. Call it from an upgrade handler on a chain whose state predates the
// index; without it IsValidRootAnyTree would reject every root the chain knows,
// halting Transact until the index was populated.
//
// Genesis import does not need this -- InitGenesis writes through the indexed
// setters -- so this is only for in-place upgrades.
//
// The walk is bounded by trees x (1 + MaxRootHistory), the same work the old
// lookup did on a single miss.
//
// It discards the whole existing index before recounting, rather than
// overwriting the entries it happens to find. That difference matters: an entry
// for a root held in no slot would otherwise survive a rebuild, and a lingering
// entry is exactly the failure this design guards against -- it keeps a root
// valid after its history slot was reused, which is unbounded lookback by
// another route. Only a full clear makes the rebuilt index a function of the
// authoritative slots alone, which is what makes it safe to run at any time and
// as often as needed.
func (k Keeper) RebuildRootIndex(ctx context.Context) error {
	count, err := k.GetTreeCount(ctx)
	if err != nil {
		return err
	}
	store := k.storeService.OpenKVStore(ctx)

	// Drop every existing entry first. Collected before deleting because
	// mutating the store under an open iterator is not safe.
	prefix := types.RootIndexPrefix()
	iter, err := store.Iterator(prefix, storetypes.PrefixEndBytes(prefix))
	if err != nil {
		return err
	}
	var stale [][]byte
	for ; iter.Valid(); iter.Next() {
		stale = append(stale, append([]byte(nil), iter.Key()...))
	}
	if err := iter.Close(); err != nil {
		return err
	}
	for _, key := range stale {
		if err := store.Delete(key); err != nil {
			return err
		}
	}

	// Collect first, then write, so a root appearing in several slots is counted
	// once per slot rather than being reset midway through its own tally.
	counts := map[string]uint64{}
	record := func(b []byte) {
		if len(b) == 0 {
			return
		}
		counts[string(types.CanonicalFieldBytes(b))]++
	}

	for treeId := uint64(0); treeId < count; treeId++ {
		cur, err := store.Get(types.TreeRootKey(treeId))
		if err != nil {
			return err
		}
		record(cur)

		for slot := uint64(0); slot < types.MaxRootHistory; slot++ {
			h, err := store.Get(types.RootHistoryKey(treeId, slot))
			if err != nil {
				return err
			}
			record(h)
		}
	}

	for canonical, n := range counts {
		bz := make([]byte, 8)
		binary.BigEndian.PutUint64(bz, n)
		if err := store.Set(types.RootIndexKey([]byte(canonical)), bz); err != nil {
			return err
		}
	}
	return nil
}

// ---------- Root validation (multi-tree) ----------

// IsKnownRoot checks if the given root matches the current or any historical root
// of the specified tree.
func (k Keeper) IsKnownRoot(ctx context.Context, treeId uint64, root []byte) (bool, error) {
	store := k.storeService.OpenKVStore(ctx)

	// Check current root
	currentRoot, err := store.Get(types.TreeRootKey(treeId))
	if err != nil {
		return false, err
	}
	if bytes.Equal(currentRoot, root) {
		return true, nil
	}

	// Check recent root history
	for i := uint64(0); i < types.MaxRootHistory; i++ {
		histRoot, err := store.Get(types.RootHistoryKey(treeId, i))
		if err != nil {
			return false, err
		}
		if bytes.Equal(histRoot, root) {
			return true, nil
		}
	}

	// Accept empty tree root
	emptyRoot := zeroRootBytes(types.DefaultTreeDepth)
	if bytes.Equal(emptyRoot, root) {
		return true, nil
	}

	return false, nil
}

// IsValidRootAnyTree reports whether root is current or recent in any tree of
// the forest.
//
// This is a single store read via the reverse index. It previously scanned
// trees x MaxRootHistory slots, which Transact pays once per non-zero
// nullifier. Because the forest only grows -- spent notes remain as nullified
// leaves -- that cost rose with total pool history and never fell: at roughly
// 1,100 gas per root read it reached ~28% of a 40M-gas block at ~50 trees, and
// at ~180 trees a single Transact would have exceeded the block limit, making
// the message type unexecutable chain-wide. An attacker could drive that growth
// while risking nothing, depositing once and then issuing self-directed
// 2-in/2-out transacts that add leaves while the principal stays pooled.
//
// The index is maintained by setTreeRootIndexed and setRootHistoryIndexed; see
// the note there on why eviction, not lookup, is the load-bearing half.
func (k Keeper) IsValidRootAnyTree(ctx context.Context, root []byte) (bool, error) {
	// Preserved from the scanning implementation: the all-zero root of an empty
	// tree is accepted unconditionally, including before any tree exists.
	//
	// This is broader than it needs to be -- a real (non-dummy) input can never
	// legitimately prove against the empty tree, since that would require a
	// Poseidon preimage of the zero leaf, and dummy inputs skip the root check
	// entirely via the zero-nullifier path in Transact. It is retained here only
	// to keep this change purely a performance fix; narrowing it is a separate
	// decision about acceptance semantics.
	if bytes.Equal(zeroRootBytes(types.DefaultTreeDepth), root) {
		return true, nil
	}

	n, err := k.rootRefCount(ctx, root)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// IsValidRegRoot checks if the given root matches the current registration tree root.
func (k Keeper) IsValidRegRoot(ctx context.Context, root []byte) (bool, error) {
	currentRoot, err := k.GetRegMerkleRoot(ctx)
	if err != nil {
		return false, err
	}
	return bytes.Equal(currentRoot, root), nil
}

// ---------- Auditor data ----------

func (k Keeper) StoreAuditorData(ctx context.Context, txHash []byte, data []byte) error {
	store := k.storeService.OpenKVStore(ctx)
	return store.Set(types.AuditorDataKey(txHash), data)
}

// ---------- Helpers ----------

func zeroRootBytes(depth uint32) []byte {
	zh := merkle.ZeroHash(depth)
	b := zh.Bytes()
	return b[:]
}
