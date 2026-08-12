package keeper

import (
	"bytes"
	"context"
	"encoding/binary"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	merkle "github.com/nixprotocol/poseidon2-merkle-go"
	poseidon2 "github.com/nixprotocol/poseidon2-go"
	"github.com/nixprotocol/cosmos-nixpool/types"
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

	// Set initial root to zero root
	emptyRoot := zeroRootBytes(depth)
	if err := store.Set(types.TreeRootKey(treeId), emptyRoot); err != nil {
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

	// Store new root
	if err := store.Set(types.TreeRootKey(treeId), newRoot); err != nil {
		return nil, 0, err
	}

	// Record root in history ring buffer
	histKey := types.RootHistoryKey(treeId, index%types.MaxRootHistory)
	if err := store.Set(histKey, newRoot); err != nil {
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

// IsValidRootAnyTree checks if the given root is known across any tree in the forest.
//
// This is O(trees x MaxRootHistory) store reads when the root is not found, and
// Transact calls it once per non-zero nullifier. The forest only grows -- spent
// notes remain as nullified leaves -- so the cost per Transact rises with total
// pool history and never falls. Measured at roughly 1,100 gas per root read,
// the lookups alone reach ~28% of a 40M-gas block at ~50 trees, and at ~180
// trees a single Transact exceeds the block limit, which would make the message
// type unexecutable chain-wide. An attacker can drive that growth while paying
// only fees: deposit once, then self-directed 2-in/2-out transacts, each adding
// leaves while the principal stays pooled.
//
// The fix is a root -> treeId index, making this O(1). Before implementing it,
// note that the easy half is the lookup and the hard half is eviction:
//
//	MaxRootHistory is not a cache bound, it is a soundness bound. It is what
//	makes old roots EXPIRE, so a spend can only prove against a recent tree
//	state. An index that never deletes would make every root ever observed
//	valid forever, silently converting bounded lookback into unbounded and
//	accepting arbitrarily stale roots. The index entry must be deleted when
//	the ring buffer overwrites its slot.
//
// That is why this has not simply been optimised in place: the obvious version
// of the optimisation is a security regression.
func (k Keeper) IsValidRootAnyTree(ctx context.Context, root []byte) (bool, error) {
	count, err := k.GetTreeCount(ctx)
	if err != nil {
		return false, err
	}

	// Also accept empty root before any trees exist
	if count == 0 {
		emptyRoot := zeroRootBytes(types.DefaultTreeDepth)
		return bytes.Equal(emptyRoot, root), nil
	}

	for treeId := uint64(0); treeId < count; treeId++ {
		known, err := k.IsKnownRoot(ctx, treeId, root)
		if err != nil {
			return false, err
		}
		if known {
			return true, nil
		}
	}
	return false, nil
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
