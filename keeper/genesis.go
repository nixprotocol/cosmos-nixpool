package keeper

import (
	"context"
	"encoding/binary"

	storetypes "cosmossdk.io/store/types"

	"github.com/nixprotocol/cosmos-nixpool/types"
)

// InitGenesis restores all nixpool state from the genesis export.
func (k Keeper) InitGenesis(ctx context.Context, gs *types.GenesisState) error {
	if gs.Params == nil {
		p := types.DefaultParams()
		gs.Params = &p
	}
	if err := k.SetParams(ctx, *gs.Params); err != nil {
		return err
	}

	store := k.storeService.OpenKVStore(ctx)

	// Multi-tree forest
	for _, tree := range gs.Trees {
		treeId := tree.TreeId

		// Commitments
		for i, c := range tree.Commitments {
			if err := store.Set(types.CommitmentKey(treeId, uint64(i)), c); err != nil {
				return err
			}
		}

		// Frontier
		for i, f := range tree.Frontier {
			if err := store.Set(types.FrontierKey(treeId, uint32(i)), f); err != nil {
				return err
			}
		}

		// Next index
		if tree.NextIndex > 0 {
			bz := make([]byte, 8)
			binary.BigEndian.PutUint64(bz, tree.NextIndex)
			if err := store.Set(types.TreeNextIndexKey(treeId), bz); err != nil {
				return err
			}
		}

		// Root
		if len(tree.MerkleRoot) > 0 {
			if err := store.Set(types.TreeRootKey(treeId), tree.MerkleRoot); err != nil {
				return err
			}
		}

		// Root history
		for i, r := range tree.RootHistory {
			if err := store.Set(types.RootHistoryKey(treeId, uint64(i)), r); err != nil {
				return err
			}
		}
	}

	// Active tree ID and tree count
	{
		bz := make([]byte, 8)
		binary.BigEndian.PutUint64(bz, gs.ActiveTreeId)
		if err := store.Set(types.ActiveTreeIdKey(), bz); err != nil {
			return err
		}
	}
	{
		bz := make([]byte, 8)
		binary.BigEndian.PutUint64(bz, gs.TreeCount)
		if err := store.Set(types.TreeCountKey(), bz); err != nil {
			return err
		}
	}

	// Registration tree. The used-marker set is derived from the commitment
	// list rather than carried as its own genesis field, so the duplicate
	// check survives an export/import round trip.
	for i, c := range gs.RegCommitments {
		if err := store.Set(types.RegCommitmentKey(uint64(i)), c); err != nil {
			return err
		}
		if err := store.Set(types.RegCommitmentUsedKey(c), []byte{1}); err != nil {
			return err
		}
	}
	for i, f := range gs.RegFrontier {
		if err := store.Set(types.RegFrontierKey(uint32(i)), f); err != nil {
			return err
		}
	}
	if gs.RegNextIndex > 0 {
		bz := make([]byte, 8)
		binary.BigEndian.PutUint64(bz, gs.RegNextIndex)
		if err := store.Set(types.RegNextIndexKeyBytes(), bz); err != nil {
			return err
		}
	}
	if len(gs.RegMerkleRoot) > 0 {
		if err := store.Set(types.RegRootKeyBytes(), gs.RegMerkleRoot); err != nil {
			return err
		}
	}

	// Nullifiers
	for _, n := range gs.Nullifiers {
		if err := store.Set(types.NullifierKey(n), []byte{1}); err != nil {
			return err
		}
	}

	// Commitments used
	for _, c := range gs.CommitmentsUsed {
		if err := store.Set(types.CommitmentUsedKey(c), []byte{1}); err != nil {
			return err
		}
	}

	// Auditor data
	for _, ad := range gs.AuditorData {
		if err := store.Set(types.AuditorDataKey(ad.TxHash), ad.Data); err != nil {
			return err
		}
	}

	// Verification keys
	for _, vke := range gs.VerificationKeys {
		if err := store.Set(types.VKKey(vke.CircuitName), vke.VkData); err != nil {
			return err
		}
	}

	return nil
}

// ExportGenesis exports the full nixpool state for genesis.
func (k Keeper) ExportGenesis(ctx context.Context) (*types.GenesisState, error) {
	params, err := k.GetParams(ctx)
	if err != nil {
		return nil, err
	}

	gs := &types.GenesisState{Params: &params}

	store := k.storeService.OpenKVStore(ctx)

	// Multi-tree forest
	treeCount, err := k.GetTreeCount(ctx)
	if err != nil {
		return nil, err
	}
	gs.TreeCount = treeCount

	activeTreeId, err := k.GetActiveTreeId(ctx)
	if err != nil {
		return nil, err
	}
	gs.ActiveTreeId = activeTreeId

	treeDepth := params.TreeDepth
	if treeDepth == 0 {
		treeDepth = types.DefaultTreeDepth
	}

	for treeId := uint64(0); treeId < treeCount; treeId++ {
		tree := &types.TreeState{TreeId: treeId}

		// Get next index
		nextIndex, err := k.GetTreeNextIndex(ctx, treeId)
		if err != nil {
			return nil, err
		}
		tree.NextIndex = nextIndex

		// Commitments
		for i := uint64(0); i < nextIndex; i++ {
			val, err := store.Get(types.CommitmentKey(treeId, i))
			if err != nil {
				return nil, err
			}
			tree.Commitments = append(tree.Commitments, val)
		}

		// Frontier
		for level := uint32(0); level < treeDepth; level++ {
			val, err := store.Get(types.FrontierKey(treeId, level))
			if err != nil {
				return nil, err
			}
			if val != nil {
				tree.Frontier = append(tree.Frontier, val)
			} else {
				tree.Frontier = append(tree.Frontier, nil)
			}
		}

		// Root
		tree.MerkleRoot, err = k.GetTreeRoot(ctx, treeId)
		if err != nil {
			return nil, err
		}

		// Root history
		for i := uint64(0); i < types.MaxRootHistory; i++ {
			val, err := store.Get(types.RootHistoryKey(treeId, i))
			if err != nil {
				return nil, err
			}
			if val != nil {
				tree.RootHistory = append(tree.RootHistory, val)
			}
		}

		gs.Trees = append(gs.Trees, tree)
	}

	// Registration tree
	regNextBz, err := store.Get(types.RegNextIndexKeyBytes())
	if err != nil {
		return nil, err
	}
	if regNextBz != nil {
		gs.RegNextIndex = binary.BigEndian.Uint64(regNextBz)
	}
	for i := uint64(0); i < gs.RegNextIndex; i++ {
		val, err := store.Get(types.RegCommitmentKey(i))
		if err != nil {
			return nil, err
		}
		gs.RegCommitments = append(gs.RegCommitments, val)
	}
	for level := uint32(0); level < types.DefaultRegTreeDepth; level++ {
		val, err := store.Get(types.RegFrontierKey(level))
		if err != nil {
			return nil, err
		}
		if val != nil {
			gs.RegFrontier = append(gs.RegFrontier, val)
		} else {
			gs.RegFrontier = append(gs.RegFrontier, nil)
		}
	}
	gs.RegMerkleRoot, err = k.GetRegMerkleRoot(ctx)
	if err != nil {
		return nil, err
	}

	// Nullifiers
	nullifiers, err := iteratePrefix(store, types.NullifierPrefix())
	if err != nil {
		return nil, err
	}
	nullifierPrefixLen := len(types.NullifierPrefix())
	for _, kv := range nullifiers {
		gs.Nullifiers = append(gs.Nullifiers, kv.key[nullifierPrefixLen:])
	}

	// Commitments used
	usedItems, err := iteratePrefix(store, types.CommitmentUsedPrefix())
	if err != nil {
		return nil, err
	}
	usedPrefixLen := len(types.CommitmentUsedPrefix())
	for _, kv := range usedItems {
		gs.CommitmentsUsed = append(gs.CommitmentsUsed, kv.key[usedPrefixLen:])
	}

	// Auditor data
	adItems, err := iteratePrefix(store, types.AuditorDataPrefix())
	if err != nil {
		return nil, err
	}
	adPrefixLen := len(types.AuditorDataPrefix())
	for _, kv := range adItems {
		gs.AuditorData = append(gs.AuditorData, &types.AuditorDataEntry{
			TxHash: kv.key[adPrefixLen:],
			Data:   kv.value,
		})
	}

	// Verification keys
	vkItems, err := iteratePrefix(store, types.VKPrefix())
	if err != nil {
		return nil, err
	}
	vkPrefixLen := len(types.VKPrefix())
	for _, kv := range vkItems {
		gs.VerificationKeys = append(gs.VerificationKeys, &types.VerificationKeyEntry{
			CircuitName: string(kv.key[vkPrefixLen:]),
			VkData:      kv.value,
		})
	}

	return gs, nil
}

type kvPair struct {
	key   []byte
	value []byte
}

// iteratePrefix collects all key-value pairs under a given prefix.
func iteratePrefix(store interface {
	Iterator(start, end []byte) (storetypes.Iterator, error)
}, prefix []byte) ([]kvPair, error) {
	end := storetypes.PrefixEndBytes(prefix)
	iter, err := store.Iterator(prefix, end)
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var pairs []kvPair
	for ; iter.Valid(); iter.Next() {
		k := make([]byte, len(iter.Key()))
		copy(k, iter.Key())
		v := make([]byte, len(iter.Value()))
		copy(v, iter.Value())
		pairs = append(pairs, kvPair{key: k, value: v})
	}
	return pairs, nil
}
