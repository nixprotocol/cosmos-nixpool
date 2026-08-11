package types

import "fmt"

// DefaultGenesisState returns the default genesis state.
func DefaultGenesisState() *GenesisState {
	p := DefaultParams()
	return &GenesisState{
		Params: &p,
	}
}

// Validate validates the genesis state.
func (gs GenesisState) Validate() error {
	if gs.Params != nil {
		if err := gs.Params.Validate(); err != nil {
			return err
		}
	}

	// Validate trees
	for i, tree := range gs.Trees {
		if uint64(len(tree.Commitments)) != tree.NextIndex {
			return fmt.Errorf("tree %d: commitments length %d does not match next_index %d", i, len(tree.Commitments), tree.NextIndex)
		}
		for j, c := range tree.Commitments {
			if len(c) != 32 {
				return fmt.Errorf("tree %d commitment %d: expected 32 bytes, got %d", i, j, len(c))
			}
		}
	}

	// Reg commitment count must match reg_next_index
	if uint64(len(gs.RegCommitments)) != gs.RegNextIndex {
		return fmt.Errorf("reg_commitments length %d does not match reg_next_index %d", len(gs.RegCommitments), gs.RegNextIndex)
	}

	for i, c := range gs.RegCommitments {
		if len(c) != 32 {
			return fmt.Errorf("reg_commitment %d: expected 32 bytes, got %d", i, len(c))
		}
	}

	// Nullifiers must be 32 bytes each
	for i, n := range gs.Nullifiers {
		if len(n) != 32 {
			return fmt.Errorf("nullifier %d: expected 32 bytes, got %d", i, len(n))
		}
	}

	// Commitments used must be 32 bytes each
	for i, c := range gs.CommitmentsUsed {
		if len(c) != 32 {
			return fmt.Errorf("commitment_used %d: expected 32 bytes, got %d", i, len(c))
		}
	}

	// Verification keys must have valid circuit names
	for i, vk := range gs.VerificationKeys {
		if vk.CircuitName == "" {
			return fmt.Errorf("verification_key %d: empty circuit name", i)
		}
		if len(vk.VkData) == 0 {
			return fmt.Errorf("verification_key %d: empty vk data", i)
		}
	}

	return nil
}
