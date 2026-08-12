package keeper

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/nixprotocol/cosmos-nixpool/types"
)

// TestDepositRefusedWithoutChainBinding pins the invariant that the pool never
// accepts value it could not return.
//
// Register and Transact both fail closed on an unset params.chain_binding, and
// deliberately so -- an unset binding would make proofs replayable across
// deployments. Deposit could not join them on the same grounds, because the
// deposit circuit has no chain_id public input to check.
//
// That left an asymmetry with real consequences. Transact is the only withdrawal
// path. A pool configured with a deposit verification key but no chain_binding
// would escrow coins on deposit and then reject every withdrawal, stranding the
// funds in the module account until governance set the param. That is not
// hypothetical: the shipped config.yml genesis carries all three verification
// keys and sets no chain_binding.
//
// Deposit now refuses outright when the binding is unset.
func TestDepositRefusedWithoutChainBinding(t *testing.T) {
	k, ms, ctx := setupKeeper(t)

	params, err := k.GetParams(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, params.ChainBinding, "harness should start with a binding set")

	// Reproduce the dangerous configuration: binding cleared, everything else intact.
	params.ChainBinding = nil
	require.NoError(t, k.SetParams(ctx, params))

	_, err = ms.Deposit(ctx, &types.MsgDeposit{
		Sender:         "cosmos1testaddressplaceholderaaaaaaaaaaaaa",
		Amount:         "100",
		Denom:          "anix",
		NoteCommitment: make([]byte, 32),
		PublicInputs:   make([]byte, 32*DepositPICount),
		Proof:          make([]byte, 14592),
	})

	require.Error(t, err, "deposit must be refused while withdrawal is impossible")
	require.Contains(t, err.Error(), "chain binding not configured",
		"deposit must fail specifically on the missing binding, and must do so before "+
			"any coins move: accepting escrow here strands funds, because Transact is "+
			"the only exit and it requires the binding")
}
