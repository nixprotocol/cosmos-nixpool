package keeper

import (
	"context"

	"github.com/nixprotocol/cosmos-nixpool/types"
)

type queryServer struct {
	Keeper
}

// NewQueryServerImpl returns an implementation of the QueryServer interface.
func NewQueryServerImpl(keeper Keeper) types.QueryServer {
	return &queryServer{Keeper: keeper}
}

var _ types.QueryServer = queryServer{}

// Root returns the current Merkle root of the active tree.
func (q queryServer) Root(ctx context.Context, req *types.QueryRootRequest) (*types.QueryRootResponse, error) {
	root, err := q.GetMerkleRoot(ctx)
	if err != nil {
		return nil, err
	}
	return &types.QueryRootResponse{Root: root}, nil
}

// NullifierStatus checks if a nullifier has been spent.
func (q queryServer) NullifierStatus(ctx context.Context, req *types.QueryNullifierStatusRequest) (*types.QueryNullifierStatusResponse, error) {
	spent, err := q.IsNullifierSpent(ctx, req.Nullifier)
	if err != nil {
		return nil, err
	}
	return &types.QueryNullifierStatusResponse{Spent: spent}, nil
}

// TreeInfo returns the current state of the multi-tree forest.
func (q queryServer) TreeInfo(ctx context.Context, req *types.QueryTreeInfoRequest) (*types.QueryTreeInfoResponse, error) {
	root, err := q.GetMerkleRoot(ctx)
	if err != nil {
		return nil, err
	}
	nextIndex, err := q.GetNextIndex(ctx)
	if err != nil {
		return nil, err
	}
	activeTreeId, err := q.GetActiveTreeId(ctx)
	if err != nil {
		return nil, err
	}
	treeCount, err := q.GetTreeCount(ctx)
	if err != nil {
		return nil, err
	}
	return &types.QueryTreeInfoResponse{
		Root:         root,
		NextIndex:    nextIndex,
		Depth:        types.DefaultTreeDepth,
		ActiveTreeId: activeTreeId,
		TreeCount:    treeCount,
	}, nil
}

// Params returns the module parameters.
func (q queryServer) Params(ctx context.Context, req *types.QueryParamsRequest) (*types.QueryParamsResponse, error) {
	params, err := q.GetParams(ctx)
	if err != nil {
		return nil, err
	}
	return &types.QueryParamsResponse{Params: &params}, nil
}

// RegistrationRoot returns the current registration tree root.
func (q queryServer) RegistrationRoot(ctx context.Context, req *types.QueryRegistrationRootRequest) (*types.QueryRegistrationRootResponse, error) {
	root, err := q.GetRegMerkleRoot(ctx)
	if err != nil {
		return nil, err
	}
	return &types.QueryRegistrationRootResponse{Root: root}, nil
}

// AuditorKey returns the current auditor public key.
func (q queryServer) AuditorKey(ctx context.Context, req *types.QueryAuditorKeyRequest) (*types.QueryAuditorKeyResponse, error) {
	params, err := q.GetParams(ctx)
	if err != nil {
		return nil, err
	}
	return &types.QueryAuditorKeyResponse{AuditorPubKey: params.AuditorPubKey}, nil
}

// SupportedDenoms returns the list of supported denominations.
func (q queryServer) SupportedDenoms(ctx context.Context, req *types.QuerySupportedDenomsRequest) (*types.QuerySupportedDenomsResponse, error) {
	params, err := q.GetParams(ctx)
	if err != nil {
		return nil, err
	}
	return &types.QuerySupportedDenomsResponse{Denoms: params.SupportedDenoms}, nil
}
