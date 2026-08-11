package keeper

import (
	"context"
	"encoding/json"
	"fmt"

	"cosmossdk.io/core/address"
	"cosmossdk.io/core/store"
	"github.com/cosmos/cosmos-sdk/codec"

	"github.com/nixprotocol/cosmos-nixpool/types"
)

// Keeper maintains the nixpool module state.
type Keeper struct {
	cdc          codec.Codec
	storeService store.KVStoreService
	addressCodec address.Codec
	bankKeeper   types.BankKeeper
	authority    []byte
}

// NewKeeper creates a new nixpool keeper.
func NewKeeper(
	storeService store.KVStoreService,
	cdc codec.Codec,
	addressCodec address.Codec,
	authority []byte,
	bankKeeper types.BankKeeper,
) Keeper {
	if _, err := addressCodec.BytesToString(authority); err != nil {
		panic(fmt.Sprintf("invalid authority address: %s", err))
	}
	return Keeper{
		cdc:          cdc,
		storeService: storeService,
		addressCodec: addressCodec,
		bankKeeper:   bankKeeper,
		authority:    authority,
	}
}

// GetAuthority returns the module authority address as bytes.
func (k Keeper) GetAuthority() []byte {
	return k.authority
}

// GetAddressCodec returns the address codec.
func (k Keeper) GetAddressCodec() address.Codec {
	return k.addressCodec
}

// SetParams stores the module parameters.
func (k Keeper) SetParams(ctx context.Context, params types.Params) error {
	store := k.storeService.OpenKVStore(ctx)
	bz, err := json.Marshal(params)
	if err != nil {
		return err
	}
	return store.Set(types.ParamsKeyBytes(), bz)
}

// SetVerificationKey stores a circuit VK in state.
func (k Keeper) SetVerificationKey(ctx context.Context, circuitName string, vkData []byte) error {
	store := k.storeService.OpenKVStore(ctx)
	return store.Set(types.VKKey(circuitName), vkData)
}

// GetVerificationKeyFromState loads a circuit VK from state.
func (k Keeper) GetVerificationKeyFromState(ctx context.Context, circuitName string) ([]byte, error) {
	store := k.storeService.OpenKVStore(ctx)
	return store.Get(types.VKKey(circuitName))
}

// GetParams returns the module parameters.
func (k Keeper) GetParams(ctx context.Context) (types.Params, error) {
	store := k.storeService.OpenKVStore(ctx)
	bz, err := store.Get(types.ParamsKeyBytes())
	if err != nil {
		return types.Params{}, err
	}
	if bz == nil {
		return types.DefaultParams(), nil
	}
	var params types.Params
	if err := json.Unmarshal(bz, &params); err != nil {
		return types.Params{}, err
	}
	return params, nil
}
