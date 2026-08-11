package types

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

const GovModuleName = "gov"

// BankKeeper defines the expected bank module interface used by the nixpool module.
type BankKeeper interface {
	SendCoinsFromAccountToModule(ctx context.Context, senderAddr sdk.AccAddress, recipientModule string, amt sdk.Coins) error
	SendCoinsFromModuleToAccount(ctx context.Context, senderModule string, recipientAddr sdk.AccAddress, amt sdk.Coins) error
	SpendableCoins(ctx context.Context, addr sdk.AccAddress) sdk.Coins
}
