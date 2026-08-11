package types

import (
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/msgservice"
)

func RegisterLegacyAminoCodec(cdc *codec.LegacyAmino) {
	cdc.RegisterConcrete(&MsgRegister{}, "nixpool/MsgRegister", nil)
	cdc.RegisterConcrete(&MsgDeposit{}, "nixpool/MsgDeposit", nil)
	cdc.RegisterConcrete(&MsgTransact{}, "nixpool/MsgTransact", nil)
	cdc.RegisterConcrete(&MsgUpdateParams{}, "nixpool/MsgUpdateParams", nil)
	cdc.RegisterConcrete(&MsgSetVerificationKey{}, "nixpool/MsgSetVerificationKey", nil)
}

func RegisterInterfaces(registry cdctypes.InterfaceRegistry) {
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgRegister{},
		&MsgDeposit{},
		&MsgTransact{},
		&MsgUpdateParams{},
		&MsgSetVerificationKey{},
	)
	msgservice.RegisterMsgServiceDesc(registry, &_Msg_serviceDesc)
}
