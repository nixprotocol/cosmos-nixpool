package cli

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"

	"github.com/nixprotocol/cosmos-nixpool/types"
)

// GetQueryCmd returns the query commands for the nixpool module.
func GetQueryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      "Querying commands for the nixpool privacy module",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		CmdQueryRoot(),
		CmdQueryNullifierStatus(),
		CmdQueryTreeInfo(),
		CmdQueryParams(),
		CmdQueryRegistrationRoot(),
		CmdQueryAuditorKey(),
		CmdQuerySupportedDenoms(),
	)

	return cmd
}

func CmdQueryRoot() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "root",
		Short: "Query the current Merkle root of the active note tree",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			queryClient := types.NewQueryClient(clientCtx)
			res, err := queryClient.Root(cmd.Context(), &types.QueryRootRequest{})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Root: %x\n", res.Root)
			return nil
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func CmdQueryNullifierStatus() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nullifier-status [hex]",
		Short: "Check whether a nullifier has been spent",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			nullifier, err := hex.DecodeString(args[0])
			if err != nil {
				return fmt.Errorf("invalid hex: %w", err)
			}
			queryClient := types.NewQueryClient(clientCtx)
			res, err := queryClient.NullifierStatus(cmd.Context(), &types.QueryNullifierStatusRequest{
				Nullifier: nullifier,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Spent: %v\n", res.Spent)
			return nil
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func CmdQueryTreeInfo() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tree-info",
		Short: "Query Merkle tree forest metadata",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			queryClient := types.NewQueryClient(clientCtx)
			res, err := queryClient.TreeInfo(cmd.Context(), &types.QueryTreeInfoRequest{})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Root: %x\nNextIndex: %d\nDepth: %d\nActiveTreeId: %d\nTreeCount: %d\n",
				res.Root, res.NextIndex, res.Depth, res.ActiveTreeId, res.TreeCount)
			return nil
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func CmdQueryParams() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "params",
		Short: "Query the nixpool module parameters",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			queryClient := types.NewQueryClient(clientCtx)
			res, err := queryClient.Params(cmd.Context(), &types.QueryParamsRequest{})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Params: %+v\n", res.Params)
			return nil
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func CmdQueryRegistrationRoot() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registration-root",
		Short: "Query the current registration tree root",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			queryClient := types.NewQueryClient(clientCtx)
			res, err := queryClient.RegistrationRoot(cmd.Context(), &types.QueryRegistrationRootRequest{})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "RegistrationRoot: %x\n", res.Root)
			return nil
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func CmdQueryAuditorKey() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auditor-key",
		Short: "Query the current auditor public key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			queryClient := types.NewQueryClient(clientCtx)
			res, err := queryClient.AuditorKey(cmd.Context(), &types.QueryAuditorKeyRequest{})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "AuditorPubKey: %x\n", res.AuditorPubKey)
			return nil
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func CmdQuerySupportedDenoms() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "supported-denoms",
		Short: "Query the list of supported denominations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			queryClient := types.NewQueryClient(clientCtx)
			res, err := queryClient.SupportedDenoms(cmd.Context(), &types.QuerySupportedDenomsRequest{})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "SupportedDenoms: %v\n", res.Denoms)
			return nil
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}
