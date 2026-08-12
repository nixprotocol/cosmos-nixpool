package cli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	nixcrypto "github.com/nixprotocol/cosmos-nixpool/crypto"
)

// CmdGenNixKey generates a random Grumpkin keypair and displays the nix address.
func CmdGenNixKey() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gen-nix-key",
		Short: "Generate a random Grumpkin keypair and display the nix address",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			privKey, err := nixcrypto.GenerateKey()
			if err != nil {
				return fmt.Errorf("failed to generate key: %w", err)
			}

			pubKey, err := privKey.PubKey()
			if err != nil {
				return fmt.Errorf("failed to derive public key: %w", err)
			}

			nixAddr := nixcrypto.EncodeNixAddress(pubKey)
			commitment := pubKey.Commitment()
			commitmentBytes := commitment.Bytes()

			jsonFlag, _ := cmd.Flags().GetBool("json")
			if jsonFlag {
				output := map[string]string{
					"private_key":  hex.EncodeToString(privKey.ScalarBytes()),
					"public_key_x": fmt.Sprintf("%064x", pubKey.Key[:32]),
					"public_key_y": fmt.Sprintf("%064x", pubKey.Key[32:]),
					"commitment":   fmt.Sprintf("%064x", commitmentBytes),
					"nix_address":  nixAddr,
				}
				bz, err := json.MarshalIndent(output, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(bz))
				return nil
			}

			fmt.Fprintln(cmd.OutOrStdout(), "=== Nix Key Generated ===")
			fmt.Fprintf(cmd.OutOrStdout(), "Private Key (scalar): %s\n", hex.EncodeToString(privKey.ScalarBytes()))
			fmt.Fprintf(cmd.OutOrStdout(), "Public Key X:         %064x\n", pubKey.Key[:32])
			fmt.Fprintf(cmd.OutOrStdout(), "Public Key Y:         %064x\n", pubKey.Key[32:])
			fmt.Fprintf(cmd.OutOrStdout(), "Commitment:           %064x\n", commitmentBytes)
			fmt.Fprintf(cmd.OutOrStdout(), "Nix Address:          %s\n", nixAddr)

			return nil
		},
	}

	cmd.Flags().Bool("json", false, "output in JSON format")
	return cmd
}

// CmdNixAddress takes a private key scalar hex and displays the nix address.
func CmdNixAddress() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nix-address [privkey-scalar-hex]",
		Short: "Display the nix address for a given Grumpkin private key scalar",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scalarBytes, err := hex.DecodeString(args[0])
			if err != nil {
				return fmt.Errorf("invalid private key hex: %w", err)
			}

			privKey, err := nixcrypto.PrivKeyFromScalarBytes(scalarBytes)
			if err != nil {
				return fmt.Errorf("failed to construct key from scalar: %w", err)
			}

			pubKey, err := privKey.PubKey()
			if err != nil {
				return fmt.Errorf("failed to derive public key: %w", err)
			}

			nixAddr := nixcrypto.EncodeNixAddress(pubKey)
			commitment := pubKey.Commitment()
			commitmentBytes := commitment.Bytes()

			jsonFlag, _ := cmd.Flags().GetBool("json")
			if jsonFlag {
				output := map[string]string{
					"public_key_x": fmt.Sprintf("%064x", pubKey.Key[:32]),
					"public_key_y": fmt.Sprintf("%064x", pubKey.Key[32:]),
					"commitment":   fmt.Sprintf("%064x", commitmentBytes),
					"nix_address":  nixAddr,
				}
				bz, err := json.MarshalIndent(output, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(bz))
				return nil
			}

			fmt.Fprintln(cmd.OutOrStdout(), "=== Nix Address ===")
			fmt.Fprintf(cmd.OutOrStdout(), "Public Key X: %064x\n", pubKey.Key[:32])
			fmt.Fprintf(cmd.OutOrStdout(), "Public Key Y: %064x\n", pubKey.Key[32:])
			fmt.Fprintf(cmd.OutOrStdout(), "Commitment:   %064x\n", commitmentBytes)
			fmt.Fprintf(cmd.OutOrStdout(), "Nix Address:  %s\n", nixAddr)

			return nil
		},
	}

	cmd.Flags().Bool("json", false, "output in JSON format")
	return cmd
}
