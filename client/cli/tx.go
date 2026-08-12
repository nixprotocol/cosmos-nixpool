package cli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"

	"github.com/nixprotocol/cosmos-nixpool/types"
)

const (
	flagAuditorData = "auditor-data"
)

// GetTxCmd returns the transaction commands for the nixpool module.
func GetTxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      "Transaction commands for the nixpool privacy module",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	cmd.AddCommand(
		CmdDeposit(),
		CmdTransact(),
		CmdRegister(),
		CmdGenNixKey(),
		CmdNixAddress(),
	)

	return cmd
}

// CmdDeposit creates a deposit transaction.
func CmdDeposit() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deposit [denom] [amount] [note-commitment-hex] [proof-file] [public-inputs-file]",
		Short: "Deposit tokens into the privacy pool",
		Args:  cobra.ExactArgs(5),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			denom := args[0]
			amount := args[1]

			noteCommitment, err := hex.DecodeString(args[2])
			if err != nil {
				return fmt.Errorf("invalid note commitment hex: %w", err)
			}

			proof, err := os.ReadFile(args[3])
			if err != nil {
				return fmt.Errorf("failed to read proof file: %w", err)
			}

			publicInputs, err := os.ReadFile(args[4])
			if err != nil {
				return fmt.Errorf("failed to read public inputs file: %w", err)
			}

			auditorData, err := readAuditorDataFlag(cmd)
			if err != nil {
				return err
			}

			msg := &types.MsgDeposit{
				Sender:               clientCtx.GetFromAddress().String(),
				Denom:                denom,
				Amount:               amount,
				NoteCommitment:       noteCommitment,
				Proof:                proof,
				PublicInputs:         publicInputs,
				AuditorEncryptedData: auditorData,
			}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	cmd.Flags().String(flagAuditorData, "", "path to auditor encrypted data file (optional)")
	return cmd
}

// CmdTransact creates a 2-in/2-out private transfer (optionally with withdrawal).
func CmdTransact() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "transact [proof-file] [nullifiers-csv] [roots-csv] [outputs-json-file] [denom] [reg-root-hex]",
		Short: "Private 2-in/2-out transfer within the privacy pool",
		Long: `Execute a private transfer with 2 input notes and 2 output notes.
Supports optional withdrawal (withdraw_amount > 0) and relayer fees.

Arguments:
  proof-file:       Path to the UltraHonk proof binary
  nullifiers-csv:   Comma-separated hex nullifiers (exactly 2)
  roots-csv:        Comma-separated hex merkle roots (exactly 2)
  outputs-json-file: JSON file with 2 OutputNote objects
  denom:            Token denomination
  reg-root-hex:     Registration tree root (hex)

Flags:
  --withdraw-amount: Amount to withdraw (default 0)
  --withdraw-address: Recipient address for withdrawal
  --relayer-fee:    Relayer fee (default 0)`,
		Args: cobra.ExactArgs(6),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			proof, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("failed to read proof file: %w", err)
			}

			// Parse nullifiers
			nullifierHexes := strings.Split(args[1], ",")
			if len(nullifierHexes) != 2 {
				return fmt.Errorf("exactly 2 nullifiers required, got %d", len(nullifierHexes))
			}
			nullifiers := make([][]byte, 2)
			for i, h := range nullifierHexes {
				nullifiers[i], err = hex.DecodeString(strings.TrimSpace(h))
				if err != nil {
					return fmt.Errorf("invalid nullifier %d hex: %w", i, err)
				}
			}

			// Parse merkle roots
			rootHexes := strings.Split(args[2], ",")
			if len(rootHexes) != 2 {
				return fmt.Errorf("exactly 2 merkle roots required, got %d", len(rootHexes))
			}
			merkleRoots := make([][]byte, 2)
			for i, h := range rootHexes {
				merkleRoots[i], err = hex.DecodeString(strings.TrimSpace(h))
				if err != nil {
					return fmt.Errorf("invalid merkle root %d hex: %w", i, err)
				}
			}

			// Parse outputs from JSON file
			outputsData, err := os.ReadFile(args[3])
			if err != nil {
				return fmt.Errorf("failed to read outputs file: %w", err)
			}
			outputs, err := parseOutputNotesJSON(outputsData)
			if err != nil {
				return fmt.Errorf("failed to parse outputs: %w", err)
			}

			denom := args[4]

			regRoot, err := hex.DecodeString(args[5])
			if err != nil {
				return fmt.Errorf("invalid registration root hex: %w", err)
			}

			withdrawAmount, _ := cmd.Flags().GetString("withdraw-amount")
			withdrawAddress, _ := cmd.Flags().GetString("withdraw-address")
			relayerFee, _ := cmd.Flags().GetString("relayer-fee")

			msg := &types.MsgTransact{
				Sender:           clientCtx.GetFromAddress().String(),
				Nullifiers:       nullifiers,
				MerkleRoots:      merkleRoots,
				Outputs:          outputs,
				WithdrawAmount:   withdrawAmount,
				WithdrawAddress:  withdrawAddress,
				Denom:            denom,
				RegistrationRoot: regRoot,
				RelayerFee:       relayerFee,
				Proof:            proof,
			}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	cmd.Flags().String("withdraw-amount", "0", "amount to withdraw from the pool")
	cmd.Flags().String("withdraw-address", "", "address to receive withdrawal")
	cmd.Flags().String("relayer-fee", "0", "fee to pay relayer")
	return cmd
}

// CmdRegister creates an identity registration transaction.
func CmdRegister() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register [identity-commitment-hex] [proof-file] [public-inputs-file]",
		Short: "Register an identity in the privacy pool",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			identityCommitment, err := hex.DecodeString(args[0])
			if err != nil {
				return fmt.Errorf("invalid identity commitment hex: %w", err)
			}

			proof, err := os.ReadFile(args[1])
			if err != nil {
				return fmt.Errorf("failed to read proof file: %w", err)
			}

			publicInputs, err := os.ReadFile(args[2])
			if err != nil {
				return fmt.Errorf("failed to read public inputs file: %w", err)
			}

			auditorData, err := readAuditorDataFlag(cmd)
			if err != nil {
				return err
			}

			msg := &types.MsgRegister{
				Sender:               clientCtx.GetFromAddress().String(),
				IdentityCommitment:   identityCommitment,
				Proof:                proof,
				PublicInputs:         publicInputs,
				AuditorEncryptedData: auditorData,
			}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	cmd.Flags().String(flagAuditorData, "", "path to auditor encrypted data file (optional)")
	return cmd
}

// readAuditorDataFlag reads the optional --auditor-data flag (file path).
func readAuditorDataFlag(cmd *cobra.Command) ([]byte, error) {
	path, _ := cmd.Flags().GetString(flagAuditorData)
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read auditor data file: %w", err)
	}
	return data, nil
}

// parseOutputNotesJSON parses a JSON array of OutputNote hex objects.
func parseOutputNotesJSON(data []byte) ([]*types.OutputNote, error) {
	type outputNoteHex struct {
		NoteHash            string `json:"note_hash"`
		EphemeralX          string `json:"ephemeral_x"`
		EphemeralY          string `json:"ephemeral_y"`
		EncAmount           string `json:"enc_amount"`
		EncSalt             string `json:"enc_salt"`
		AuditorEnc          string `json:"auditor_enc"`
		AuditorAuthKeyX     string `json:"auditor_auth_key_x"`
		AuditorAuthKeyY     string `json:"auditor_auth_key_y"`
		AuditorEncRecipient string `json:"auditor_enc_recipient"`
	}

	var hexNotes []outputNoteHex
	if err := json.Unmarshal(data, &hexNotes); err != nil {
		return nil, err
	}
	if len(hexNotes) != 2 {
		return nil, fmt.Errorf("exactly 2 output notes required, got %d", len(hexNotes))
	}

	notes := make([]*types.OutputNote, 2)
	for i, hn := range hexNotes {
		note := &types.OutputNote{}
		var err error
		if note.NoteHash, err = hex.DecodeString(hn.NoteHash); err != nil {
			return nil, fmt.Errorf("output %d note_hash: %w", i, err)
		}
		if note.EphemeralX, err = hex.DecodeString(hn.EphemeralX); err != nil {
			return nil, fmt.Errorf("output %d ephemeral_x: %w", i, err)
		}
		if note.EphemeralY, err = hex.DecodeString(hn.EphemeralY); err != nil {
			return nil, fmt.Errorf("output %d ephemeral_y: %w", i, err)
		}
		if note.EncAmount, err = hex.DecodeString(hn.EncAmount); err != nil {
			return nil, fmt.Errorf("output %d enc_amount: %w", i, err)
		}
		if note.EncSalt, err = hex.DecodeString(hn.EncSalt); err != nil {
			return nil, fmt.Errorf("output %d enc_salt: %w", i, err)
		}
		if note.AuditorEnc, err = hex.DecodeString(hn.AuditorEnc); err != nil {
			return nil, fmt.Errorf("output %d auditor_enc: %w", i, err)
		}
		if note.AuditorAuthKeyX, err = hex.DecodeString(hn.AuditorAuthKeyX); err != nil {
			return nil, fmt.Errorf("output %d auditor_auth_key_x: %w", i, err)
		}
		if note.AuditorAuthKeyY, err = hex.DecodeString(hn.AuditorAuthKeyY); err != nil {
			return nil, fmt.Errorf("output %d auditor_auth_key_y: %w", i, err)
		}
		if note.AuditorEncRecipient, err = hex.DecodeString(hn.AuditorEncRecipient); err != nil {
			return nil, fmt.Errorf("output %d auditor_enc_recipient: %w", i, err)
		}
		notes[i] = note
	}
	return notes, nil
}
