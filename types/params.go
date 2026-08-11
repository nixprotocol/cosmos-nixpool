package types

const (
	// DefaultTreeDepth is the depth of note Merkle trees (2^20 leaves per tree).
	DefaultTreeDepth = 20

	// DefaultRegTreeDepth is the depth of the registration Merkle tree.
	DefaultRegTreeDepth = 20
)

// DefaultParams returns default module parameters.
func DefaultParams() Params {
	return Params{
		TreeDepth:       DefaultTreeDepth,
		RegTreeDepth:    DefaultRegTreeDepth,
		AuditorPubKey:   nil,
		SupportedDenoms: []string{"anix"},
	}
}

// Validate validates the parameter set.
func (p Params) Validate() error {
	if p.TreeDepth == 0 || p.TreeDepth > 40 {
		return ErrInvalidCommitment.Wrap("tree depth must be between 1 and 40")
	}
	if p.RegTreeDepth == 0 || p.RegTreeDepth > 40 {
		return ErrInvalidCommitment.Wrap("reg tree depth must be between 1 and 40")
	}
	// The auditor key is two 32-byte Grumpkin coordinates. Handlers bind proof
	// public inputs against these bytes, so a short key would silently disable
	// that binding instead of failing loudly here.
	if len(p.AuditorPubKey) != 0 && len(p.AuditorPubKey) != 64 {
		return ErrInvalidPublicInputs.Wrapf(
			"auditor public key must be 64 bytes, got %d", len(p.AuditorPubKey))
	}
	// ChainBinding is read into a single field element.
	if len(p.ChainBinding) > 32 {
		return ErrInvalidPublicInputs.Wrapf(
			"chain binding must be at most 32 bytes, got %d", len(p.ChainBinding))
	}
	return nil
}
