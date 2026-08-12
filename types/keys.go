package types

import (
	"encoding/binary"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const (
	ModuleName        = "nixpool"
	StoreKey          = ModuleName
	ModuleAccountName = ModuleName

	// MaxRootHistory is the number of recent Merkle roots kept per tree for validation.
	MaxRootHistory = 100

	// MaxAuditorDataSize is the maximum size of auditor encrypted data in bytes.
	MaxAuditorDataSize = 4096
)

// Store key prefixes for multi-tree forest.
var (
	// Per-tree note commitments: prefix + treeId(8) + index(8)
	commitmentPrefix = []byte("nixpool/c/")
	// Per-tree frontier: prefix + treeId(8) + level(4)
	frontierPrefix = []byte("nixpool/f/")
	// Per-tree root history ring buffer: prefix + treeId(8) + slot(8)
	rootHistoryPrefix = []byte("nixpool/rh/")
	// Per-tree current root: prefix + treeId(8)
	treeRootPrefix = []byte("nixpool/tr/")

	// rootIndexPrefix keys the root -> reference-count reverse index.
	rootIndexPrefix = []byte("nixpool/ri/")
	// Per-tree next index: prefix + treeId(8)
	treeNextIndexPrefix = []byte("nixpool/ti/")
	// Active tree ID
	activeTreeIdKey = []byte("nixpool/atid")
	// Total tree count
	treeCountKey = []byte("nixpool/tc")

	// Registration tree (single tree, not multi-tree)
	regCommitmentPrefix = []byte("nixpool/reg/c/")
	regFrontierPrefix   = []byte("nixpool/reg/f/")
	regRootKey          = []byte("nixpool/reg/root")
	regNextIndexKey     = []byte("nixpool/reg/ni")

	// Commitment used tracking (prevents duplicate inserts)
	commitmentUsedPrefix = []byte("nixpool/used/")
	// Registration commitment used tracking (prevents duplicate inserts)
	regCommitmentUsedPrefix = []byte("nixpool/reg/used/")

	// Nullifier tracking
	nullifierPrefix = []byte("nixpool/n/")

	// Module params
	paramsKey = []byte("nixpool/params")

	// Verification keys: prefix + circuitName
	vkPrefix = []byte("nixpool/vk/")

	// Auditor encrypted data: prefix + txHash
	auditorDataPrefix = []byte("nixpool/ad/")
)

// Key accessor functions — each returns a fresh slice to avoid append mutation.

func ActiveTreeIdKey() []byte      { return copyBytes(activeTreeIdKey) }
func TreeCountKey() []byte         { return copyBytes(treeCountKey) }
func RegRootKeyBytes() []byte      { return copyBytes(regRootKey) }
func RegNextIndexKeyBytes() []byte { return copyBytes(regNextIndexKey) }
func ParamsKeyBytes() []byte       { return copyBytes(paramsKey) }

// Prefix accessors for iteration during genesis export.
func CommitmentPrefix() []byte        { return copyBytes(commitmentPrefix) }
func FrontierPrefixAll() []byte       { return copyBytes(frontierPrefix) }
func RootHistoryPrefixAll() []byte    { return copyBytes(rootHistoryPrefix) }
func TreeRootPrefixAll() []byte       { return copyBytes(treeRootPrefix) }
func TreeNextIndexPrefixAll() []byte  { return copyBytes(treeNextIndexPrefix) }
func RegCommitmentPrefix() []byte     { return copyBytes(regCommitmentPrefix) }
func RegFrontierPrefix() []byte       { return copyBytes(regFrontierPrefix) }
func NullifierPrefix() []byte         { return copyBytes(nullifierPrefix) }
func AuditorDataPrefix() []byte       { return copyBytes(auditorDataPrefix) }
func CommitmentUsedPrefix() []byte    { return copyBytes(commitmentUsedPrefix) }
func RegCommitmentUsedPrefix() []byte { return copyBytes(regCommitmentUsedPrefix) }
func VKPrefix() []byte                { return copyBytes(vkPrefix) }

// Multi-tree key constructors

// CommitmentKey returns the store key for a leaf in a specific tree.
func CommitmentKey(treeId uint64, index uint64) []byte {
	key := make([]byte, len(commitmentPrefix)+16)
	copy(key, commitmentPrefix)
	binary.BigEndian.PutUint64(key[len(commitmentPrefix):], treeId)
	binary.BigEndian.PutUint64(key[len(commitmentPrefix)+8:], index)
	return key
}

// FrontierKey returns the store key for a frontier element in a specific tree.
func FrontierKey(treeId uint64, level uint32) []byte {
	key := make([]byte, len(frontierPrefix)+12)
	copy(key, frontierPrefix)
	binary.BigEndian.PutUint64(key[len(frontierPrefix):], treeId)
	binary.BigEndian.PutUint32(key[len(frontierPrefix)+8:], level)
	return key
}

// RootHistoryKey returns the store key for a root history slot in a specific tree.
func RootHistoryKey(treeId uint64, slot uint64) []byte {
	key := make([]byte, len(rootHistoryPrefix)+16)
	copy(key, rootHistoryPrefix)
	binary.BigEndian.PutUint64(key[len(rootHistoryPrefix):], treeId)
	binary.BigEndian.PutUint64(key[len(rootHistoryPrefix)+8:], slot)
	return key
}

// TreeRootKey returns the store key for the current root of a specific tree.
func TreeRootKey(treeId uint64) []byte {
	return appendUint64(treeRootPrefix, treeId)
}

// RootIndexKey keys the reverse index from a root to the number of live
// references to it across the forest -- every TreeRootKey slot and every
// RootHistoryKey slot currently holding that value.
//
// It exists so root validation is O(1) instead of a scan over
// trees x MaxRootHistory. A reference count rather than a plain set is
// required because one root legitimately occupies several slots at once: an
// insert writes the new root to both the tree's current-root slot and a history
// slot, and every freshly created tree starts at the same empty root.
//
// The canonicalisation is load-bearing for the same reason it is on
// NullifierKey: a field element has multiple valid byte encodings, and a root
// looked up under one encoding must hit the entry written under another.
func RootIndexKey(root []byte) []byte {
	return appendBytes(rootIndexPrefix, CanonicalFieldBytes(root))
}

// TreeNextIndexKey returns the store key for the next leaf index of a specific tree.
func TreeNextIndexKey(treeId uint64) []byte {
	return appendUint64(treeNextIndexPrefix, treeId)
}

// Registration tree keys (single tree)

func RegCommitmentKey(index uint64) []byte {
	return appendUint64(regCommitmentPrefix, index)
}

func RegFrontierKey(level uint32) []byte {
	return appendUint32(regFrontierPrefix, level)
}

// Other keys

// CanonicalFieldBytes reduces 32-byte field-element input to its canonical
// little-than-modulus encoding.
//
// Circuit public inputs are parsed with fr.Element.SetBytes, which reduces mod
// p. A value N therefore has several distinct 32-byte encodings — N, N+p,
// N+2p, ... — that are all indistinguishable to a proof. Any store key derived
// from the RAW bytes would treat those as different entries while the proof
// treats them as the same value.
//
// For the nullifier set that mismatch is a double-spend: one note yields six
// independent "not yet spent" slots (floor(2^256/p) = 5, so N .. N+5p all fit
// in 32 bytes), and a single transact proof re-verifies against every one of
// them. Every key built from a field element must go through this.
func CanonicalFieldBytes(b []byte) []byte {
	var e fr.Element
	e.SetBytes(b)
	out := e.Bytes()
	return out[:]
}

func CommitmentUsedKey(commitment []byte) []byte {
	return appendBytes(commitmentUsedPrefix, CanonicalFieldBytes(commitment))
}

// RegCommitmentUsedKey marks a registration commitment as already inserted so
// one identity cannot consume repeated slots in the registration tree.
func RegCommitmentUsedKey(commitment []byte) []byte {
	return appendBytes(regCommitmentUsedPrefix, CanonicalFieldBytes(commitment))
}

// NullifierKey keys the spent-nullifier set. The canonicalisation is
// load-bearing: see CanonicalFieldBytes.
func NullifierKey(hash []byte) []byte {
	return appendBytes(nullifierPrefix, CanonicalFieldBytes(hash))
}

func VKKey(circuitName string) []byte {
	return appendBytes(vkPrefix, []byte(circuitName))
}

func AuditorDataKey(txHash []byte) []byte {
	return appendBytes(auditorDataPrefix, txHash)
}

// helpers that always allocate fresh slices

func copyBytes(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func appendUint64(prefix []byte, v uint64) []byte {
	key := make([]byte, len(prefix)+8)
	copy(key, prefix)
	binary.BigEndian.PutUint64(key[len(prefix):], v)
	return key
}

func appendUint32(prefix []byte, v uint32) []byte {
	key := make([]byte, len(prefix)+4)
	copy(key, prefix)
	binary.BigEndian.PutUint32(key[len(prefix):], v)
	return key
}

func appendBytes(prefix, suffix []byte) []byte {
	key := make([]byte, len(prefix)+len(suffix))
	copy(key, prefix)
	copy(key[len(prefix):], suffix)
	return key
}
