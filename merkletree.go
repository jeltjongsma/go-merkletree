package gomerkletree

import (
	"bytes"
	"errors"

	"github.com/jeltjongsma/go-merkletree/pkg/hashing"
)

type Node struct {
	h           []byte
	left, right *Node
	parent      *Node
}

func (n *Node) verify(hasher HashStrategy) bool {
	if n.left != nil && n.right != nil {
		hash := hasher.HashInternal(n.left.h, n.right.h)
		return bytes.Equal(n.h, hash) && n.left.verify(hasher) && n.right.verify(hasher)
	} else if n.left == nil && n.right == nil {
		return true
	} else {
		return false
	}
}

func (n *Node) isLeft() bool {
	return n.parent != nil && n.parent.left == n
}

// Leaf is the interface data needs to implement to turn it into a merkle tree.
type Leaf interface {
	Bytes() []byte
}

// HashStrategy is the interface for defining custom hashing strategies.
type HashStrategy interface {
	HashLeaf([]byte) []byte
	HashInternal([]byte, []byte) []byte
}

type defaultHashStrategy struct{}

func (h defaultHashStrategy) HashLeaf(l []byte) []byte {
	bytes := append([]byte{0x00}, l...)
	return hashing.HashSHA256(bytes)
}

func (h defaultHashStrategy) HashInternal(l, r []byte) []byte {
	bytes := append([]byte{0x01}, l...)
	bytes = append(bytes, r...)
	return hashing.HashSHA256(bytes)
}

type Proof struct {
	root         []byte
	siblings     [][]byte
	left         []bool
	hashStrategy HashStrategy
}

type MerkleTree struct {
	root         *Node
	n            int
	leaves       []*Node
	hashStrategy HashStrategy
}

// BuildMerkleTree takes a slice of leaves and builds a merkle tree.
// This function will use the default SHA-256 based hash strategy,
// where leaves and internal nodes are prepended with 0x00 and 0x01, respectively.
// On odd input the function relies on promotion, where the last node is carried up unchanged.
func BuildMerkleTree(data []Leaf) *MerkleTree {
	return buildMerkleTree(data, defaultHashStrategy{})
}

// BuildMerkleTreeWithHashStrategy takes a slice of leaves and a hash strategy, and builds a merkle tree.
// On odd input the function relies on promotion, where the last node is carried up unchanged.
func BuildMerkleTreeWithHashStrategy(data []Leaf, hash HashStrategy) *MerkleTree {
	return buildMerkleTree(data, hash)
}

func buildMerkleTree(data []Leaf, hash HashStrategy) *MerkleTree {
	if len(data) == 0 {
		return nil
	}
	level := make([]*Node, len(data))
	for i, x := range data {
		level[i] = &Node{
			h: hash.HashLeaf(x.Bytes()),
		}
	}

	var leaves []*Node
	leaves = append(leaves, level...)

	n := len(level)
	for len(level) > 1 {
		next := make([]*Node, 0, (len(level)+1)/2)
		for i := range len(level) / 2 {
			parent := &Node{
				h:     hash.HashInternal(level[2*i].h, level[2*i+1].h),
				left:  level[2*i],
				right: level[2*i+1],
			}
			parent.left.parent = parent
			parent.right.parent = parent
			next = append(next, parent)
			n++
		}
		if len(level)%2 != 0 {
			next = append(next, level[len(level)-1])
		}

		level = next
	}

	return &MerkleTree{
		root:         level[0],
		n:            n,
		leaves:       leaves,
		hashStrategy: hash,
	}
}

// Root returns the bytes of the root.
func (m *MerkleTree) Root() []byte {
	if m == nil || m.root == nil {
		return nil
	}
	return m.root.h
}

// Len returns the total number of nodes in the tree.
func (m *MerkleTree) Len() int {
	if m == nil {
		return -1
	}
	return m.n
}

// Verify verifies the integrity of the tree.
func (m *MerkleTree) Verify() bool {
	return m != nil && m.root != nil && m.hashStrategy != nil && m.root.verify(m.hashStrategy)
}

// VerifyExists verifies a leaf's existence in the tree in O(n) and returns its node (if found).
func (m *MerkleTree) VerifyExists(x Leaf) (*Node, error) {
	inLeaves := false
	hash := m.hashStrategy.HashLeaf(x.Bytes())
	var node *Node
	for _, l := range m.leaves {
		if bytes.Equal(hash, l.h) {
			inLeaves = true
			node = l
		}
	}
	if !inLeaves {
		return node, errors.New("not in tree")
	}

	if !m.Verify() {
		return node, errors.New("unable to verify tree")
	}

	return node, nil
}

// Proof generates a proof for a given leaf.
// Returns `Proof` object that contains the root, necessary siblings for the proof,
// and whether the sibling is a left or right child.
func (m *MerkleTree) Proof(x Leaf) (proof *Proof, err error) {
	if m == nil {
		return nil, errors.New("nil tree")
	}
	node, err := m.VerifyExists(x)
	if err != nil {
		return nil, err
	}

	var siblings [][]byte
	var left []bool

	for node.parent != nil {
		if isLeft := node.isLeft(); isLeft {
			siblings = append(siblings, node.parent.right.h)
			left = append(left, false) // maps to sibling hash
		} else {
			siblings = append(siblings, node.parent.left.h)
			left = append(left, true) // maps to sibling hash
		}
		node = node.parent
	}

	return &Proof{
		root:         m.Root(),
		siblings:     siblings,
		left:         left,
		hashStrategy: m.hashStrategy,
	}, nil
}

// VerifyProof checks if a proof is valid for a given leaf.
func VerifyProof(x Leaf, p *Proof) error {
	if p == nil || p.hashStrategy == nil {
		return errors.New("no proof/hash strategy")
	}
	if len(p.siblings) != len(p.left) {
		return errors.New("proof lengths mismatch")
	}
	hash := p.hashStrategy.HashLeaf(x.Bytes())

	for i, isLeft := range p.left {
		if isLeft {
			hash = p.hashStrategy.HashInternal(p.siblings[i], hash)
		} else {
			hash = p.hashStrategy.HashInternal(hash, p.siblings[i])
		}
	}

	if !bytes.Equal(hash, p.root) {
		return errors.New("root does not match")
	}
	return nil
}
