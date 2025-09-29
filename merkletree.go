package gomerkletree

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/jeltjongsma/go-merkletree/pkg/hashing"
)

type Node struct {
	h           []byte
	left, right *Node
	parent      *Node
}

func (n *Node) verify() bool {
	if n.left != nil && n.right != nil {
		hash := hashing.HashInternal(n.left.h, n.right.h)
		return bytes.Equal(n.h, hash) && n.left.verify() && n.right.verify()
	} else if n.left == nil && n.right == nil {
		return true
	} else {
		return false
	}
}

func (n *Node) isLeft() bool {
	if n.parent == nil {
		return false
	}
	if bytes.Equal(n.h, n.parent.left.h) {
		return true
	}
	return false
}

type Leaf interface {
	Bytes() []byte
}

type Proof struct {
	root     []byte
	siblings [][]byte
	left     []bool
}

type MerkleTree struct {
	root   *Node
	n      int
	leaves []*Node
}

func BuildMerkleTree(data []Leaf) *MerkleTree {
	if len(data) == 0 {
		return nil
	}
	level := make([]*Node, len(data))
	for i, x := range data {
		level[i] = &Node{
			h: hashing.HashLeaf(x.Bytes()),
		}
	}

	var leaves []*Node
	leaves = append(leaves, level...)

	n := len(level)
	for len(level) > 1 {
		next := make([]*Node, 0, (len(level)+1)/2)
		for i := range len(level) / 2 {
			parent := &Node{
				h:     hashing.HashInternal(level[2*i].h, level[2*i+1].h),
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
		root:   level[0],
		n:      n,
		leaves: leaves,
	}
}

func (m *MerkleTree) Root() []byte {
	return m.root.h
}

func (m *MerkleTree) Len() int {
	return m.n
}

func (m *MerkleTree) Verify() bool {
	return m.root.verify()
}

func (m *MerkleTree) VerifyExists(x Leaf) (*Node, error) {
	inLeaves := false
	hash := hashing.HashLeaf(x.Bytes())
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

func (m *MerkleTree) Proof(x Leaf) (proof *Proof, err error) {
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
		root:     m.Root(),
		siblings: siblings,
		left:     left,
	}, nil
}

func VerifyProof(x Leaf, p *Proof) error {
	if len(p.siblings) != len(p.left) {
		return errors.New("proof lengths mismatch")
	}
	hash := hashing.HashLeaf(x.Bytes())

	for i, isLeft := range p.left {
		if isLeft {
			hash = hashing.HashInternal(p.siblings[i], hash)
		} else {
			hash = hashing.HashInternal(hash, p.siblings[i])
		}
	}

	if !bytes.Equal(hash, p.root) {
		return errors.New("root does not match")
	}
	return nil
}

func (n *Node) PrintTreeDFS() {
	b64 := base64.RawStdEncoding.EncodeToString(n.h)
	fmt.Printf("x: %v\n", b64)
	if n.left != nil {
		fmt.Println("left:")
		n.left.PrintTreeDFS()
	}
	if n.right != nil {
		fmt.Println("right:")
		n.right.PrintTreeDFS()
	}
}
