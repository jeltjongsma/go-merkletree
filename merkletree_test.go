package gomerkletree

import (
	"bytes"
	"testing"

	"github.com/jeltjongsma/go-merkletree/pkg/hashing"
)

func TestNode_Verify(t *testing.T) {
	left := &Node{
		h: hashing.HashLeaf([]byte("a")),
	}
	right := &Node{
		h: hashing.HashLeaf([]byte("b")),
	}
	root := &Node{
		h:     hashing.HashInternal(left.h, right.h),
		left:  left,
		right: right,
	}

	if !root.verify() {
		t.Errorf("expected true, got false")
	}

	// change left leafs hash
	root.left = &Node{
		h: hashing.HashLeaf([]byte("c")),
	}

	if root.verify() {
		t.Errorf("expected false, got true")
	}

	// change right leafs hash
	root.left = left
	root.right = &Node{
		h: hashing.HashLeaf([]byte("d")),
	}

	if root.verify() {
		t.Errorf("expected false, got true")
	}

	// only one child
	root.right = nil

	if root.verify() {
		t.Errorf("expected false, got true")
	}

	// change root
	root.right = right
	root.h = hashing.HashInternal([]byte("a"), []byte("b")) // fails because no 0x01 prepend

	if root.verify() {
		t.Errorf("expected false, got true")
	}
}

type TestLeaf struct {
	x string
}

func (t *TestLeaf) Bytes() []byte {
	return []byte(t.x)
}

func TestTree_Build_Basic(t *testing.T) {
	var data []Leaf
	data = append(data, &TestLeaf{"a"})
	data = append(data, &TestLeaf{"b"})

	tree := BuildMerkleTree(data)

	// check tree properties
	if tree.Len() != 3 {
		t.Errorf("expected len=3, got %d", tree.Len())
	}

	if len(tree.leaves) != 2 {
		t.Fatalf("expected len=2, got %d", len(tree.leaves))
	}

	if !tree.Verify() {
		t.Fatalf("couldn't verify tree")
	}

	if _, err := tree.VerifyExists(data[0]); err != nil {
		t.Errorf("couldn't verify exists")
	}

	if _, err := tree.VerifyExists(data[1]); err != nil {
		t.Errorf("couldn't verify exists")
	}

	// check node properties
	left := hashing.HashLeaf(data[0].Bytes())
	right := hashing.HashLeaf(data[1].Bytes())
	root := hashing.HashInternal(left, right)

	if !bytes.Equal(tree.Root(), root) {
		t.Errorf("root not correct")
	}

	if !bytes.Equal(tree.leaves[0].parent.h, root) {
		t.Errorf("left parent not correct")
	}

	if !bytes.Equal(tree.leaves[1].parent.h, root) {
		t.Errorf("right parent not correct")
	}
}

func TestTree_Build_Uneven(t *testing.T) {
	var data []Leaf
	data = append(data, &TestLeaf{"a"})
	data = append(data, &TestLeaf{"b"})
	data = append(data, &TestLeaf{"c"})

	tree := BuildMerkleTree(data)

	// check tree properties
	if tree.Len() != 5 {
		t.Errorf("expected len=5, got %d", tree.Len())
	}

	if len(tree.leaves) != 3 {
		t.Fatalf("expected len=3, got %d", len(tree.leaves))
	}

	if !tree.Verify() {
		t.Fatalf("couldn't verify tree")
	}

	if _, err := tree.VerifyExists(data[0]); err != nil {
		t.Errorf("couldn't verify exists")
	}

	if _, err := tree.VerifyExists(data[1]); err != nil {
		t.Errorf("couldn't verify exists")
	}

	if _, err := tree.VerifyExists(data[2]); err != nil {
		t.Errorf("couldn't verify exists")
	}

	// check node properties
	leftLeft := hashing.HashLeaf(data[0].Bytes())
	leftRight := hashing.HashLeaf(data[1].Bytes())
	left := hashing.HashInternal(leftLeft, leftRight)
	right := hashing.HashLeaf(data[2].Bytes())

	root := hashing.HashInternal(left, right)

	if !bytes.Equal(tree.Root(), root) {
		t.Errorf("root not correct")
	}

	if !bytes.Equal(tree.leaves[0].parent.h, left) {
		t.Errorf("left left parent not correct")
	}

	if !bytes.Equal(tree.leaves[1].parent.h, left) {
		t.Errorf("left right parent not correct")
	}

	if !bytes.Equal(tree.leaves[2].parent.h, root) {
		t.Errorf("right parent not correct")
	}
}

func TestTree_VerifyExists(t *testing.T) {
	var data []Leaf
	data = append(data, &TestLeaf{"a"})
	data = append(data, &TestLeaf{"b"})
	data = append(data, &TestLeaf{"c"})

	tree := BuildMerkleTree(data)

	if _, err := tree.VerifyExists(data[0]); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if _, err := tree.VerifyExists(data[1]); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if _, err := tree.VerifyExists(data[2]); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if _, err := tree.VerifyExists(&TestLeaf{"d"}); err == nil {
		t.Errorf("expected error, got nil")
	}
}

func TestTree_Proof(t *testing.T) {
	var data []Leaf
	data = append(data, &TestLeaf{"a"})
	data = append(data, &TestLeaf{"b"})
	data = append(data, &TestLeaf{"c"})

	tree := BuildMerkleTree(data)

	// not in tree
	_, err := tree.Proof(&TestLeaf{"d"})
	if err == nil {
		t.Fatalf("expected err, got nil")
	}

	leftLeft := hashing.HashLeaf(data[0].Bytes())
	leftRight := hashing.HashLeaf(data[1].Bytes())
	left := hashing.HashInternal(leftLeft, leftRight)
	right := hashing.HashLeaf(data[2].Bytes())
	root := hashing.HashInternal(left, right)

	// check left left proof properties
	proof, err := tree.Proof(data[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(root, proof.root) {
		t.Errorf("root not correct")
	}

	if !bytes.Equal(leftRight, proof.siblings[0]) {
		t.Errorf("first sibling not correct")
	}
	if proof.left[0] {
		t.Errorf("expected false, got true (right child)")
	}

	if !bytes.Equal(right, proof.siblings[1]) {
		t.Errorf("second sibling not correct")
	}
	if proof.left[1] {
		t.Errorf("expected false, got true (right child)")
	}

	// check left right proof properties
	proof, err = tree.Proof(data[1])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(root, proof.root) {
		t.Errorf("root not correct")
	}

	if !bytes.Equal(leftLeft, proof.siblings[0]) {
		t.Errorf("first sibling not correct")
	}
	if !proof.left[0] {
		t.Errorf("expected true, got false (left child)")
	}

	if !bytes.Equal(right, proof.siblings[1]) {
		t.Errorf("second sibling not correct")
	}
	if proof.left[1] {
		t.Errorf("expected false, got true (right child)")
	}

	// check right proof properties
	proof, err = tree.Proof(data[2])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(root, proof.root) {
		t.Errorf("root not correct")
	}

	if !bytes.Equal(left, proof.siblings[0]) {
		t.Errorf("first sibling not correct")
	}
	if !proof.left[0] {
		t.Errorf("expected true, got false (left child)")
	}
}

func TestProof_Verify(t *testing.T) {
	var data []Leaf
	data = append(data, &TestLeaf{"a"})
	data = append(data, &TestLeaf{"b"})
	data = append(data, &TestLeaf{"c"})

	tree := BuildMerkleTree(data)

	proof, _ := tree.Proof(data[0])

	// happy case
	if err := VerifyProof(data[0], proof); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// wrong leaf for proof
	err := VerifyProof(data[1], proof)
	if err == nil {
		t.Errorf("expected err, got nil")
	}

	if err.Error() != "root does not match" {
		t.Errorf("expected root does not match, got %s", err.Error())
	}

	// invalid proof
	proof = &Proof{
		root:     []byte("a"),
		siblings: [][]byte{[]byte("a")},
		left:     []bool{false, true},
	}

	err = VerifyProof(data[0], proof)
	if err == nil {
		t.Fatalf("expected err, got nil")
	}

	if err.Error() != "proof lengths mismatch" {
		t.Errorf("expected lengths mismatch, got %s", err.Error())
	}
}
