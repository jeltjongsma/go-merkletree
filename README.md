# Go Merkle Tree

A simple Merkle tree implemented in Go. 
Leaves and internal nodes are prepended with `0x00` and `0x01` respectively, and hashed with SHA-256.
On odd inputs the tree relies on promotion, where the last node is carried up unchanged.

This library was implemented as a learning exercise into binary tree creation, Merkle trees, roots and proofs, so it is **not** hardened for production, and unlike standard implementations does not use duplication (which means standard proof verification methods likely won't work).

Building the Merkle tree is `O(n)` (with `n = #leaves`; the total number of nodes is ~2n-1). Proof size and verification are `O(log n)`.

## Overview
- `BuildMerkleTree(x []Leaf) *MerkleTree` 
- `*MerkleTree`
    - `.Proof(x Leaf) (*Proof, error)`
    - `.Root() []byte`
    - `.Len() int` - total number of nodes
    - `.Verify() bool` - verify tree integrity
    - `.VerifyExists(x Leaf) error` - verify existence in `O(n)`
- `VerifyProof(x Leaf, p *Proof) error`

```golang
// Leaf interface required for input data
type Leaf interface {
    Bytes() []byte
}
```


## Usage

### Installation
```bash
go get github.com/jeltjongsma/go-merkletree
```

### Example
```golang
package main

import (
    "encoding/hex"
	"fmt"

	"github.com/jeltjongsma/go-merkletree"
)

type TestLeaf struct {
	x string
}

func (t *TestLeaf) Bytes() []byte {
	return []byte(t.x)
}

func main() {
	data := []gomerkletree.Leaf{
		&TestLeaf{"a"},
		&TestLeaf{"b"},
		&TestLeaf{"c"},
	}

	mt := gomerkletree.BuildMerkleTree(data)

	fmt.Println("root:", hex.EncodeToString(mt.Root()))

    // generate proof
	proof, err := mt.Proof(data[0])
	if err != nil {
		panic(err)
	}

	// verify proof
	if err := gomerkletree.VerifyProof(data[0], proof); err != nil {
		panic("proof failed unexpectedly: " + err.Error())
	}
	fmt.Println("'a' is in the Merkle tree")

	// returns error on bad input
	bad := &TestLeaf{"a*"}
	if err := gomerkletree.VerifyProof(bad, proof); err != nil {
		fmt.Println("tamper detected (as expected):", err)
	} else {
		panic("tamper not detected")
	}
}
```

### Testing
```bash
go test ./...
```

## License
This project is licensed under the [MIT license](LICENSE)
