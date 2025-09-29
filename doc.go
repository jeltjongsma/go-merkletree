// A simple Merkle tree implemented in Go.
// Leaves and internal nodes are prepended with 0x00 and 0x01 respectively, and hashed with SHA-256.
// On odd inputs the tree relies on promotion, where the last node is carried up unchanged.
//
// This library was implemented as a learning exercise into binary tree creation, Merkle trees,
// roots and proofs, so it is not hardened for production, and unlike standard implementations
// does not use duplication (which means standard proof verification methods likely won't work).
//
// Building the Merkle tree is O(n) (with n = #leaves; the total number of nodes is ~2n-1).
// Proof size and verification are O(log n).
package gomerkletree
