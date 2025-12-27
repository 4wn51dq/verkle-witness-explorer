package tree

import (
	"github.com/ethereum/go-verkle"
	"github.com/ethereum/go-verkle/verkle"
)

// a verkle node exists at every node of the tree, pointing to children, storing values, generate commitments
/*
* @function NodeResolverFn:
* 1. Resolver fetches children from disk / DB.
* 2. Ethereum state is too large to keep fully in memory
* 3. Child nodes live on either disk or (a DB in) network
*
********************************** BUILDING A TREE *********************************
* @params (whats the scalar at leaf?)
* key-> either an account address or storage slot
* value-> can be balance, nonce, storage value, hash
*
* @notice
* The concept of verkle trees is that each Verkle Node has a commitment for it
* The commitment scheme is based on IPA(inner product argument) scheme in ethereum
* The result of committing is a point on the elliptic curve for the scheme:
* {IPA: bandersnatch EC, KZG: BLS12-381 EC}
* however to commit is expensive (polynomial evaluation, cryptographic operations over EC)
* SO the committing result is first cached then the node uses a getter to get the commitment vector
*
* HASHING THE COMMITMENTS: WHY?
*
* The first verkle node commitment (let C00) is vector (or polynomial) defined over
* scalar fields (suppose the values S = [s00, s02, ... s0n], n = 255). This creates a trie
* that is 2 levels long.
* From calculations: a 4 level verlke tree would be enough to store all possible
* ethereum addresses at the highest level. How?
*
* Suppose we have 256 vectors [S0, S1... S255] and each vector with its own commitment
* that gives 256 commitments: hash each commitment to make things simple for commitment scheme
* after hashing we can define a vector: S' =[hash(C00), hash(C01)... hash(C0255)]
* now for S0' we can compute a commitment C10
* how many scalars (or leafs) can we put? 256^2 for a 3 level merkle tree!
*
* To have a 4th level in the verkle tree we would need 255 more commitments at the 3rd level:
* S'' = [hash(C10), hash(C11), hash(C12),..... hash(C1 255)]
* The commitment of the above vector S'' = C20
* now calculate: 1 commitment at 4th level= 256 at 3rd = 256^2 at 2nd = (2^8)^3 leafs
*
* @notice
* Field element Fr for IPA scheme is defined over 255 bits [Fr: r~(2^255)]
* Even the base field Fp is [Fp: p~(2^255)]
*
* Like any nodes there would be internal nodes and leaf nodes. here the internal nodes are commitments hashed.
 */

const NodeWidth uint16 = 256
const StemSize uint8 = 31

type (
	Node             verkle.VerkleNode
	ResolverFunction verkle.NodeResolverFn
)

type SimpleVerkleNode struct {
	stemSize   byte            //
	values     map[byte][]byte // leaf
	children   map[byte][]SimpleVerkleNode
	commitment verkle.Point
}

func createNode(depth byte) *SimpleVerkleNode {
	return &SimpleVerkleNode{
		stemSize: StemSize,
		values:   make(map[byte][]byte),
		children: make(map[byte][]SimpleVerkleNode),
	}
}

// find which child to look at in a node, this is the key function to navigate in the tree
func keyIndex(key []byte) byte {
	return verkle.KeyToStem(key)
}

func (node *SimpleVerkleNode) Insert(key []byte, value []byte, rf ResolverFunction) {

}
