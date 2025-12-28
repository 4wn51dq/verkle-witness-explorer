package tree

import (
	"github.com/ethereum/go-verkle"
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

type (
	Node             verkle.VerkleNode
	ResolverFunction verkle.NodeResolverFn
	proof            verkle.ProofElements
)

type (
	LeafNode struct {
		stem       verkle.Stem   // key = stem(31 bytes) + suffix(1 byte)
		values     [][]byte      // list of byte buffers
		commitment *verkle.Point // C00
		depth      byte
		c1, c2     *verkle.Point
		// {c1: commitment to values[], c2: commitment to extentions/ continuations}
		// c1 is something valid. Then why tf c2 ? There comes another field in this struct:
		proofOfAbsenseStub bool
		// The leafs represent sparse keys; some values may be missing
		// in a stateless client, you want to handle absense or partial presence of keys and future extensions
		// Without having the full state and having small witnesses, this field can control
		// the POA: {c1, c1, (IPA or KZG) opening proofs, path proof, claim}

		/* case A: stem exists but value is missing
		* The prover sends (c1, an opening proof at the suffix saying value claimed = 0)
		* The verifier checks (a valid c1 commitment, valid opening proof, value at suffix is exactly 0)
		* FAQ: opening proof says that taht the value at an index (suffix in this case) is exactly what its told
		*
		* case B: no stem exists at all
		* its not possible to prove that there is no leaf at all. So we need both the commitments (c1, c2)
		* and then we just mark the leaf with the poaStub having {c1: commit to a zero polynomial [p(x)=0],
		* c2: commitment to an empty metadata.
		* Without c2, fake structuring of leaf and broken extension logic would be a risk.
		 */
	}

	InternalNode struct {
		children   []Node
		commitment *verkle.Point
		depth      byte
		cow        map[byte]*verkle.Point
	}
)

/*
* @params these constants are for defining a shallower and wider tree for ethereum.
 */
const (
	KeySize = 32
	// in ethereum 20 bytes addresses are hashed to 32 bytes(256 bit) for stateless execution,
	// storage slots are already 32 bytes and everything in state trie is keccak256()
	// key[0], key[1]... key[32] can be used to navigate or index
	LeafValueSize = 32
	// Account fields and storage slot values are standardized to 32 bytes
	NodeWidth         = 256 // number of slots for each node
	NodeBitWidth byte = 8
	StemSize          = 31
	// it is most important to realise that we only walk 31 bytes deep and leave the last byte
	// as the suffix
)

// find which child to look at in a node, this is the key function to navigate in the tree
func keyIndex(key []byte) verkle.Stem {
	return verkle.KeyToStem(key)
}

func splitKey(key []byte) ([]byte, byte) {
	stem := verkle.KeyToStem(key)
	suffix := key[len(key)-1]
	return stem, suffix
}
