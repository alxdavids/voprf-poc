package dleq

import (
	"hash"
	"math/big"

	"github.com/alxdavids/voprf-poc/go/oerr"
	gg "github.com/alxdavids/voprf-poc/go/oprf/groups"
	"github.com/alxdavids/voprf-poc/go/oprf/groups/ecgroup"
	"github.com/alxdavids/voprf-poc/go/oprf/utils"
)

// Proof corresponds to the DLEQ proof object that is used to prove that the
// server has correctly evaluated the random function during VOPRF evaluation
type Proof struct {
	C, S *big.Int
}

// Generate constructs a new Proof object using a VOPRF secret key and the group
// elements that were provided as input
func Generate(pog gg.PrimeOrderGroup, h hash.Hash, k *big.Int, Y, M, Z gg.GroupElement) (Proof, error) {
	t, err := pog.UniformFieldElement()
	if err != nil {
		return Proof{}, err
	}

	return FixedGenerate(pog, h, k, Y, M, Z, t)
}

// FixedGenerate constructs a new Proof object with the random scalar t
// explicitly generated
func FixedGenerate(pog gg.PrimeOrderGroup, h hash.Hash, k *big.Int, Y, M, Z gg.GroupElement, t *big.Int) (Proof, error) {
	// A := tG, B := tM
	A, err := pog.GeneratorMult(t)
	if err != nil {
		return Proof{}, err
	}
	B, err := M.ScalarMult(t)
	if err != nil {
		return Proof{}, err
	}

	// compute hash output c
	c, err := computeHashAsBigInt(h, pog.Generator(), Y, M, Z, A, B)
	if err != nil {
		return Proof{}, err
	}
	// s = t-ck
	ck := new(big.Int).Mul(c, k)
	n := pog.(ecgroup.GroupCurve).Order()
	s := new(big.Int).Sub(t, ck)

	return Proof{C: c.Mod(c, n), S: s.Mod(s, n)}, nil
}

// BatchGenerate generates a batched DLEQ proof evaluated over multiple values
// of the form Z[i] = kM[i], wrt to the public key Y = kG
func BatchGenerate(pog gg.PrimeOrderGroup, h3, h4 hash.Hash, h5 utils.ExtractorExpander, k *big.Int, Y gg.GroupElement, batchM, batchZ []gg.GroupElement) (Proof, error) {
	// compute composite group elements
	M, Z, err := batchComposites(pog, h4, h5, Y, batchM, batchZ)
	if err != nil {
		return Proof{}, err
	}

	// generate DLEQ proof object
	return Generate(pog, h3, k, Y, M, Z)
}

// FixedBatchGenerate generates a batched DLEQ proof with fixed proof generation
func FixedBatchGenerate(pog gg.PrimeOrderGroup, h3, h4 hash.Hash, h5 utils.ExtractorExpander, k *big.Int, Y gg.GroupElement, batchM, batchZ []gg.GroupElement, t *big.Int) (Proof, error) {
	// compute composite group elements
	M, Z, err := batchComposites(pog, h4, h5, Y, batchM, batchZ)
	if err != nil {
		return Proof{}, err
	}

	// generate DLEQ proof object
	return FixedGenerate(pog, h3, k, Y, M, Z, t)
}

// Verify runs the DLEQ proof validation algorithm and returns a bool
// indicating success or failure
func (proof Proof) Verify(pog gg.PrimeOrderGroup, h hash.Hash, Y, M, Z gg.GroupElement) bool {
	// A = sG + cY
	sG, err := pog.GeneratorMult(proof.S)
	if err != nil {
		return false
	}
	cY, err := Y.ScalarMult(proof.C)
	if err != nil {
		return false
	}
	A, err := sG.Add(cY)
	if err != nil {
		return false
	}
	// B = sM + cZ
	sM, err := M.ScalarMult(proof.S)
	if err != nil {
		return false
	}
	cZ, err := Z.ScalarMult(proof.C)
	if err != nil {
		return false
	}
	B, err := sM.Add(cZ)
	if err != nil {
		return false
	}

	// recompute hash output
	c, err := computeHashAsBigInt(h, pog.Generator(), Y, M, Z, A, B)
	if err != nil {
		return false
	}

	// check hash outputs
	if c.Mod(c, pog.Order()).Cmp(proof.C) == 0 {
		return true
	}
	return false
}

// BatchVerify verifies a batched DLEQ proof object over an array of
// GroupElement objects of the form Zi = kMi where Y = kG.
func (proof Proof) BatchVerify(pog gg.PrimeOrderGroup, h3, h4 hash.Hash, h5 utils.ExtractorExpander, Y gg.GroupElement, batchM, batchZ []gg.GroupElement) bool {
	// compute composite group elements
	M, Z, err := batchComposites(pog, h4, h5, Y, batchM, batchZ)
	if err != nil {
		return false
	}

	// Verify standalone DLEQ proof object
	return proof.Verify(pog, h3, Y, M, Z)
}

// Serialize takes the values of the proof object and converts them into bytes
func (proof Proof) Serialize() [][]byte {
	return [][]byte{proof.C.Bytes(), proof.S.Bytes()}
}

// Deserialize takes the provided bytes and converts them into a valid Proof
// object
func (proof Proof) Deserialize(proofBytes [][]byte) Proof {
	return Proof{C: new(big.Int).SetBytes(proofBytes[0]), S: new(big.Int).SetBytes(proofBytes[1])}
}

// computeSeed constructs the initial seed that is used for constructing and
// verifying batched DLEQ proofs
func computeSeed(pog gg.PrimeOrderGroup, h4 hash.Hash, Y gg.GroupElement, batchM, batchZ []gg.GroupElement) ([]byte, error) {
	m := len(batchM)
	if m != len(batchZ) {
		return nil, oerr.ErrDLEQInvalidInput
	}

	// compute seed
	inputs := append(batchM, batchZ...)
	inputs = append([]gg.GroupElement{pog.Generator(), Y}, inputs...)
	seed, err := computeHash(h4, inputs...)
	if err != nil {
		return nil, err
	}
	return seed, nil
}

// computeComposites constructs the composite GroupElement objects that are
// used for generating and verifying a batched DLEQ proof
func computeComposites(pog gg.PrimeOrderGroup, h4 hash.Hash, h5 utils.ExtractorExpander, seed []byte, batchM, batchZ []gg.GroupElement) (gg.GroupElement, gg.GroupElement, error) {
	var M gg.GroupElement
	var Z gg.GroupElement
	ctr := 0
	for i := 0; i < len(batchM); i++ {
		ctrBytes, err := utils.I2osp(ctr, 4)
		if err != nil {
			return nil, nil, err
		}
		ctr++
		hkdfInp := append(ctrBytes, []byte("voprf_batch_dleq")...)

		// sample coefficient and reject if it is too big
		expand := h5.Expander()
		output := expand(func() hash.Hash { h4.Reset(); return h4 }, seed, hkdfInp)
		diBuf := make([]byte, pog.ByteLength())
		output.Read(diBuf)
		di := new(big.Int).SetBytes(diBuf[:pog.ByteLength()])
		if di.Cmp(pog.Order()) > 0 {
			i--
			continue
		}

		// multiply group elements by coefficients
		diMi, err := batchM[i].ScalarMult(di)
		if err != nil {
			return nil, nil, err
		}
		diZi, err := batchZ[i].ScalarMult(di)
		if err != nil {
			return nil, nil, err
		}

		// init M if haven't already done so
		if M == nil {
			M = diMi
			Z = diZi
			continue
		}

		// Add points together
		M, err = M.Add(diMi)
		if err != nil {
			return nil, nil, err
		}
		Z, err = Z.Add(diZi)
		if err != nil {
			return nil, nil, err
		}
	}
	return M, Z, nil
}

func batchComposites(pog gg.PrimeOrderGroup, h4 hash.Hash, h5 utils.ExtractorExpander, Y gg.GroupElement, batchM, batchZ []gg.GroupElement) (gg.GroupElement, gg.GroupElement, error) {
	seed, err := computeSeed(pog, h4, Y, batchM, batchZ)
	if err != nil {
		return nil, nil, err
	}
	return computeComposites(pog, h4, h5, seed, batchM, batchZ)
}

// computeHash serializes the group elements and computes the hash output c
func computeHash(h hash.Hash, eles ...gg.GroupElement) ([]byte, error) {
	serialized, err := getSerializedElements(eles...)
	if err != nil {
		return nil, err
	}
	h.Reset()
	for _, buf := range serialized {
		h.Write(buf)
	}
	return h.Sum(nil), nil
}

// computeHashAsBigInt outputs whatever computeHash outputs (on the same input),
// but with the output cast to big.Int type
func computeHashAsBigInt(h hash.Hash, eles ...gg.GroupElement) (*big.Int, error) {
	cBuf, err := computeHash(h, eles...)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(cBuf), nil
}

// getSerializedElements returns the serializations of multiple GroupElement
// objects
func getSerializedElements(eles ...gg.GroupElement) ([][]byte, error) {
	serialized := make([][]byte, len(eles))
	for i, x := range eles {
		buf, err := x.Serialize()
		if err != nil {
			return nil, err
		}
		serialized[i] = buf
	}
	return serialized, nil
}
