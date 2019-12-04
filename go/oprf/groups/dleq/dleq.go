package dleq

import (
	"hash"
	"math/big"

	"github.com/alxdavids/oprf-poc/go/oerr"
	gg "github.com/alxdavids/oprf-poc/go/oprf/groups"
	"github.com/alxdavids/oprf-poc/go/oprf/groups/ecgroup"
	"github.com/alxdavids/oprf-poc/go/oprf/utils"
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
func BatchGenerate(pog gg.PrimeOrderGroup, h4 hash.Hash, h5 utils.ExtractorExpander, k *big.Int, Y gg.GroupElement, batchM, batchZ []gg.GroupElement) (Proof, error) {
	m := len(batchM)
	if m != len(batchZ) {
		return Proof{}, oerr.ErrInternalInstantiation
	}

	// compute seed
	inputs := append(batchM, batchZ...)
	inputs = append([]gg.GroupElement{pog.Generator(), Y}, inputs...)
	seed, err := computeHash(h4, inputs...)
	if err != nil {
		return Proof{}, err
	}

	// compute coefficients
	coeffs := make([]*big.Int, m)
	for i := 0; i < m; i++ {
		extract := h5.Extractor()
		iBuf, err := utils.I2osp(i, 4)
		if err != nil {
			return Proof{}, nil
		}
		hkdfInp := append(iBuf, []byte("voprf_batch_dleq")...)
		di := extract(func() hash.Hash { h4.Reset(); return h4 }, seed, hkdfInp)
		coeffs[i] = new(big.Int).SetBytes(di)
	}
	return Proof{}, nil
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

// computeHashAsBigInt serializes the group elements and computes the hash output c
// as a big int
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
