package dleq

import (
	"hash"
	"math/big"

	gg "github.com/alxdavids/oprf-poc/go/oprf/groups"
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
	c, err := computeDLEQHash(h, pog.Generator(), Y, M, Z, A, B)
	if err != nil {
		return Proof{}, err
	}
	// r = t-ck
	s := new(big.Int).Sub(t, new(big.Int).Mul(c, k))

	return Proof{C: c, S: s}, nil
}

// Validate runs the DLEQ proof validation algorithm and returns a bool
// indicating success or failure
func (proof Proof) Validate(pog gg.PrimeOrderGroup, h hash.Hash, Y, M, Z gg.GroupElement) bool {
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
	c, err := computeDLEQHash(h, pog.Generator(), Y, M, Z, A, B)
	if err != nil {
		return false
	}

	// check hash outputs
	if c.Cmp(proof.C) == 0 {
		return true
	}
	return false
}

// computeDLEQHash serializes the group elements and computes the hash output c
// as a big int
func computeDLEQHash(h hash.Hash, eles ...gg.GroupElement) (*big.Int, error) {
	serialized, err := getSerializedElements(eles...)
	if err != nil {
		return nil, err
	}
	h.Reset()
	for _, buf := range serialized {
		h.Write(buf)
	}
	cBuf := h.Sum(nil)
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
