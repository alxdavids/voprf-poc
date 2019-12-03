package dleq

import (
	gg "github.com/alxdavids/oprf-poc/go/oprf/groups"
	"math/big"
)

// Proof corresponds to the DLEQ proof object that is used to prove that the
// server has correctly evaluated the random function during VOPRF evaluation
type Proof struct {
	C, S *big.Int
}

// Generate constructs a new Proof object using a VOPRF secret key and the group
// elements that were provided as input
func Generate(k *big.Int, Y, M, Z gg.GroupElement) (Proof, error) {
	return Proof{}, nil
}
