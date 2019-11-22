package oprf

import (
	"crypto"
	"github.com/alxdavids/oprf-poc/go/oprf/groups"
	"math/big"
)

// Ciphersuite corresponds to the OPRF ciphersuite that is chosen
//
// Even though groups == curves, we keep the abstraction to fit with curve
// implementations
type Ciphersuite struct {
	GG  groups.Group
	H_1 crypto.Hash
	H_2 crypto.Hash
	H_3 crypto.Hash
	H_4 crypto.Hash
	H_5 crypto.Hash
}

type PublicKey struct {
	Ciph Ciphersuite
	Y    groups.GroupElement
}

type SecretKey struct {
	K      *big.Int
	PubKey PublicKey
}
