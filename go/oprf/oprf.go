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
	GG    groups.PrimeOrderGroup
	Hash1 crypto.Hash
	Hash2 crypto.Hash
	Hash3 crypto.Hash
	Hash4 crypto.Hash
	Hash5 crypto.Hash
}

type PublicKey struct {
	Ciph Ciphersuite
	Y    groups.GroupElement
}

type SecretKey struct {
	K      *big.Int
	PubKey PublicKey
}
