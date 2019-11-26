package oprf

import (
	"crypto/rand"
	"math/big"

	gg "github.com/alxdavids/oprf-poc/go/oprf/groups"
)

// PublicKey represents a commitment to a given secret key that is made public
// during the OPRF protocol
type PublicKey struct {
	Ciph gg.Ciphersuite
	Y    gg.GroupElement
}

// SecretKey represents a scalar value controlled by the server in an OPRF
// protocol
type SecretKey struct {
	K      *big.Int
	PubKey PublicKey
}

func (sk SecretKey) New(pog gg.PrimeOrderGroup) (SecretKey, error) {
	randInt, err := rand.Int(rand.Reader, pog.Order())
	if err != nil {
		return SecretKey{}, err
	}

	Y, err := pog.GeneratorMult(randInt)
	if err != nil {
		return SecretKey{}, err
	}

	return SecretKey{K: randInt, PubKey: {Y: Y}}, nil
}

func OprfSetup(pog gg.PrimeOrderGroup) (SecretKey, error) {

	return SecretKey{K: randInt}, nil
}
