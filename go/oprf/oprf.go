package oprf

import (
	"crypto/rand"
	"math/big"

	gg "github.com/alxdavids/oprf-poc/go/oprf/groups"
)

// PublicKey represents a commitment to a given secret key that is made public
// during the OPRF protocol
type PublicKey gg.GroupElement

// SecretKey represents a scalar value controlled by the server in an OPRF
// protocol
type SecretKey struct {
	K      *big.Int
	PubKey PublicKey
}

// New returns a SecretKey object corresponding to the PrimeOrderGroup that was
// passed into it
func (sk SecretKey) New(pog gg.PrimeOrderGroup) (SecretKey, error) {
	randInt, err := rand.Int(rand.Reader, pog.Order())
	if err != nil {
		return SecretKey{}, err
	}

	Y, err := pog.GeneratorMult(randInt)
	if err != nil {
		return SecretKey{}, err
	}

	return SecretKey{K: randInt, PubKey: Y}, nil
}

// Setup is run by the server, it generates a SecretKey object based on the
// choice of ciphersuite that is made
func Setup(ciphersuite string, pogInit gg.PrimeOrderGroup) (SecretKey, gg.Ciphersuite, error) {
	ciph, err := gg.Ciphersuite{}.FromString(ciphersuite, pogInit)
	if err != nil {
		return SecretKey{}, gg.Ciphersuite{}, err
	}

	sk, err := SecretKey{}.New(ciph.Pog)
	if err != nil {
		return SecretKey{}, gg.Ciphersuite{}, err
	}

	return sk, ciph, nil
}

// Blind samples a new random blind value from ZZp and returns P=r*T where T is
// the representation of the input bytes x in the group pog
func Blind(ciph gg.Ciphersuite, x []byte) (gg.GroupElement, *big.Int, error) {
	pog := ciph.Pog

	// encode bytes to group
	T, err := pog.EncodeToGroup(x)
	if err != nil {
		return nil, nil, err
	}

	// sample a random blind
	r, err := pog.UniformFieldElement()
	if err != nil {
		return nil, nil, err
	}

	// compute blinded group element
	P, err := T.ScalarMult(pog, r)
	if err != nil {
		return nil, nil, err
	}
	return P, r, nil
}
