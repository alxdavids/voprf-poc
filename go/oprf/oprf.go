package oprf

import (
	"crypto/rand"
	"errors"
	"math/big"

	gg "github.com/alxdavids/oprf-poc/go/oprf/groups"
)

var (
	// ErrOPRFCiphersuiteUnsupportedFunction indicates that the given OPRF
	// function is not supported for the configuration specified by the
	// ciphersuite
	ErrOPRFCiphersuiteUnsupportedFunction = errors.New("Chosen OPRF function is not yet supported for the chosen ciphersuite")
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

	sk, err := SecretKey{}.New(ciph.POG())
	if err != nil {
		return SecretKey{}, gg.Ciphersuite{}, err
	}

	return sk, ciph, nil
}

// Blind samples a new random blind value from ZZp and returns P=r*T where T is
// the representation of the input bytes x in the group pog
func Blind(ciph gg.Ciphersuite, x []byte) (gg.GroupElement, *big.Int, error) {
	pog := ciph.POG()

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

// Unblind returns the unblinded group element N = r^{-1}*Z
func Unblind(ciph gg.Ciphersuite, Z gg.GroupElement, r *big.Int) (gg.GroupElement, error) {
	pog := ciph.POG()
	p := pog.Order()

	if ciph.Verifiable() {
		return nil, ErrOPRFCiphersuiteUnsupportedFunction
	}

	rInv := new(big.Int).ModInverse(r, p)
	N, err := Z.ScalarMult(pog, rInv)
	if err != nil {
		return nil, err
	}
	return N, nil
}

// Eval computes the Server-side evaluation of the (V)OPRF using a secret key
// and a provided group element
//
// TODO: support VOPRF
func Eval(ciph gg.Ciphersuite, sk SecretKey, M gg.GroupElement) (gg.GroupElement, error) {
	pog := ciph.POG()
	var Z gg.GroupElement
	var err error
	if !ciph.Verifiable() {
		Z, err = M.ScalarMult(pog, sk.K)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, ErrOPRFCiphersuiteUnsupportedFunction
	}
	return Z, nil
}

// Finalize constructs the final client output from the OPRF protocol
func Finalize(ciph gg.Ciphersuite, x []byte, N gg.GroupElement, aux []byte) ([]byte, error) {
	pog := ciph.POG()
	DST := []byte("oprf_derive_output")

	// derive shared key
	hmacShared := (ciph.H2())(ciph.H3, DST)
	NBytes, err := N.Serialize(pog)
	if err != nil {
		return nil, err
	}
	hmacShared.Write(x)
	dk := hmacShared.Sum(NBytes)

	// derive output
	hmacOut := (ciph.H2())(ciph.H3, dk)
	y := hmacOut.Sum(aux)
	return y, nil
}
