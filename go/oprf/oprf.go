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
	// ErrUnimplementedFunctionClient indicates that the function that has been
	// called is not implemented for the client in the OPRF protocol
	ErrUnimplementedFunctionClient = errors.New("Function is unimplemented for the OPRF client")
	// ErrUnimplementedFunctionServer indicates that the function that has been
	// called is not implemented for the server in the OPRF protocol
	ErrUnimplementedFunctionServer = errors.New("Function is unimplemented for the OPRF server")
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

// The OPRF interface defines the functions necessary for implenting an OPRF
// protocol
type OPRF interface {
	Setup(string, gg.PrimeOrderGroup) (SecretKey, gg.Ciphersuite, error)
	Blind(gg.Ciphersuite, []byte) (gg.GroupElement, *big.Int, error)
	Unblind(gg.Ciphersuite, gg.GroupElement, *big.Int) (gg.GroupElement, error)
	Eval(gg.Ciphersuite, SecretKey, gg.GroupElement) (gg.GroupElement, error)
	Finalize(gg.Ciphersuite, gg.GroupElement, []byte, []byte) ([]byte, error)
}

// Server implements the OPRF interface for processing the server-side
// operations of the OPRF protocol
type Server struct {
	ciph gg.Ciphersuite
	sk   SecretKey
}

// Setup is run by the server, it generates a SecretKey object based on the
// choice of ciphersuite that is made
func (s Server) Setup(ciphersuite string, pogInit gg.PrimeOrderGroup) (SecretKey, gg.Ciphersuite, error) {
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

// Eval computes the Server-side evaluation of the (V)OPRF using a secret key
// and a provided group element
//
// TODO: support VOPRF
func (s Server) Eval(sk SecretKey, M gg.GroupElement) (gg.GroupElement, error) {
	ciph := s.ciph
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

// Blind is unimplemented for the server
func (s Server) Blind(x []byte) (gg.GroupElement, *big.Int, error) {
	return nil, nil, ErrUnimplementedFunctionServer
}

// Unblind is unimplemented for the server
func (s Server) Unblind(Z gg.GroupElement, r *big.Int) (gg.GroupElement, error) {
	return nil, ErrUnimplementedFunctionServer
}

// Finalize is unimplemented for the server
func (s Server) Finalize(N gg.GroupElement, x, aux []byte) ([]byte, error) {
	return nil, ErrUnimplementedFunctionServer
}

// Client implements the OPRF interface for processing the client-side
// operations of the OPRF protocol
type Client struct {
	ciph gg.Ciphersuite
	pk   PublicKey
}

// Blind samples a new random blind value from ZZp and returns P=r*T where T is
// the representation of the input bytes x in the group pog
func (c Client) Blind(x []byte) (gg.GroupElement, *big.Int, error) {
	pog := c.ciph.POG()

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
//
// TODO: support VOPRF
func (c Client) Unblind(Z gg.GroupElement, r *big.Int) (gg.GroupElement, error) {
	ciph := c.ciph
	pog := c.ciph.POG()
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

// Finalize constructs the final client output from the OPRF protocol
func (c Client) Finalize(N gg.GroupElement, x, aux []byte) ([]byte, error) {
	ciph := c.ciph
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

// Setup is not implemented for the OPRF client
func (c Client) Setup(ciphersuite string, pogInit gg.PrimeOrderGroup) (SecretKey, gg.Ciphersuite, error) {
	return SecretKey{}, gg.Ciphersuite{}, ErrUnimplementedFunctionClient
}

// Eval is not implemented for the OPRF client
func (c Client) Eval(sk SecretKey, M gg.GroupElement) (gg.GroupElement, error) {
	return nil, ErrUnimplementedFunctionClient
}
