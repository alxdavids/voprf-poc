package oprf

import (
	"math/big"

	"github.com/alxdavids/oprf-poc/go/oerr"
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
func (sk SecretKey) New(pog gg.PrimeOrderGroup) (SecretKey, oerr.Error) {
	randInt, err := pog.UniformFieldElement()
	if err.Err() != nil {
		return SecretKey{}, err
	}

	Y, err := pog.GeneratorMult(randInt)
	if err.Err() != nil {
		return SecretKey{}, err
	}

	return SecretKey{K: randInt, PubKey: Y}, oerr.Nil()
}

// The Participant interface defines the functions necessary for implenting an OPRF
// protocol
type Participant interface {
	Ciphersuite() gg.Ciphersuite
	Setup(string, gg.PrimeOrderGroup) (Participant, oerr.Error)
	Blind([]byte) (gg.GroupElement, *big.Int, oerr.Error)
	Unblind(gg.GroupElement, *big.Int) (gg.GroupElement, oerr.Error)
	Eval(SecretKey, gg.GroupElement) (gg.GroupElement, oerr.Error)
	Finalize(gg.GroupElement, []byte, []byte) ([]byte, oerr.Error)
}

// Server implements the OPRF interface for processing the server-side
// operations of the OPRF protocol
type Server struct {
	ciph gg.Ciphersuite
	sk   SecretKey
}

// Ciphersuite returns the Ciphersuite object associated with the Server
func (s Server) Ciphersuite() gg.Ciphersuite { return s.ciph }

// SecretKey returns the SecretKey object associated with the Server
func (s Server) SecretKey() SecretKey { return s.sk }

// Setup is run by the server, it generates a SecretKey object based on the
// choice of ciphersuite that is made
func (s Server) Setup(ciphersuite string, pogInit gg.PrimeOrderGroup) (Participant, oerr.Error) {
	ciph, err := gg.Ciphersuite{}.FromString(ciphersuite, pogInit)
	if err.Err() != nil {
		return nil, err
	}

	sk, err := SecretKey{}.New(ciph.POG())
	if err.Err() != nil {
		return nil, err
	}

	s.ciph = ciph
	s.sk = sk
	return s, oerr.Nil()
}

// Eval computes the Server-side evaluation of the (V)OPRF using a secret key
// and a provided group element
//
// TODO: support VOPRF
func (s Server) Eval(sk SecretKey, M gg.GroupElement) (gg.GroupElement, oerr.Error) {
	ciph := s.ciph
	var Z gg.GroupElement
	var err oerr.Error
	if !ciph.Verifiable() {
		Z, err = M.ScalarMult(sk.K)
		if err.Err() != nil {
			return nil, err
		}
	} else {
		return nil, oerr.ErrOPRFCiphersuiteUnsupportedFunction
	}
	return Z, oerr.Nil()
}

// Blind is unimplemented for the server
func (s Server) Blind(x []byte) (gg.GroupElement, *big.Int, oerr.Error) {
	return nil, nil, oerr.ErrOPRFUnimplementedFunctionServer
}

// Unblind is unimplemented for the server
func (s Server) Unblind(Z gg.GroupElement, r *big.Int) (gg.GroupElement, oerr.Error) {
	return nil, oerr.ErrOPRFUnimplementedFunctionServer
}

// Finalize is unimplemented for the server
func (s Server) Finalize(N gg.GroupElement, x, aux []byte) ([]byte, oerr.Error) {
	return nil, oerr.ErrOPRFUnimplementedFunctionServer
}

// Client implements the OPRF interface for processing the client-side
// operations of the OPRF protocol
type Client struct {
	ciph gg.Ciphersuite
	pk   PublicKey
}

// Ciphersuite returns the Ciphersuite object associated with the Client
func (c Client) Ciphersuite() gg.Ciphersuite { return c.ciph }

// PublicKey returns the PublicKey object associated with the Client
func (c Client) PublicKey() PublicKey { return c.pk }

// Setup associates the client with a ciphersuite object
func (c Client) Setup(ciphersuite string, pogInit gg.PrimeOrderGroup) (Participant, oerr.Error) {
	ciph, err := gg.Ciphersuite{}.FromString(ciphersuite, pogInit)
	if err.Err() != nil {
		return nil, err
	}
	c.ciph = ciph
	return c, oerr.Nil()
}

// Blind samples a new random blind value from ZZp and returns P=r*T where T is
// the representation of the input bytes x in the group pog
func (c Client) Blind(x []byte) (gg.GroupElement, *big.Int, oerr.Error) {
	pog := c.ciph.POG()

	// encode bytes to group
	T, err := pog.EncodeToGroup(x)
	if err.Err() != nil {
		return nil, nil, err
	}

	// sample a random blind
	r, err := pog.UniformFieldElement()
	if err.Err() != nil {
		return nil, nil, err
	}

	// compute blinded group element
	P, err := T.ScalarMult(r)
	if err.Err() != nil {
		return nil, nil, err
	}
	return P, r, oerr.Nil()
}

// Unblind returns the unblinded group element N = r^{-1}*Z
//
// TODO: support VOPRF
func (c Client) Unblind(Z gg.GroupElement, r *big.Int) (gg.GroupElement, oerr.Error) {
	ciph := c.ciph
	pog := c.ciph.POG()
	p := pog.Order()

	if ciph.Verifiable() {
		return nil, oerr.ErrOPRFCiphersuiteUnsupportedFunction
	}

	rInv := new(big.Int).ModInverse(r, p)
	N, err := Z.ScalarMult(rInv)
	if err.Err() != nil {
		return nil, err
	}
	return N, oerr.Nil()
}

// Finalize constructs the final client output from the OPRF protocol
func (c Client) Finalize(N gg.GroupElement, x, aux []byte) ([]byte, oerr.Error) {
	ciph := c.ciph
	DST := []byte("oprf_derive_output")

	// derive shared key
	hmacShared := (c.ciph.H2())(ciph.H3, DST)
	bytesN, err := N.Serialize()
	if err.Err() != nil {
		return nil, err
	}
	_, e := hmacShared.Write(x)
	if e != nil {
		return nil, oerr.ErrInternalInstantiation
	}
	_, e = hmacShared.Write(bytesN)
	if e != nil {
		return nil, oerr.ErrInternalInstantiation
	}
	dk := hmacShared.Sum(nil)

	// derive output
	hmacOut := (c.ciph.H2())(ciph.H3, dk)
	_, e = hmacOut.Write(aux)
	if e != nil {
		return nil, oerr.ErrInternalInstantiation
	}
	y := hmacOut.Sum(nil)
	return y, oerr.Nil()
}

// Eval is not implemented for the OPRF client
func (c Client) Eval(sk SecretKey, M gg.GroupElement) (gg.GroupElement, oerr.Error) {
	return nil, oerr.ErrOPRFUnimplementedFunctionClient
}

/**
 * Utility functions
 */

// CastServer casts a Participant directly into a Server type
func CastServer(ptpnt Participant) (Server, oerr.Error) {
	srv, ok := ptpnt.(Server)
	if !ok {
		return Server{}, oerr.ErrOPRFInvalidParticipant
	}
	return srv, oerr.Nil()
}

// CastClient casts a Participant directly into a Server type
func CastClient(ptpnt Participant) (Client, oerr.Error) {
	cli, ok := ptpnt.(Client)
	if !ok {
		return Client{}, oerr.ErrOPRFInvalidParticipant
	}
	return cli, oerr.Nil()
}
