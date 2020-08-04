package oprf

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"

	"github.com/alxdavids/voprf-poc/go/oerr"
	gg "github.com/alxdavids/voprf-poc/go/oprf/groups"
	"github.com/alxdavids/voprf-poc/go/oprf/groups/dleq"
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
	randInt, err := pog.RandomScalar()
	if err != nil {
		return SecretKey{}, err
	}

	Y, err := pog.GeneratorMult(randInt)
	if err != nil {
		return SecretKey{}, err
	}

	return SecretKey{K: randInt, PubKey: Y}, nil
}

// A Token is an object created by a client when constructing a
// (V)OPRF protocol input.  It is stored so that it can be used after
// receiving the server response.
type Token struct {
	Data  []byte // original input to Blind
	Blind *big.Int
}

// Evaluation corresponds to the output object of a (V)OPRF evaluation.
// In the case of an OPRF, the object only consists of the output group element. For a
// VOPRF, it also consists of a proof object
type Evaluation struct {
	Element gg.GroupElement
	Proof   dleq.Proof
}

// BatchedEvaluation corresponds to the output object of a batched (V)OPRF evaluation.
// In the case of an OPRF, the object only consists of the output group elements. For a
// VOPRF, it also consists of a proof object
type BatchedEvaluation struct {
	Elements []gg.GroupElement
	Proof    dleq.Proof
}

// ToJSON returns a formatted string containing the contents of the Evaluation
// object
func (ev BatchedEvaluation) ToJSON(verifiable bool) ([]byte, error) {
	eleSerialized := make([]string, len(ev.Elements))
	for i, v := range ev.Elements {
		s, err := v.Serialize()
		if err != nil {
			return nil, err
		}
		eleSerialized[i] = hex.EncodeToString(s)
	}
	serialization := make(map[string][]string)
	serialization["elements"] = eleSerialized
	if verifiable {
		proofSerialized := make([]string, 2)
		for i, val := range ev.Proof.Serialize() {
			proofSerialized[i] = hex.EncodeToString(val)
		}
		serialization["proof"] = proofSerialized
	}
	return json.MarshalIndent(serialization, "", "  ")
}

// The Participant interface defines the functions necessary for implementing an OPRF
// protocol
type Participant interface {
	Ciphersuite() gg.Ciphersuite
	Setup(string, gg.PrimeOrderGroup) (Participant, error)
	Blind([]byte) (*Token, gg.GroupElement, error)
	Unblind(Evaluation, *Token, gg.GroupElement) (gg.GroupElement, error)
	BatchUnblind(BatchedEvaluation, []*Token, []gg.GroupElement) ([]gg.GroupElement, error)
	Evaluate(gg.GroupElement) (Evaluation, error)
	BatchEvaluate([]gg.GroupElement) (BatchedEvaluation, error)
	Finalize(*Token, gg.GroupElement, []byte) ([]byte, error)
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

// SetSecretKey returns the SecretKey object associated with the Server
func (s Server) SetSecretKey(sk SecretKey) Server { s.sk = sk; return s }

// Setup is run by the server, it generates a SecretKey object based on the
// choice of ciphersuite that is made
func (s Server) Setup(ciphersuite string, pogInit gg.PrimeOrderGroup) (Participant, error) {
	ciph, err := gg.Ciphersuite{}.FromString(ciphersuite, pogInit)
	if err != nil {
		return nil, err
	}

	sk, err := SecretKey{}.New(ciph.POG())
	if err != nil {
		return nil, err
	}

	s.ciph = ciph
	s.sk = sk
	return s, nil
}

// BatchEvaluate computes the Server-side evaluation of the (V)OPRF using a secret key
// and a provided group element
func (s Server) Evaluate(M gg.GroupElement) (Evaluation, error) {
	if !s.Ciphersuite().Verifiable() {
		return s.oprfEval(M)
	}
	return s.voprfEval(M)
}

// BatchEvaluate computes the Server-side evaluation of the batched (V)OPRF using
// a secret key and provided group elements
func (s Server) BatchEvaluate(batchM []gg.GroupElement) (BatchedEvaluation, error) {
	if !s.Ciphersuite().Verifiable() {
		return s.oprfBatchEval(batchM)
	}
	return s.voprfBatchEval(batchM)
}

// FixedBatchEval computes the Server-side evaluation of the (V)OPRF with fixed DLEQ
// values (for testing)
func (s Server) FixedEval(M gg.GroupElement, tDleq string) (Evaluation, error) {
	if !s.Ciphersuite().Verifiable() {
		return s.oprfEval(M)
	}
	return s.voprfFixedEval(M, tDleq)
}

// FixedBatchEval computes the Server-side evaluation of the (V)OPRF with fixed DLEQ
// values (for testing)
func (s Server) FixedBatchEval(batchM []gg.GroupElement, tDleq string) (BatchedEvaluation, error) {
	if !s.Ciphersuite().Verifiable() {
		return s.oprfBatchEval(batchM)
	}
	return s.voprfFixedBatchEval(batchM, tDleq)
}

func (s Server) oprfEval(M gg.GroupElement) (Evaluation, error) {
	Z, err := M.ScalarMult(s.sk.K)
	if err != nil {
		return Evaluation{}, err
	}
	return Evaluation{Element: Z}, nil
}

// oprfEval evaluates OPRF_Eval as specified in draft-irtf-cfrg-voprf-02
func (s Server) oprfBatchEval(batchM []gg.GroupElement) (BatchedEvaluation, error) {
	batchZ := make([]gg.GroupElement, len(batchM))
	for i, M := range batchM {
		Z, err := M.ScalarMult(s.sk.K)
		if err != nil {
			return BatchedEvaluation{}, err
		}
		batchZ[i] = Z
	}
	return BatchedEvaluation{Elements: batchZ}, nil
}

// voprfEval evaluates VOPRF_Eval as specified in draft-irtf-cfrg-voprf-02
func (s Server) voprfEval(M gg.GroupElement) (Evaluation, error) {
	eval, err := s.oprfEval(M)
	if err != nil {
		return Evaluation{}, err
	}
	Z := eval.Element

	ciph := s.Ciphersuite()
	sk := s.SecretKey()

	proof, err := dleq.Generate(ciph.POG(), ciph.H2(), ciph.H3(), sk.K, sk.PubKey, M, Z)
	if err != nil {
		return Evaluation{}, err
	}

	return Evaluation{Element: Z, Proof: proof}, nil
}

// voprfBatchEval evaluates VOPRF_Eval as specified in draft-irtf-cfrg-voprf-02
func (s Server) voprfBatchEval(batchM []gg.GroupElement) (BatchedEvaluation, error) {
	eval, err := s.oprfBatchEval(batchM)
	if err != nil {
		return BatchedEvaluation{}, err
	}
	batchZ := eval.Elements

	ciph := s.Ciphersuite()
	sk := s.SecretKey()
	var proof dleq.Proof
	if len(batchM) == 1 {
		proof, err = dleq.Generate(ciph.POG(), ciph.H2(), ciph.H3(), sk.K, sk.PubKey, batchM[0], batchZ[0])
	} else {
		proof, err = dleq.BatchGenerate(ciph.POG(), ciph.H2(), ciph.H3(), sk.K, sk.PubKey, batchM, batchZ)
	}
	if err != nil {
		return BatchedEvaluation{}, err
	}

	return BatchedEvaluation{Elements: batchZ, Proof: proof}, nil
}

// voprfFixedEval evaluates VOPRF_Eval with a fixed DLEQ parameter
func (s Server) voprfFixedEval(M gg.GroupElement, tDleq string) (Evaluation, error) {
	eval, err := s.oprfEval(M)
	if err != nil {
		return Evaluation{}, err
	}

	Z := eval.Element
	ciph := s.Ciphersuite()
	sk := s.SecretKey()
	t, ok := new(big.Int).SetString(tDleq, 16)
	if !ok {
		panic("Bad hex value specified for fixed DLEQ value")
	}

	proof, err := dleq.FixedGenerate(ciph.POG(), ciph.H2(), ciph.H3(), sk.K, sk.PubKey, M, Z, t)
	if err != nil {
		return Evaluation{}, err
	}

	return Evaluation{Element: Z, Proof: proof}, nil
}

// voprfFixedEval evaluates VOPRF_Eval with a fixed DLEQ parameter
func (s Server) voprfFixedBatchEval(batchM []gg.GroupElement, tDleq string) (BatchedEvaluation, error) {
	eval, err := s.oprfBatchEval(batchM)
	if err != nil {
		return BatchedEvaluation{}, err
	}
	batchZ := eval.Elements

	ciph := s.Ciphersuite()
	sk := s.SecretKey()
	t, ok := new(big.Int).SetString(tDleq, 16)
	if !ok {
		panic("Bad hex value specified for fixed DLEQ value")
	}
	var proof dleq.Proof
	if len(batchM) == 1 {
		proof, err = dleq.FixedGenerate(ciph.POG(), ciph.H2(), ciph.H3(), sk.K, sk.PubKey, batchM[0], batchZ[0], t)
	} else {
		proof, err = dleq.FixedBatchGenerate(ciph.POG(), ciph.H2(), ciph.H3(), sk.K, sk.PubKey, batchM, batchZ, t)
	}
	if err != nil {
		return BatchedEvaluation{}, err
	}

	return BatchedEvaluation{Elements: batchZ, Proof: proof}, nil
}

// Blind is unimplemented for the server
func (s Server) Blind(x []byte) (*Token, gg.GroupElement, error) {
	return nil, nil, oerr.ErrOPRFUnimplementedFunctionServer
}

// Unblind is unimplemented for the server
func (s Server) Unblind(ev Evaluation, token *Token, blindedToken gg.GroupElement) (gg.GroupElement, error) {
	return nil, oerr.ErrOPRFUnimplementedFunctionServer
}

// BatchUnblind is unimplemented for the server
func (s Server) BatchUnblind(ev BatchedEvaluation, tokens []*Token, blindedTokens []gg.GroupElement) ([]gg.GroupElement, error) {
	return nil, oerr.ErrOPRFUnimplementedFunctionServer
}

// Finalize is unimplemented for the server
func (s Server) Finalize(token *Token, unblindedToken gg.GroupElement, info []byte) ([]byte, error) {
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

// SetPublicKey sets a server public key for the client. All VOPRF messages will
// be verified with respect to this PublicKey
func (c Client) SetPublicKey(pk PublicKey) Client { c.pk = pk; return c }

// Setup associates the client with a ciphersuite object
func (c Client) Setup(ciphersuite string, pogInit gg.PrimeOrderGroup) (Participant, error) {
	ciph, err := gg.Ciphersuite{}.FromString(ciphersuite, pogInit)
	if err != nil {
		return nil, err
	}
	c.ciph = ciph
	return c, nil
}

// Blind samples a new random blind value from ZZp and returns P=r*T where T is
// the representation of the input bytes x in the group pog.
func (c Client) Blind(x []byte) (*Token, gg.GroupElement, error) {
	P, _, r, err := c.BlindInternal(x)
	return &Token{Data: x, Blind: r}, P, err
}

// BlindInternal samples a new random blind value from ZZp and returns P=r*T and T, where T
// is the representation of the input bytes x in the group pog.
func (c Client) BlindInternal(x []byte) (gg.GroupElement, gg.GroupElement, *big.Int, error) {
	pog := c.ciph.POG()

	// sample a random blind
	r, err := pog.RandomScalar()
	if err != nil {
		return nil, nil, nil, err
	}

	// compute blinded group element
	P, T, err := c.BlindFixed(x, r)
	if err != nil {
		return nil, nil, nil, err
	}

	return P, T, r, nil
}

// BlindFixed performs the actual blinding, with the blinding value specified as
// a fixed parameter.
func (c Client) BlindFixed(x []byte, blind *big.Int) (gg.GroupElement, gg.GroupElement, error) {
	pog := c.Ciphersuite().POG()

	// encode bytes to group
	T, err := pog.HashToGroup(x)
	if err != nil {
		return nil, nil, err
	}

	// compute blinded group element
	P, err := T.ScalarMult(blind)
	if err != nil {
		return nil, nil, err
	}

	return P, T, nil
}

// BatchUnblind returns the unblinded group element N = r^{-1}*Z if the DLEQ proof
// check passes (proof check is omitted if the ciphersuite is not verifiable)
func (c Client) Unblind(ev Evaluation, token *Token, blindedToken gg.GroupElement) (gg.GroupElement, error) {
	if !c.ciph.Verifiable() {
		return c.oprfUnblind(ev, token.Blind)
	}
	return c.voprfUnblind(ev, blindedToken, token.Blind)
}

// BatchUnblind returns the unblinded group elements N = r^{-1}*Z if the DLEQ proof
// check passes (proof check is omitted if the ciphersuite is not verifiable)
func (c Client) BatchUnblind(ev BatchedEvaluation, tokens []*Token, blindedTokens []gg.GroupElement) ([]gg.GroupElement, error) {
	// check that the lengths of the expected evaluations is the same as the
	// number generated
	if len(ev.Elements) != len(blindedTokens) {
		return nil, oerr.ErrClientInconsistentResponse
	}
	if !c.ciph.Verifiable() {
		return c.oprfBatchUnblind(ev, tokens)
	}
	return c.voprfBatchUnblind(ev, tokens, blindedTokens)
}

func (c Client) voprfUnblind(ev Evaluation, orig gg.GroupElement, blind *big.Int) (gg.GroupElement, error) {
	ciph := c.ciph
	proof := ev.Proof
	// check DLEQ proof
	if b := proof.Verify(ciph.POG(), ciph.H2(), ciph.H3(), c.PublicKey(), orig, ev.Element); !b {
		return nil, oerr.ErrClientVerification
	}
	return c.oprfUnblind(ev, blind)
}

// voprfBatchUnblind runs VOPRF_Unblind as specified in draft-irtf-cfrg-voprf-02
func (c Client) voprfBatchUnblind(evs BatchedEvaluation, tokens []*Token, blindedTokens []gg.GroupElement) ([]gg.GroupElement, error) {
	ciph := c.ciph
	eles := evs.Elements
	proof := evs.Proof
	// check DLEQ proof
	b := false
	if len(eles) == 1 {
		b = proof.Verify(ciph.POG(), ciph.H2(), ciph.H3(), c.PublicKey(), blindedTokens[0], eles[0])
	} else {
		b = proof.BatchVerify(ciph.POG(), ciph.H2(), ciph.H3(), c.PublicKey(), blindedTokens, eles)
	}
	if !b {
		return nil, oerr.ErrClientVerification
	}
	return c.oprfBatchUnblind(evs, tokens)
}

func (c Client) oprfUnblind(ev Evaluation, blind *big.Int) (gg.GroupElement, error) {
	pog := c.ciph.POG()
	N := pog.Order()
	blindInverse := new(big.Int).ModInverse(blind, N)
	unblindedToken, err := ev.Element.ScalarMult(blindInverse)
	if err != nil {
		return nil, err
	}
	return unblindedToken, nil
}

// oprfBatchUnblind runs OPRF_Unblind as specified in draft-irtf-cfrg-voprf-02
func (c Client) oprfBatchUnblind(evs BatchedEvaluation, tokens []*Token) ([]gg.GroupElement, error) {
	pog := c.ciph.POG()
	N := pog.Order()
	eles := evs.Elements
	unblindedTokens := make([]gg.GroupElement, len(eles))
	for i, token := range tokens {
		ele := eles[i]
		blindInverse := new(big.Int).ModInverse(token.Blind, N)
		unblindedToken, err := ele.ScalarMult(blindInverse)
		if err != nil {
			return nil, err
		}
		unblindedTokens[i] = unblindedToken
	}
	return unblindedTokens, nil
}

func (c Client) CreateFinalizeInput(token *Token, unblindedToken gg.GroupElement, info []byte) ([]byte, error) {
	DST := []byte("RFCXXXX-Finalize")

	buffer := make([]byte, 0)
	lengthBuffer := make([]byte, 2)

	binary.BigEndian.PutUint16(lengthBuffer, uint16(len(DST)))
	buffer = append(buffer, lengthBuffer...)
	buffer = append(buffer, DST...)

	binary.BigEndian.PutUint16(lengthBuffer, uint16(len(token.Data)))
	buffer = append(buffer, lengthBuffer...)
	buffer = append(buffer, token.Data...)

	bytesN, err := unblindedToken.Serialize()
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(lengthBuffer, uint16(len(bytesN)))
	buffer = append(buffer, lengthBuffer...)
	buffer = append(buffer, bytesN...)

	binary.BigEndian.PutUint16(lengthBuffer, uint16(len(info)))
	buffer = append(buffer, lengthBuffer...)
	buffer = append(buffer, info...)

	return buffer, nil
}

// Finalize constructs the final client output from the OPRF protocol
func (c Client) Finalize(token *Token, unblindedToken gg.GroupElement, info []byte) ([]byte, error) {
	ciph := c.ciph

	hash := ciph.H1()
	input, err := c.CreateFinalizeInput(token, unblindedToken, info)
	if err != nil {
		return nil, err
	}
	_, err = hash.Write(input)
	if err != nil {
		return nil, err
	}
	y := hash.Sum(nil)

	return y, nil
}

// Evaluate is not implemented for the OPRF client
func (c Client) Evaluate(M gg.GroupElement) (Evaluation, error) {
	return Evaluation{}, oerr.ErrOPRFUnimplementedFunctionClient
}

// BatchEvaluate is not implemented for the OPRF client
func (c Client) BatchEvaluate(M []gg.GroupElement) (BatchedEvaluation, error) {
	return BatchedEvaluation{}, oerr.ErrOPRFUnimplementedFunctionClient
}

/**
 * Utility functions
 */

// CastServer casts a Participant directly into a Server type
func CastServer(ptpnt Participant) (Server, error) {
	srv, ok := ptpnt.(Server)
	if !ok {
		return Server{}, oerr.ErrOPRFInvalidParticipant
	}
	return srv, nil
}

// CastClient casts a Participant directly into a Server type
func CastClient(ptpnt Participant) (Client, error) {
	cli, ok := ptpnt.(Client)
	if !ok {
		return Client{}, oerr.ErrOPRFInvalidParticipant
	}
	return cli, nil
}
