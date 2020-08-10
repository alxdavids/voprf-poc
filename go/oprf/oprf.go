package oprf

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"

	"github.com/alxdavids/voprf-poc/go/oerr"
	gg "github.com/alxdavids/voprf-poc/go/oprf/groups"
	"github.com/alxdavids/voprf-poc/go/oprf/utils"
)

const (
	modeBase       int = 0
	modeVerifiable     = 1
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

type Proof struct {
	pog  gg.PrimeOrderGroup
	C, S *big.Int
}

// Serialize takes the values of the proof object and converts them into bytes
func (proof Proof) Serialize() [][]byte {
	return [][]byte{proof.pog.ScalarToBytes(proof.C), proof.pog.ScalarToBytes(proof.S)}
}

// Deserialize takes the provided bytes and converts them into a valid Proof
// object
func (proof Proof) Deserialize(pog gg.PrimeOrderGroup, proofBytes [][]byte) Proof {
	return Proof{pog: pog, C: new(big.Int).SetBytes(proofBytes[0]), S: new(big.Int).SetBytes(proofBytes[1])}
}

// Evaluation corresponds to the output object of a (V)OPRF evaluation.
// In the case of an OPRF, the object only consists of the output group element. For a
// VOPRF, it also consists of a proof object
type Evaluation struct {
	Element gg.GroupElement
	Proof   Proof
}

// BatchedEvaluation corresponds to the output object of a batched (V)OPRF evaluation.
// In the case of an OPRF, the object only consists of the output group elements. For a
// VOPRF, it also consists of a proof object
type BatchedEvaluation struct {
	Elements []gg.GroupElement
	Proof    Proof
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
	Setup(int, gg.PrimeOrderGroup) (Participant, error)
	SetupVerifiable(int, gg.PrimeOrderGroup) (Participant, error)
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
	contextString []byte
	ciph          gg.Ciphersuite
	sk            SecretKey
	verifiable    bool
}

// Ciphersuite returns the Ciphersuite object associated with the Server
func (s Server) Ciphersuite() gg.Ciphersuite { return s.ciph }

// SecretKey returns the SecretKey object associated with the Server
func (s Server) SecretKey() SecretKey { return s.sk }

// SetSecretKey returns the SecretKey object associated with the Server
func (s Server) SetSecretKey(sk SecretKey) Server { s.sk = sk; return s }

// Setup is run by the server, it generates a SecretKey object based on the
// choice of ciphersuite that is made
func (s Server) Setup(ciphersuiteID int, pogInit gg.PrimeOrderGroup) (Participant, error) {
	s.verifiable = false
	return s.setup(ciphersuiteID, pogInit, modeBase)
}

func (s Server) SetupVerifiable(ciphersuiteID int, pogInit gg.PrimeOrderGroup) (Participant, error) {
	s.verifiable = true
	return s.setup(ciphersuiteID, pogInit, modeVerifiable)
}

func (s Server) setup(ciphersuiteID int, pogInit gg.PrimeOrderGroup, mode int) (Participant, error) {
	ciph, err := gg.Ciphersuite{}.FromID(ciphersuiteID, pogInit)
	if err != nil {
		return nil, err
	}

	sk, err := SecretKey{}.New(ciph.POG())
	if err != nil {
		return nil, err
	}

	s.ciph = ciph
	s.sk = sk

	modeString, err := utils.I2osp(mode, 1)
	if err != nil {
		return nil, err
	}

	idString, err := utils.I2osp(int(ciph.ID()), 2)
	if err != nil {
		return nil, err
	}

	s.contextString = append(modeString, idString...)

	return s, nil
}

// Evaluate computes the Server-side evaluation of the (V)OPRF using a secret key
// and a provided group element
func (s Server) Evaluate(blindToken gg.GroupElement) (Evaluation, error) {
	if !s.Verifiable() {
		return s.oprfEval(blindToken)
	}
	return s.voprfEval(blindToken)
}

// BatchEvaluate computes the Server-side evaluation of the batched (V)OPRF using
// a secret key and provided group elements
func (s Server) BatchEvaluate(blindTokens []gg.GroupElement) (BatchedEvaluation, error) {
	if !s.Verifiable() {
		return s.oprfBatchEval(blindTokens)
	}
	return s.voprfBatchEval(blindTokens)
}

// FixedEval computes the Server-side evaluation of the (V)OPRF with fixed DLEQ
// values (for testing)
func (s Server) FixedEval(blindToken gg.GroupElement, tDleq string) (Evaluation, error) {
	if !s.Verifiable() {
		return s.oprfEval(blindToken)
	}
	return s.voprfFixedEval(blindToken, tDleq)
}

// FixedBatchEval computes the Server-side evaluation of the (V)OPRF with fixed DLEQ
// values (for testing)
func (s Server) FixedBatchEval(blindTokens []gg.GroupElement, tDleq string) (BatchedEvaluation, error) {
	if !s.Verifiable() {
		return s.oprfBatchEval(blindTokens)
	}
	return s.voprfFixedBatchEval(blindTokens, tDleq)
}

func (s Server) oprfEval(blindToken gg.GroupElement) (Evaluation, error) {
	elem, err := blindToken.ScalarMult(s.sk.K)
	if err != nil {
		return Evaluation{}, err
	}
	return Evaluation{Element: elem}, nil
}

// oprfEval evaluates OPRF_Eval as specified in draft-irtf-cfrg-voprf-02
func (s Server) oprfBatchEval(blindTokens []gg.GroupElement) (BatchedEvaluation, error) {
	elems := make([]gg.GroupElement, len(blindTokens))
	for i, blindToken := range blindTokens {
		elem, err := blindToken.ScalarMult(s.sk.K)
		if err != nil {
			return BatchedEvaluation{}, err
		}
		elems[i] = elem
	}
	return BatchedEvaluation{Elements: elems}, nil
}

// voprfEval evaluates VOPRF_Eval as specified in draft-irtf-cfrg-voprf-02
func (s Server) voprfEval(blindToken gg.GroupElement) (Evaluation, error) {
	eval, err := s.oprfEval(blindToken)
	if err != nil {
		return Evaluation{}, err
	}

	proof, err := s.GenerateProof(blindToken, eval.Element)
	if err != nil {
		return Evaluation{}, err
	}

	eval.Proof = proof

	return eval, nil
}

// voprfBatchEval evaluates VOPRF_Eval as specified in draft-irtf-cfrg-voprf-02
func (s Server) voprfBatchEval(blindTokens []gg.GroupElement) (BatchedEvaluation, error) {
	eval, err := s.oprfBatchEval(blindTokens)
	if err != nil {
		return BatchedEvaluation{}, err
	}
	elems := eval.Elements

	var proof Proof
	if len(blindTokens) == 1 {
		proof, err = s.GenerateProof(blindTokens[0], elems[0])
	} else {
		proof, err = s.BatchGenerateProof(blindTokens, elems)
	}
	if err != nil {
		return BatchedEvaluation{}, err
	}

	return BatchedEvaluation{Elements: elems, Proof: proof}, nil
}

// voprfFixedEval evaluates VOPRF_Eval with a fixed DLEQ parameter
func (s Server) voprfFixedEval(blindToken gg.GroupElement, tDleq string) (Evaluation, error) {
	eval, err := s.oprfEval(blindToken)
	if err != nil {
		return Evaluation{}, err
	}

	t, ok := new(big.Int).SetString(tDleq, 16)
	if !ok {
		panic("Bad hex value specified for fixed DLEQ value")
	}

	proof, err := s.FixedGenerateProof(blindToken, eval.Element, t)
	if err != nil {
		return Evaluation{}, err
	}

	eval.Proof = proof

	return eval, nil
}

// voprfFixedEval evaluates VOPRF_Eval with a fixed DLEQ parameter
func (s Server) voprfFixedBatchEval(blindTokens []gg.GroupElement, tDleq string) (BatchedEvaluation, error) {
	eval, err := s.oprfBatchEval(blindTokens)
	if err != nil {
		return BatchedEvaluation{}, err
	}
	elems := eval.Elements

	t, ok := new(big.Int).SetString(tDleq, 16)
	if !ok {
		panic("Bad hex value specified for fixed DLEQ value")
	}

	proof, err := s.FixedBatchGenerateProof(blindTokens, elems, t)
	if err != nil {
		return BatchedEvaluation{}, err
	}

	return BatchedEvaluation{Elements: elems, Proof: proof}, nil
}

func (s Server) GenerateProof(blindToken, elem gg.GroupElement) (Proof, error) {
	pog := s.ciph.POG()

	r, err := pog.RandomScalar()
	if err != nil {
		return Proof{}, err
	}

	return s.FixedGenerateProof(blindToken, elem, r)
}

func (s Server) FixedGenerateProof(blindToken, elem gg.GroupElement, r *big.Int) (Proof, error) {
	blindTokens := gg.GroupElementList{blindToken}
	elements := gg.GroupElementList{elem}

	M, Z, err := s.ComputeComposites(blindTokens, elements)
	if err != nil {
		return Proof{}, err
	}

	return s.fixedGenerateProofInner(M, Z, r)
}

func (s Server) fixedGenerateProofInner(M, Z gg.GroupElement, r *big.Int) (Proof, error) {
	pog := s.ciph.POG()
	G := pog.Generator()

	rG, err := G.ScalarMult(r)
	if err != nil {
		return Proof{}, err
	}

	rM, err := M.ScalarMult(r)
	if err != nil {
		return Proof{}, err
	}

	challengeDST := append([]byte("RFCXXXX-challenge-"), s.contextString...)
	h2Input, err := utils.ByteSliceLengthPrefixed(G, s.sk.PubKey, M, Z, rG, rM, challengeDST)
	if err != nil {
		return Proof{}, err
	}

	c1, err := pog.HashToScalar(h2Input)
	if err != nil {
		return Proof{}, err
	}

	c2 := big.NewInt(1)

	c2.Mul(c1, s.sk.K)
	c2.Sub(r, c2)
	c2.Mod(c2, pog.Order())

	return Proof{pog, c1, c2}, nil
}

func (s Server) BatchGenerateProof(blindTokens, elems []gg.GroupElement) (Proof, error) {
	pog := s.ciph.POG()

	r, err := pog.RandomScalar()
	if err != nil {
		return Proof{}, err
	}

	return s.FixedBatchGenerateProof(blindTokens, elems, r)
}

func (s Server) FixedBatchGenerateProof(blindTokens, elements []gg.GroupElement, r *big.Int) (Proof, error) {
	M, Z, err := s.ComputeComposites(blindTokens, elements)
	if err != nil {
		return Proof{}, err
	}

	return s.fixedGenerateProofInner(M, Z, r)
}

func (s Server) Verifiable() bool {
	return s.verifiable
}

func (s Server) ComputeComposites(blindTokens gg.GroupElementList, elements gg.GroupElementList) (M gg.GroupElement, Z gg.GroupElement, err error) {
	return computeComposites(s.ciph.POG(), s.contextString, s.sk.PubKey, blindTokens, elements)
}

func computeComposites(pog gg.PrimeOrderGroup, contextString []byte, pubKey PublicKey,
	blindTokens gg.GroupElementList, elements gg.GroupElementList) (M gg.GroupElement, Z gg.GroupElement, err error) {
	G := pog.Generator()

	seedDST := append([]byte("RFCXXXX-seed-"), contextString...)
	compositeDST := append([]byte("RFCXXXX-composite-"), contextString...)

	h1Input, err := utils.ByteSliceLengthPrefixed(G, pubKey, blindTokens, elements, seedDST)
	if err != nil {
		return nil, nil, err
	}

	h := pog.Hash()
	h.Write(h1Input)
	seed := h.Sum(nil)

	if len(blindTokens) != len(elements) {
		return nil, nil, errors.New("blindTokens and elements must have equal length")
	}

	for i, blindToken := range blindTokens {
		h2Input, err := utils.ByteSliceLengthPrefixed(seed, i, compositeDST)
		if err != nil {
			return nil, nil, err
		}

		di, err := pog.HashToScalar(h2Input)
		if err != nil {
			return nil, nil, err
		}

		Mi := blindToken

		// M = di*Mi + M
		Mi, err = Mi.ScalarMult(di)
		if err != nil {
			return nil, nil, err
		}

		if i == 0 {
			M = Mi
		} else {
			M, err = M.Add(Mi)
			if err != nil {
				return nil, nil, err
			}
		}

		Zi := elements[i]

		// Z = di*Zi + Z
		Zi, err = Zi.ScalarMult(di)
		if err != nil {
			return nil, nil, err
		}

		if i == 0 {
			Z = Zi
		} else {
			Z, err = Z.Add(Zi)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	return M, Z, nil
}

// Blind is unimplemented for the server
func (s Server) Blind(x []byte) (*Token, gg.GroupElement, error) {
	return nil, nil, oerr.ErrOPRFUnimplementedFunctionServer
}

// Unblind is unimplemented for the server
func (s Server) Unblind(ev Evaluation, token *Token, blindToken gg.GroupElement) (gg.GroupElement, error) {
	return nil, oerr.ErrOPRFUnimplementedFunctionServer
}

// BatchUnblind is unimplemented for the server
func (s Server) BatchUnblind(ev BatchedEvaluation, tokens []*Token, blindTokens []gg.GroupElement) ([]gg.GroupElement, error) {
	return nil, oerr.ErrOPRFUnimplementedFunctionServer
}

// Finalize is unimplemented for the server
func (s Server) Finalize(token *Token, unblindedToken gg.GroupElement, info []byte) ([]byte, error) {
	return nil, oerr.ErrOPRFUnimplementedFunctionServer
}

// Client implements the OPRF interface for processing the client-side
// operations of the OPRF protocol
type Client struct {
	contextString []byte
	ciph          gg.Ciphersuite
	pk            PublicKey
	verifiable    bool
}

// Ciphersuite returns the Ciphersuite object associated with the Client
func (c Client) Ciphersuite() gg.Ciphersuite { return c.ciph }

// PublicKey returns the PublicKey object associated with the Client
func (c Client) PublicKey() PublicKey { return c.pk }

// SetPublicKey sets a server public key for the client. All VOPRF messages will
// be verified with respect to this PublicKey
func (c Client) SetPublicKey(pk PublicKey) Client { c.pk = pk; return c }

// Setup associates the client with a ciphersuite object
func (c Client) Setup(ciphersuiteID int, pogInit gg.PrimeOrderGroup) (Participant, error) {
	c.verifiable = false
	return c.setup(ciphersuiteID, pogInit, modeBase)
}

func (c Client) SetupVerifiable(ciphersuiteID int, pogInit gg.PrimeOrderGroup) (Participant, error) {
	c.verifiable = true
	return c.setup(ciphersuiteID, pogInit, modeVerifiable)
}

func (c Client) setup(ciphersuiteID int, pogInit gg.PrimeOrderGroup, mode int) (Participant, error) {
	ciph, err := gg.Ciphersuite{}.FromID(ciphersuiteID, pogInit)
	if err != nil {
		return nil, err
	}

	modeString, err := utils.I2osp(mode, 1)
	if err != nil {
		return nil, err
	}

	idString, err := utils.I2osp(int(ciph.ID()), 2)
	if err != nil {
		return nil, err
	}

	c.ciph = ciph
	c.contextString = append(modeString, idString...)

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

// BatchUnblind returns the unblinded group element N = r^{-1}*elem if the DLEQ proof
// check passes (proof check is omitted if the ciphersuite is not verifiable)
func (c Client) Unblind(ev Evaluation, token *Token, blindToken gg.GroupElement) (gg.GroupElement, error) {
	if !c.Verifiable() {
		return c.oprfUnblind(ev, token.Blind)
	}
	return c.voprfUnblind(ev, token, blindToken)
}

// BatchUnblind returns the unblinded group elements N = r^{-1}*elem if the DLEQ proof
// check passes (proof check is omitted if the ciphersuite is not verifiable)
func (c Client) BatchUnblind(ev BatchedEvaluation, tokens []*Token, blindTokens []gg.GroupElement) ([]gg.GroupElement, error) {
	// check that the lengths of the expected evaluations is the same as the
	// number generated
	if len(ev.Elements) != len(blindTokens) {
		return nil, oerr.ErrClientInconsistentResponse
	}
	if !c.Verifiable() {
		return c.oprfBatchUnblind(ev, tokens)
	}
	return c.voprfBatchUnblind(ev, tokens, blindTokens)
}

func (c Client) voprfUnblind(ev Evaluation, token *Token, blindToken gg.GroupElement) (gg.GroupElement, error) {
	// check proof
	if b, err := c.VerifyProof(blindToken, ev); !b {
		if err == nil {
			return nil, oerr.ErrClientVerification
		}
		return nil, err
	}

	return c.oprfUnblind(ev, token.Blind)
}

// voprfBatchUnblind runs VOPRF_Unblind as specified in draft-irtf-cfrg-voprf-02
func (c Client) voprfBatchUnblind(evs BatchedEvaluation, tokens []*Token, blindTokens []gg.GroupElement) ([]gg.GroupElement, error) {
	// check proof
	if b, err := c.BatchVerifyProof(blindTokens, evs); !b {
		if err != nil {
			return nil, err
		}
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

func (c Client) VerifyProof(blindToken gg.GroupElement, ev Evaluation) (bool, error) {
	blindTokens := gg.GroupElementList{blindToken}
	elements := gg.GroupElementList{ev.Element}

	M, Z, err := c.ComputeComposites(blindTokens, elements)
	if err != nil {
		return false, err
	}

	return c.verifyProofInner(M, Z, ev.Proof)
}

func (c Client) BatchVerifyProof(blindTokens []gg.GroupElement, evs BatchedEvaluation) (bool, error) {
	M, Z, err := c.ComputeComposites(blindTokens, evs.Elements)
	if err != nil {
		return false, err
	}

	return c.verifyProofInner(M, Z, evs.Proof)
}

func (c Client) verifyProofInner(M, Z gg.GroupElement, proof Proof) (bool, error) {
	pog := c.ciph.POG()
	G := pog.Generator()

	// A' = (Ev.proof[1] * G + Ev.proof[0] * pkS)
	A, err := G.ScalarMult(proof.S)
	if err != nil {
		return false, err
	}

	A2, err := c.pk.ScalarMult(proof.C)
	if err != nil {
		return false, err
	}

	A, err = A.Add(A2)
	if err != nil {
		return false, err
	}

	// B' = (Ev.proof[1] * M + Ev.proof[0] * Z)
	B, err := M.ScalarMult(proof.S)
	if err != nil {
		return false, err
	}

	B2, err := Z.ScalarMult(proof.C)
	if err != nil {
		return false, err
	}

	B, err = B.Add(B2)
	if err != nil {
		return false, err
	}

	challengeDST := append([]byte("RFCXXXX-challenge-"), c.contextString...)
	h2Input, err := utils.ByteSliceLengthPrefixed(G, c.pk, M, Z, A, B, challengeDST)
	if err != nil {
		return false, err
	}

	c1, err := pog.HashToScalar(h2Input)
	if err != nil {
		return false, err
	}

	return c1.Cmp(proof.C) == 0, nil
}

func (c Client) Verifiable() bool {
	return c.verifiable
}

func (c Client) ComputeComposites(blindTokens gg.GroupElementList, elements gg.GroupElementList) (M gg.GroupElement, Z gg.GroupElement, err error) {
	return computeComposites(c.ciph.POG(), c.contextString, c.pk, blindTokens, elements)
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

	hash := ciph.Hash()
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
func (c Client) Evaluate(blindToken gg.GroupElement) (Evaluation, error) {
	return Evaluation{}, oerr.ErrOPRFUnimplementedFunctionClient
}

// BatchEvaluate is not implemented for the OPRF client
func (c Client) BatchEvaluate(blindToken []gg.GroupElement) (BatchedEvaluation, error) {
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

// CastClient casts a Participant directly into a Client type
func CastClient(ptpnt Participant) (Client, error) {
	cli, ok := ptpnt.(Client)
	if !ok {
		return Client{}, oerr.ErrOPRFInvalidParticipant
	}
	return cli, nil
}
