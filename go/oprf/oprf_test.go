package oprf

import (
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"

	gg "github.com/alxdavids/voprf-poc/go/oprf/groups"
	"github.com/alxdavids/voprf-poc/go/oprf/groups/ecgroup"
	"github.com/stretchr/testify/assert"
)

type testCfg struct {
	t           *testing.T
	ciphersuite int
	batch       bool
	verifiable  bool
}

func batchStr(batch bool) string {
	if batch {
		return "Batch"
	} else {
		return "Single"
	}
}

func verifStr(verifiable bool) string {
	if verifiable {
		return "Verifiable"
	} else {
		return "Base"
	}
}

func runTest(t *testing.T, testFunc func(*testCfg)) {
	supported := []int{
		//gg.OPRF_CURVE25519_SHA512, //TODO
		gg.OPRF_CURVE448_SHA512,
		//gg.OPRF_P256_SHA512, //TODO
		gg.OPRF_P384_SHA512,
		gg.OPRF_P521_SHA512,
	}

	for _, ciph := range supported {
		for _, batch := range []bool{true, false} {
			for _, verifiable := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/%s/%s", gg.IDtoName(ciph), batchStr(batch), verifStr(verifiable)),
					func(t *testing.T) {
						testFunc(&testCfg{t, ciph, batch, verifiable})
					})
			}
		}
	}
}

func TestFullOPRF(t *testing.T) {
	runTest(t, checkFull)
}

// func TestFullOPRFP384(t *testing.T) {
// 	checkFullBase(t, gg.OPRF_P384_SHA512)
// }

// func TestFullOPRFP384Multiple(t *testing.T) {
// 	checkFullBatchBase(t, gg.OPRF_P384_SHA512, 5)
// }

// func TestFullVOPRFP384(t *testing.T) {
// 	checkFullVerifiable(t, gg.OPRF_P384_SHA512)
// }

// func TestFullVOPRFP384Multiple(t *testing.T) {
// 	checkFullBatchVerifiable(t, gg.OPRF_P384_SHA512, 5)
// }

// func TestFullOPRFP521(t *testing.T) {
// 	checkFullBase(t, gg.OPRF_P521_SHA512)
// }

// func TestFullOPRFP521Multiple(t *testing.T) {
// 	checkFullBatchBase(t, gg.OPRF_P521_SHA512, 5)
// }

// func TestFullVOPRFP521(t *testing.T) {
// 	checkFullVerifiable(t, gg.OPRF_P521_SHA512)
// }

// func TestFullVOPRFP521Multiple(t *testing.T) {
// 	checkFullBatchVerifiable(t, gg.OPRF_P521_SHA512, 5)
// }

// func TestFullOPRFCurve448(t *testing.T) {
// 	checkFullBase(t, gg.OPRF_CURVE448_SHA512)
// }

// func TestFullOPRFCurve448Multiple(t *testing.T) {
// 	checkFullBatchBase(t, gg.OPRF_CURVE448_SHA512, 5)
// }

// func TestFullVOPRFCurve448(t *testing.T) {
// 	checkFullVerifiable(t, gg.OPRF_CURVE448_SHA512)
// }

// func TestFullVOPRFCurve448Multiple(t *testing.T) {
// 	checkFullBatchVerifiable(t, gg.OPRF_CURVE448_SHA512, 5)
// }

// func TestServerSetupP384(t *testing.T) {
// 	checkServerSetup(t, gg.OPRF_P384_SHA512)
// }

// func TestServerSetupP521(t *testing.T) {
// 	checkServerSetup(t, gg.OPRF_P521_SHA512)
// }

// func TestServerSetupCurve448(t *testing.T) {
// 	checkServerSetup(t, gg.OPRF_CURVE448_SHA512)
// }

// func TestServerEvalP384(t *testing.T) {
// 	checkServerEval(t, gg.OPRF_P384_SHA512, 1)
// }

// func TestServerEvalP384Multiple(t *testing.T) {
// 	checkServerEval(t, gg.OPRF_P384_SHA512, 5)
// }

// func TestServerEvalP384Verifiable(t *testing.T) {
// 	checkServerEvalVerifiable(t, gg.OPRF_P384_SHA512, 1)
// }

// func TestServerEvalP384VerifiableMultiple(t *testing.T) {
// 	checkServerEvalVerifiable(t, gg.OPRF_P384_SHA512, 5)
// }

// func TestServerEvalP521(t *testing.T) {
// 	checkServerEval(t, gg.OPRF_P521_SHA512, 1)
// }

// func TestServerEvalP521Multiple(t *testing.T) {
// 	checkServerEval(t, gg.OPRF_P521_SHA512, 5)
// }

// func TestServerEvalP521Verifiable(t *testing.T) {
// 	checkServerEvalVerifiable(t, gg.OPRF_P521_SHA512, 1)
// }

// func TestServerEvalP521VerifiableMultiple(t *testing.T) {
// 	checkServerEvalVerifiable(t, gg.OPRF_P521_SHA512, 5)
// }

// func TestServerEvalCurve448(t *testing.T) {
// 	checkServerEval(t, gg.OPRF_CURVE448_SHA512, 1)
// }

// func TestServerEvalCurve448Multiple(t *testing.T) {
// 	checkServerEval(t, gg.OPRF_CURVE448_SHA512, 5)
// }

// func TestServerEvalCurve448Verifiable(t *testing.T) {
// 	checkServerEvalVerifiable(t, gg.OPRF_CURVE448_SHA512, 1)
// }

// func TestServerEvalCurve448VerifiableMultiple(t *testing.T) {
// 	checkServerEvalVerifiable(t, gg.OPRF_CURVE448_SHA512, 5)
// }

// func TestServerBlind(t *testing.T) {
// 	s, err := serverSetup(gg.OPRF_P384_SHA512)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	_, _, err = s.Blind([]byte{})
// 	if !errors.Is(err, oerr.ErrOPRFUnimplementedFunctionServer) {
// 		t.Fatal("Function should be unimplemented")
// 	}
// }

// func TestServerUnblind(t *testing.T) {
// 	s, err := serverSetup(gg.OPRF_P384_SHA512)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	_, err = s.BatchUnblind(BatchedEvaluation{}, []*Token{new(Token)}, []gg.GroupElement{ecgroup.Point{}})
// 	if !errors.Is(err, oerr.ErrOPRFUnimplementedFunctionServer) {
// 		t.Fatal("Function should be unimplemented")
// 	}
// }

// func TestServerFinalize(t *testing.T) {
// 	s, err := serverSetup(gg.OPRF_P384_SHA512)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	var ge gg.GroupElement

// 	_, err = s.Finalize(&Token{}, ge, []byte{})
// 	if !errors.Is(err, oerr.ErrOPRFUnimplementedFunctionServer) {
// 		t.Fatal("Function should be unimplemented")
// 	}
// }

// func TestClientSetupP384(t *testing.T) {
// 	checkClientSetup(t, gg.OPRF_P384_SHA512)
// }

// func TestClientSetupP521(t *testing.T) {
// 	checkClientSetup(t, gg.OPRF_P521_SHA512)
// }

// func TestClientSetupCurve448(t *testing.T) {
// 	checkClientSetup(t, gg.OPRF_CURVE448_SHA512)
// }

// func TestClientBlindUnblindP384(t *testing.T) {
// 	checkClientBlindUnblind(t, gg.OPRF_P384_SHA512, 1)
// }

// func TestClientBlindUnblindP384Multiple(t *testing.T) {
// 	checkClientBlindUnblind(t, gg.OPRF_P384_SHA512, 5)
// }

// func TestClientBlindUnblindP384Verifiable(t *testing.T) {
// 	checkClientBlindUnblind(t, gg.OPRF_P384_SHA512, 1)
// }

// func TestClientBlindUnblindP384VerifiableMultiple(t *testing.T) {
// 	checkClientBlindUnblind(t, gg.OPRF_P384_SHA512, 5)
// }

// func TestClientBlindUnblindP521(t *testing.T) {
// 	checkClientBlindUnblind(t, gg.OPRF_P521_SHA512, 1)
// }

// func TestClientBlindUnblindP521Multiple(t *testing.T) {
// 	checkClientBlindUnblind(t, gg.OPRF_P521_SHA512, 5)
// }

// func TestClientBlindUnblindP521Verifiable(t *testing.T) {
// 	checkClientBlindUnblind(t, gg.OPRF_P521_SHA512, 1)
// }

// func TestClientBlindUnblindP521VerifiableMultiple(t *testing.T) {
// 	checkClientBlindUnblind(t, gg.OPRF_P521_SHA512, 5)
// }

// func TestClientBlindUnblindCurve448(t *testing.T) {
// 	checkClientBlindUnblind(t, gg.OPRF_CURVE448_SHA512, 1)
// }

// func TestClientBlindUnblindCurve448Multiple(t *testing.T) {
// 	checkClientBlindUnblind(t, gg.OPRF_CURVE448_SHA512, 5)
// }

// func TestClientBlindUnblindCurve448Verifiable(t *testing.T) {
// 	checkClientBlindUnblind(t, gg.OPRF_CURVE448_SHA512, 1)
// }

// func TestClientBlindUnblindCurve448VerifiableMultiple(t *testing.T) {
// 	checkClientBlindUnblind(t, gg.OPRF_CURVE448_SHA512, 5)
// }

// func TestClientFinalizeP384(t *testing.T) {
// 	checkClientFinalize(t, gg.OPRF_P384_SHA512)
// }

// func TestClientFinalizeP521(t *testing.T) {
// 	checkClientFinalize(t, gg.OPRF_P521_SHA512)
// }

// func TestClientFinalizeCurve448(t *testing.T) {
// 	checkClientFinalize(t, gg.OPRF_CURVE448_SHA512)
// }

// func TestClientEval(t *testing.T) {
// 	c, err := clientSetup(gg.OPRF_P384_SHA512)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	_, err = c.BatchEvaluate([]gg.GroupElement{ecgroup.Point{}})
// 	if !errors.Is(err, oerr.ErrOPRFUnimplementedFunctionClient) {
// 		t.Fatal("Function should be unimplemented")
// 	}
// }

// func TestClientUnblindVerifiable(t *testing.T) {
// 	c, err := clientSetup(gg.OPRF_P384_SHA512)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	pog := c.Ciphersuite().POG()
// 	_, err = pog.RandomScalar()
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// }

// func checkServerSetup(t *testing.T, validCiphersuite int) {
// 	s, err := serverSetup(validCiphersuite)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	assert.NotEmpty(t, s)
// 	assert.NotEmpty(t, s.Ciphersuite())
// 	assert.NotEmpty(t, s.SecretKey())
// 	assert.NotEmpty(t, s.SecretKey().PubKey)
// }

// func checkClientSetup(t *testing.T, validCiphersuite int) {
// 	c, err := clientSetup(validCiphersuite)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	assert.NotEmpty(t, c)
// 	assert.NotEmpty(t, c.Ciphersuite())
// }

func setup(cfg *testCfg) (Server, Client, error) {
	s, err := serverSetup(cfg)
	if err != nil {
		return Server{}, Client{}, err
	}

	c, err := clientSetup(cfg)
	if err != nil {
		return Server{}, Client{}, err
	}

	if c.Ciphersuite().ID() != s.Ciphersuite().ID() {
		return Server{}, Client{}, errors.New("inconsistent ciphersuites")
	}

	return s, c, nil
}

func serverSetup(cfg *testCfg) (Server, error) {
	var s Participant
	var err error

	if cfg.verifiable {
		s, err = Server{}.SetupVerifiable(cfg.ciphersuite, ecgroup.GroupCurve{})
	} else {
		s, err = Server{}.Setup(cfg.ciphersuite, ecgroup.GroupCurve{})
	}
	if err != nil {
		return Server{}, err
	}

	return s.(Server), nil
}

func clientSetup(cfg *testCfg) (Client, error) {
	var c Participant
	var err error

	if cfg.verifiable {
		c, err = Client{}.SetupVerifiable(cfg.ciphersuite, ecgroup.GroupCurve{})
	} else {
		c, err = Client{}.Setup(cfg.ciphersuite, ecgroup.GroupCurve{})
	}
	if err != nil {
		return Client{}, err
	}

	return c.(Client), nil
}

// func checkServerEval(t *testing.T, validCiphersuite int, n int) {
// 	s, _, blindTokens, err := setupServerEval(validCiphersuite, n)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	ciph := s.Ciphersuite()

// 	// evaluate the OPRF
// 	var ev Evaluation
// 	var evs BatchedEvaluation
// 	var elems []gg.GroupElement
// 	if n == 1 {
// 		ev, err := s.Evaluate(blindTokens[0])
// 		if err != nil {
// 			t.Fatal(err)
// 		}
// 		elems = []gg.GroupElement{ev.Element}
// 	} else {
// 		evs, err := s.BatchEvaluate(blindTokens)
// 		if err != nil {
// 			t.Fatal(err)
// 		}
// 		elems = evs.Elements
// 	}

// 	// only one evaluation
// 	for i, Q := range elems {
// 		chkQ, err := blindTokens[i].ScalarMult(s.SecretKey().K)
// 		if err != nil {
// 			t.Fatal(err)
// 		}
// 		if !Q.Equal(chkQ) {
// 			t.Fatal("Server evaluation returned inconsistent result")
// 		}
// 	}

// 	// verify proof if necessary
// 	if ciph.Verifiable() {
// 		c, err := clientSetup(validCiphersuite)
// 		if err != nil {
// 			t.Fatal(err)
// 		}
// 		if n == 1 {
// 			valid, err := c.VerifyProof(blindTokens[0], ev)
// 			if err != nil {
// 				t.Fatal(err)
// 			}
// 			assert.True(t, valid)
// 		} else {
// 			valid, err := c.BatchVerifyProof(blindTokens, evs)
// 			if err != nil {
// 				t.Fatal(err)
// 			}
// 			assert.True(t, valid)
// 		}
// 	}
// }

// func checkClientBlindUnblind(t *testing.T, validCiphersuite int, n int) {
// 	c, eval, tokens, blindTokens, sk, err := clientSetupUnblind(validCiphersuite, n)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	// attempt unblind
// 	unblindedTokens, err := c.BatchUnblind(eval, tokens, blindTokens)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	// check that the unblinded elements correspond
// 	for i, unblindedToken := range unblindedTokens {
// 		T, err := c.Ciphersuite().POG().HashToGroup(tokens[i].Data)
// 		if err != nil {
// 			t.Fatal(err)
// 		}

// 		expected, err := T.ScalarMult(sk)
// 		if err != nil {
// 			t.Fatal(err)
// 		}
// 		assert.True(t, unblindedToken.Equal(expected))
// 	}
// }

// func checkClientFinalize(t *testing.T, validCiphersuite int) {
// 	c, err := clientSetup(validCiphersuite)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	clientInput := []byte{1, 2, 3, 4, 5}
// 	token := &Token{Data: clientInput}
// 	info := []byte{6, 7, 8, 9, 10}
// 	pog := c.Ciphersuite().POG()

// 	unblindedToken, err := pog.HashToGroup(clientInput)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	output, err := c.Finalize(token, unblindedToken, info)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	// recompute
// 	bytesUnblindedToken, err := unblindedToken.Serialize()
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	DST := []byte("RFCXXXX-Finalize")

// 	hash := c.Ciphersuite().Hash()
// 	lengthBuffer := make([]byte, 2)

// 	binary.BigEndian.PutUint16(lengthBuffer, uint16(len(DST)))
// 	hash.Write(lengthBuffer)
// 	hash.Write(DST)

// 	binary.BigEndian.PutUint16(lengthBuffer, uint16(len(clientInput)))
// 	hash.Write(lengthBuffer)
// 	hash.Write(clientInput)

// 	binary.BigEndian.PutUint16(lengthBuffer, uint16(len(bytesUnblindedToken)))
// 	hash.Write(lengthBuffer)
// 	hash.Write(bytesUnblindedToken)

// 	binary.BigEndian.PutUint16(lengthBuffer, uint16(len(info)))
// 	hash.Write(lengthBuffer)
// 	hash.Write(info)

// 	outputCheck := hash.Sum(nil)

// 	if !hmac.Equal(output, outputCheck) {
// 		t.Fatal("Finalize failed to produce the correct output")
// 	}
// }

func checkFull(cfg *testCfg) {
	s, c, err := setup(cfg)
	if err != nil {
		cfg.t.Fatal(err)
	}

	checkFullOld(cfg.t, cfg.ciphersuite, s, c)
}


func checkFullOld(t *testing.T, validCiphersuite int, s Server, c Client) {
	infoFinal := []byte{6, 7, 8, 9, 10}
	c.pk = s.SecretKey().PubKey

	// create blinded point
	x := make([]byte, c.Ciphersuite().POG().ByteLength())
	rand.Read(x)
	token, blindToken, err := c.Blind(x)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, blindToken.IsValid())

	// do server evaluation
	eval, err := s.Evaluate(blindToken)
	if err != nil {
		t.Fatal(err)
	}

	// do client unblinding
	unblindedToken, err := c.Unblind(eval, token, blindToken)
	if err != nil {
		t.Fatal(err)
	}

	// compute finalizations and check that they can also be recomputed by the
	// server

	outputClient, err := c.Finalize(token, unblindedToken, infoFinal)
	if err != nil {
		t.Fatal(err)
	}

	// compute server finalization
	T, err := s.Ciphersuite().POG().HashToGroup(token.Data)
	if err != nil {
		t.Fatal(err)
	}

	ev, err := s.Evaluate(T)
	if err != nil {
		t.Fatal(err)
	}

	outputServer, err := c.Finalize(token, ev.Element, infoFinal)
	if err != nil {
		t.Fatal(err)
	}

	// check that client & server agree
	assert.True(t, hmac.Equal(outputClient, outputServer))
}

func checkFullBatch(t *testing.T, validCiphersuite int, n int, s Server, c Client) {
	infoFinal := []byte{6, 7, 8, 9, 10}
	c.pk = s.SecretKey().PubKey

	// create blinded points
	blindTokens := make([]gg.GroupElement, n)
	tokens := make([]*Token, n)
	for i := 0; i < n; i++ {
		x := make([]byte, c.Ciphersuite().POG().ByteLength())
		rand.Read(x)
		token, blindToken, err := c.Blind(x)
		if err != nil {
			t.Fatal(err)
		}
		assert.True(t, blindToken.IsValid())

		blindTokens[i] = blindToken
		tokens[i] = token
	}

	// do server evaluation
	eval, err := s.BatchEvaluate(blindTokens)
	if err != nil {
		t.Fatal(err)
	}

	// do client unblinding
	unblindedTokens, err := c.BatchUnblind(eval, tokens, blindTokens)
	if err != nil {
		t.Fatal(err)
	}

	// compute finalizations and check that they can also be recomputed by the
	// server
	for i, unblindedToken := range unblindedTokens {
		y, err := c.Finalize(tokens[i], unblindedToken, infoFinal)
		if err != nil {
			t.Fatal(err)
		}

		// compute server finalization
		T, err := s.Ciphersuite().POG().HashToGroup(tokens[i].Data)
		if err != nil {
			t.Fatal(err)
		}

		evs, err := s.BatchEvaluate([]gg.GroupElement{T})
		if err != nil {
			t.Fatal(err)
		}

		elem := evs.Elements[0]

		yServer, err := c.Finalize(tokens[i], elem, infoFinal)
		if err != nil {
			t.Fatal(err)
		}

		// check that client & server agree
		assert.True(t, hmac.Equal(y, yServer))
	}
}

// func setupServerEval(validCiphersuite int, n int) (Server, [][]byte, []gg.GroupElement, error) {
// 	s, err := serverSetup(validCiphersuite)
// 	if err != nil {
// 		return Server{}, nil, nil, err
// 	}
// 	ciph := s.Ciphersuite()
// 	pog := ciph.POG()
// 	inputs := make([][]byte, n)
// 	eles := make([]gg.GroupElement, n)
// 	for i := 0; i < n; i++ {
// 		x := make([]byte, pog.ByteLength())
// 		rand.Read(x)
// 		P, err := pog.HashToGroup(x)
// 		if err != nil {
// 			return Server{}, nil, nil, err
// 		}
// 		inputs[i] = x
// 		eles[i] = P
// 	}
// 	return s, inputs, eles, nil
// }

// func clientSetupUnblind(validCiphersuite int, n int) (Client, BatchedEvaluation, []*Token, []gg.GroupElement, *big.Int, error) {
// 	c, err := clientSetup(validCiphersuite)
// 	if err != nil {
// 		return Client{}, BatchedEvaluation{}, nil, nil, nil, err
// 	}
// 	pog := c.Ciphersuite().POG()

// 	// create blinded points
// 	blindTokens := make([]gg.GroupElement, n)
// 	tokens := make([]*Token, n)
// 	for i := 0; i < n; i++ {
// 		x := make([]byte, pog.ByteLength())
// 		rand.Read(x)
// 		token, blindToken, err := c.Blind(x)
// 		if err != nil {
// 			return Client{}, BatchedEvaluation{}, nil, nil, nil, err
// 		}

// 		if !blindToken.IsValid() {
// 			return Client{}, BatchedEvaluation{}, nil, nil, nil, errors.New("Point is not valid")
// 		}

// 		blindTokens[i] = blindToken
// 		tokens[i] = token
// 	}

// 	// dummy server for generating keys and evaluating OPRF
// 	// we need to do this as BatchUnblind also checks the DLEQ proof in the
// 	// verifiable mode
// 	s, err := serverSetup(validCiphersuite)
// 	if err != nil {
// 		return Client{}, BatchedEvaluation{}, nil, nil, nil, err
// 	}
// 	eval, err := s.BatchEvaluate(blindTokens)
// 	if err != nil {
// 		return Client{}, BatchedEvaluation{}, nil, nil, nil, err
// 	}
// 	c.pk = s.sk.PubKey

// 	return c, eval, tokens, blindTokens, s.SecretKey().K, err
// }

/**
 * Benchmarks
 */

// func BenchmarkServerOPRFSetupP384(b *testing.B) {
// 	benchServerSetup(b, gg.OPRF_P384_SHA512)
// }

// func BenchmarkServerVOPRFSetupP384(b *testing.B) {
// 	benchServerSetup(b, gg.OPRF_P384_SHA512)
// }

// func BenchmarkServerOPRFSetupP521(b *testing.B) {
// 	benchServerSetup(b, gg.OPRF_P521_SHA512)
// }

// func BenchmarkServerVOPRFSetupP521(b *testing.B) {
// 	benchServerSetup(b, gg.OPRF_P521_SHA512)
// }

// func BenchmarkServerOPRFSetupC448(b *testing.B) {
// 	benchServerSetup(b, gg.OPRF_CURVE448_SHA512)
// }

// func BenchmarkServerVOPRFSetupC448(b *testing.B) {
// 	benchServerSetup(b, gg.OPRF_CURVE448_SHA512)
// }

// // func benchServerSetup(b *testing.B, validCiphersuite int) {
// // 	for i := 0; i < b.N; i++ {
// // 		_, err := serverSetup(validCiphersuite)
// // 		if err != nil {
// // 			b.Fatal(err)
// // 		}
// // 	}
// // }

// func BenchmarkServerOPRFEvalP384_1(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P384_SHA512, 1)
// }

// func BenchmarkServerOPRFEvalP384_5(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P384_SHA512, 5)
// }

// func BenchmarkServerOPRFEvalP384_10(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P384_SHA512, 10)
// }

// func BenchmarkServerOPRFEvalP384_25(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P384_SHA512, 25)
// }

// func BenchmarkServerOPRFEvalP384_50(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P384_SHA512, 50)
// }

// func BenchmarkServerOPRFEvalP384_100(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P384_SHA512, 100)
// }

// func BenchmarkServerVOPRFEvalP384_1(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P384_SHA512, 1)
// }

// func BenchmarkServerVOPRFEvalP384_5(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P384_SHA512, 5)
// }

// func BenchmarkServerVOPRFEvalP384_10(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P384_SHA512, 10)
// }

// func BenchmarkServerVOPRFEvalP384_25(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P384_SHA512, 25)
// }

// func BenchmarkServerVOPRFEvalP384_50(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P384_SHA512, 50)
// }

// func BenchmarkServerVOPRFEvalP384_100(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P384_SHA512, 100)
// }

// func BenchmarkServerOPRFEvalP521_1(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P521_SHA512, 1)
// }

// func BenchmarkServerOPRFEvalP521_5(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P521_SHA512, 5)
// }

// func BenchmarkServerOPRFEvalP521_10(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P521_SHA512, 10)
// }

// func BenchmarkServerOPRFEvalP521_25(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P521_SHA512, 25)
// }

// func BenchmarkServerOPRFEvalP521_50(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P521_SHA512, 50)
// }

// func BenchmarkServerOPRFEvalP521_100(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P521_SHA512, 100)
// }

// func BenchmarkServerVOPRFEvalP521_1(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P521_SHA512, 1)
// }

// func BenchmarkServerVOPRFEvalP521_5(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P521_SHA512, 5)
// }

// func BenchmarkServerVOPRFEvalP521_10(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P521_SHA512, 10)
// }

// func BenchmarkServerVOPRFEvalP521_25(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P521_SHA512, 25)
// }

// func BenchmarkServerVOPRFEvalP521_50(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P521_SHA512, 50)
// }

// func BenchmarkServerVOPRFEvalP521_100(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_P521_SHA512, 100)
// }

// func BenchmarkServerOPRFEvalC448_1(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_CURVE448_SHA512, 1)
// }

// func BenchmarkServerOPRFEvalC448_5(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_CURVE448_SHA512, 5)
// }

// func BenchmarkServerOPRFEvalC448_10(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_CURVE448_SHA512, 10)
// }

// func BenchmarkServerOPRFEvalC448_25(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_CURVE448_SHA512, 25)
// }

// func BenchmarkServerOPRFEvalC448_50(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_CURVE448_SHA512, 50)
// }

// func BenchmarkServerOPRFEvalC448_100(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_CURVE448_SHA512, 100)
// }

// func BenchmarkServerVOPRFEvalC448_1(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_CURVE448_SHA512, 1)
// }

// func BenchmarkServerVOPRFEvalC448_5(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_CURVE448_SHA512, 5)
// }

// func BenchmarkServerVOPRFEvalC448_10(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_CURVE448_SHA512, 10)
// }

// func BenchmarkServerVOPRFEvalC448_25(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_CURVE448_SHA512, 25)
// }

// func BenchmarkServerVOPRFEvalC448_50(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_CURVE448_SHA512, 50)
// }

// func BenchmarkServerVOPRFEvalC448_100(b *testing.B) {
// 	benchServerEval(b, gg.OPRF_CURVE448_SHA512, 100)
// }

// func benchServerEval(b *testing.B, validCiphersuite int, n int) {
// 	s, _, eles, err := setupServerEval(validCiphersuite, n)
// 	if err != nil {
// 		b.Fatal(err)
// 	}

// 	// benchmark
// 	for i := 0; i < b.N; i++ {
// 		_, err := s.BatchEvaluate(eles)
// 		if err != nil {
// 			b.Fatal(err)
// 		}
// 	}
// }

// func BenchmarkClientBlindP384(b *testing.B) {
// 	benchClientBlind(b, gg.OPRF_P384_SHA512)
// }

// func BenchmarkClientBlindP521(b *testing.B) {
// 	benchClientBlind(b, gg.OPRF_P521_SHA512)
// }

// func benchClientBlind(b *testing.B, validCiphersuite int) {
// 	c, err := clientSetup(validCiphersuite)
// 	if err != nil {
// 		b.Fatal(err)
// 	}
// 	pog := c.Ciphersuite().POG()
// 	x := make([]byte, pog.ByteLength())
// 	rand.Read(x)

// 	// benchmark
// 	for i := 0; i < b.N; i++ {
// 		_, _, err := c.Blind(x)
// 		if err != nil {
// 			b.Fatal(err)
// 		}
// 	}
// }

// func BenchmarkClientOPRFUnblindP384_1(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P384_SHA512, 1)
// }

// func BenchmarkClientOPRFUnblindP384_5(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P384_SHA512, 5)
// }

// func BenchmarkClientOPRFUnblindP384_10(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P384_SHA512, 10)
// }

// func BenchmarkClientOPRFUnblindP384_25(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P384_SHA512, 25)
// }

// func BenchmarkClientOPRFUnblindP384_50(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P384_SHA512, 50)
// }

// func BenchmarkClientOPRFUnblindP384_100(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P384_SHA512, 100)
// }

// func BenchmarkClientVOPRFUnblindP384_1(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P384_SHA512, 1)
// }

// func BenchmarkClientVOPRFUnblindP384_5(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P384_SHA512, 5)
// }

// func BenchmarkClientVOPRFUnblindP384_10(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P384_SHA512, 10)
// }

// func BenchmarkClientVOPRFUnblindP384_25(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P384_SHA512, 25)
// }

// func BenchmarkClientVOPRFUnblindP384_50(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P384_SHA512, 50)
// }

// func BenchmarkClientVOPRFUnblindP384_100(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P384_SHA512, 100)
// }

// func BenchmarkClientOPRFUnblindP521_1(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P521_SHA512, 1)
// }

// func BenchmarkClientOPRFUnblindP521_5(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P521_SHA512, 5)
// }

// func BenchmarkClientOPRFUnblindP521_10(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P521_SHA512, 10)
// }

// func BenchmarkClientOPRFUnblindP521_25(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P521_SHA512, 25)
// }

// func BenchmarkClientOPRFUnblindP521_50(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P521_SHA512, 50)
// }

// func BenchmarkClientOPRFUnblindP521_100(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P521_SHA512, 100)
// }

// func BenchmarkClientVOPRFUnblindP521_1(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P521_SHA512, 1)
// }

// func BenchmarkClientVOPRFUnblindP521_5(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P521_SHA512, 5)
// }

// func BenchmarkClientVOPRFUnblindP521_10(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P521_SHA512, 10)
// }

// func BenchmarkClientVOPRFUnblindP521_25(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P521_SHA512, 25)
// }

// func BenchmarkClientVOPRFUnblindP521_50(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P521_SHA512, 50)
// }

// func BenchmarkClientVOPRFUnblindP521_100(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_P521_SHA512, 100)
// }

// func BenchmarkClientOPRFUnblindC448_1(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_CURVE448_SHA512, 1)
// }

// func BenchmarkClientOPRFUnblindC448_5(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_CURVE448_SHA512, 5)
// }

// func BenchmarkClientOPRFUnblindC448_10(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_CURVE448_SHA512, 10)
// }

// func BenchmarkClientOPRFUnblindC448_25(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_CURVE448_SHA512, 25)
// }

// func BenchmarkClientOPRFUnblindC448_50(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_CURVE448_SHA512, 50)
// }

// func BenchmarkClientOPRFUnblindC448_100(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_CURVE448_SHA512, 100)
// }

// func BenchmarkClientVOPRFUnblindC448_1(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_CURVE448_SHA512, 1)
// }

// func BenchmarkClientVOPRFUnblindC448_5(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_CURVE448_SHA512, 5)
// }

// func BenchmarkClientVOPRFUnblindC448_10(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_CURVE448_SHA512, 10)
// }

// func BenchmarkClientVOPRFUnblindC448_25(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_CURVE448_SHA512, 25)
// }

// func BenchmarkClientVOPRFUnblindC448_50(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_CURVE448_SHA512, 50)
// }

// func BenchmarkClientVOPRFUnblindC448_100(b *testing.B) {
// 	benchClientUnblind(b, gg.OPRF_CURVE448_SHA512, 100)
// }

// func benchClientUnblind(b *testing.B, validCiphersuite int, n int) {
// 	c, eval, tokens, blindTokens, _, err := clientSetupUnblind(validCiphersuite, n)
// 	if err != nil {
// 		b.Fatal(err)
// 	}

// 	// benchmark
// 	for i := 0; i < b.N; i++ {
// 		_, err := c.BatchUnblind(eval, tokens, blindTokens)
// 		if err != nil {
// 			b.Fatal(err)
// 		}
// 	}
// }

// func BenchmarkClientFinalizeP384(b *testing.B) {
// 	benchClientFinalize(b, gg.OPRF_P384_SHA512)
// }

// func BenchmarkClientFinalizeP521(b *testing.B) {
// 	benchClientFinalize(b, gg.OPRF_P521_SHA512)
// }

// func BenchmarkClientFinalizeC448(b *testing.B) {
// 	benchClientFinalize(b, gg.OPRF_CURVE448_SHA512)
// }

// func benchClientFinalize(b *testing.B, validCiphersuite int) {
// 	c, err := clientSetup(validCiphersuite)
// 	if err != nil {
// 		b.Fatal(err)
// 	}
// 	pog := c.Ciphersuite().POG()
// 	input := make([]byte, pog.ByteLength())
// 	rand.Read(input)
// 	info := []byte{6, 7, 8, 9, 10}
// 	unblindedToken, err := pog.HashToGroup(input)
// 	if err != nil {
// 		b.Fatal(err)
// 	}
// 	token := &Token{Data: input}

// 	// benchmark
// 	for i := 0; i < b.N; i++ {
// 		_, err := c.Finalize(token, unblindedToken, info)
// 		if err != nil {
// 			b.Fatal(err)
// 		}
// 	}
// }
