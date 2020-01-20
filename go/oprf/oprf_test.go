package oprf

import (
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"

	"github.com/alxdavids/voprf-poc/go/oerr"
	gg "github.com/alxdavids/voprf-poc/go/oprf/groups"
	"github.com/alxdavids/voprf-poc/go/oprf/groups/ecgroup"
	"github.com/stretchr/testify/assert"
)

var (
	validOPRFP384Ciphersuite      = "OPRF-P384-HKDF-SHA512-SSWU-RO"
	validOPRFP521Ciphersuite      = "OPRF-P521-HKDF-SHA512-SSWU-RO"
	validVOPRFP384Ciphersuite     = "VOPRF-P384-HKDF-SHA512-SSWU-RO"
	validVOPRFP521Ciphersuite     = "VOPRF-P521-HKDF-SHA512-SSWU-RO"
	validOPRFCURVE448Ciphersuite  = "OPRF-curve448-HKDF-SHA512-ELL2-RO"
	validVOPRFCURVE448Ciphersuite = "OPRF-curve448-HKDF-SHA512-ELL2-RO"
)

func TestFullOPRFP384(t *testing.T) {
	checkFull(t, validOPRFP384Ciphersuite, 1)
}

func TestFullOPRFP384Multiple(t *testing.T) {
	checkFull(t, validOPRFP384Ciphersuite, 5)
}

func TestFullVOPRFP384(t *testing.T) {
	checkFull(t, validOPRFP384Ciphersuite, 1)
}

func TestFullVOPRFP384Multiple(t *testing.T) {
	checkFull(t, validOPRFP384Ciphersuite, 5)
}

func TestFullOPRFP521(t *testing.T) {
	checkFull(t, validOPRFP521Ciphersuite, 1)
}

func TestFullOPRFP521Multiple(t *testing.T) {
	checkFull(t, validOPRFP521Ciphersuite, 5)
}

func TestFullVOPRFP521(t *testing.T) {
	checkFull(t, validOPRFP521Ciphersuite, 1)
}

func TestFullVOPRFP521Multiple(t *testing.T) {
	checkFull(t, validOPRFP521Ciphersuite, 5)
}

func TestFullCurve448(t *testing.T) {
	t.Skip("Skipping test.")
	checkFull(t, validOPRFCURVE448Ciphersuite, 1)
}

func TestServerSetupP384(t *testing.T) {
	checkServerSetup(t, validOPRFP384Ciphersuite)
}

func TestServerSetupP521(t *testing.T) {
	checkServerSetup(t, validOPRFP521Ciphersuite)
}

func TestServerEvalP384(t *testing.T) {
	checkServerEval(t, validOPRFP384Ciphersuite, 1)
}

func TestServerEvalP384Multiple(t *testing.T) {
	checkServerEval(t, validOPRFP384Ciphersuite, 5)
}

func TestServerEvalP384Verifiable(t *testing.T) {
	checkServerEval(t, validVOPRFP384Ciphersuite, 1)
}

func TestServerEvalP384VerifiableMultiple(t *testing.T) {
	checkServerEval(t, validVOPRFP384Ciphersuite, 5)
}

func TestServerEvalP521(t *testing.T) {
	checkServerEval(t, validOPRFP521Ciphersuite, 1)
}

func TestServerEvalP521Multiple(t *testing.T) {
	checkServerEval(t, validOPRFP521Ciphersuite, 5)
}

func TestServerEvalP521Verifiable(t *testing.T) {
	checkServerEval(t, validVOPRFP521Ciphersuite, 1)
}

func TestServerEvalP521VerifiableMultiple(t *testing.T) {
	checkServerEval(t, validVOPRFP521Ciphersuite, 5)
}

func TestServerBlind(t *testing.T) {
	s, err := serverSetup(validOPRFP384Ciphersuite)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = s.Blind([]byte{})
	if err != oerr.ErrOPRFUnimplementedFunctionServer {
		t.Fatal("Function should be unimplemented")
	}
}

func TestServerUnblind(t *testing.T) {
	s, err := serverSetup(validOPRFP384Ciphersuite)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Unblind(Evaluation{}, []gg.GroupElement{ecgroup.Point{}}, []*big.Int{new(big.Int)})
	if err != oerr.ErrOPRFUnimplementedFunctionServer {
		t.Fatal("Function should be unimplemented")
	}
}

func TestServerFinalize(t *testing.T) {
	s, err := serverSetup(validOPRFP384Ciphersuite)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Finalize(ecgroup.Point{}, []byte{}, []byte{})
	if err != oerr.ErrOPRFUnimplementedFunctionServer {
		t.Fatal("Function should be unimplemented")
	}
}

func TestClientSetupP384(t *testing.T) {
	checkClientSetup(t, validOPRFP384Ciphersuite)
}

func TestClientSetupP521(t *testing.T) {
	checkClientSetup(t, validOPRFP521Ciphersuite)
}

func TestClientBlindUnblindP384(t *testing.T) {
	checkClientBlindUnblind(t, validOPRFP384Ciphersuite, 1)
}

func TestClientBlindUnblindP384Multiple(t *testing.T) {
	checkClientBlindUnblind(t, validOPRFP384Ciphersuite, 5)
}

func TestClientBlindUnblindP384Verifiable(t *testing.T) {
	checkClientBlindUnblind(t, validVOPRFP384Ciphersuite, 1)
}

func TestClientBlindUnblindP384VerifiableMultiple(t *testing.T) {
	checkClientBlindUnblind(t, validVOPRFP384Ciphersuite, 5)
}

func TestClientBlindUnblindP521(t *testing.T) {
	checkClientBlindUnblind(t, validOPRFP521Ciphersuite, 1)
}

func TestClientBlindUnblindP521Multiple(t *testing.T) {
	checkClientBlindUnblind(t, validOPRFP521Ciphersuite, 5)
}

func TestClientBlindUnblindP521Verifiable(t *testing.T) {
	checkClientBlindUnblind(t, validVOPRFP521Ciphersuite, 1)
}

func TestClientBlindUnblindP521VerifiableMultiple(t *testing.T) {
	checkClientBlindUnblind(t, validVOPRFP521Ciphersuite, 5)
}

func TestClientFinalizeP384(t *testing.T) {
	checkClientFinalize(t, validOPRFP384Ciphersuite)
}

func TestClientFinalizeP521(t *testing.T) {
	checkClientFinalize(t, validOPRFP521Ciphersuite)
}

func TestClientEval(t *testing.T) {
	c, err := clientSetup(validOPRFP384Ciphersuite)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Eval([]gg.GroupElement{ecgroup.Point{}})
	if err != oerr.ErrOPRFUnimplementedFunctionClient {
		t.Fatal("Function should be unimplemented")
	}
}

func TestClientUnblindVerifiable(t *testing.T) {
	c, err := clientSetup(validVOPRFP384Ciphersuite)
	if err != nil {
		t.Fatal(err)
	}
	pog := c.Ciphersuite().POG()
	_, err = pog.UniformFieldElement()
	if err != nil {
		t.Fatal(err)
	}
}

func checkServerSetup(t *testing.T, validCiphersuite string) {
	s, err := serverSetup(validCiphersuite)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotEmpty(t, s)
	assert.NotEmpty(t, s.Ciphersuite())
	assert.NotEmpty(t, s.SecretKey())
	assert.NotEmpty(t, s.SecretKey().PubKey)
}

func checkClientSetup(t *testing.T, validCiphersuite string) {
	c, err := clientSetup(validCiphersuite)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotEmpty(t, c)
	assert.NotEmpty(t, c.Ciphersuite())
}

func serverSetup(ciph string) (Server, error) {
	s, err := Server{}.Setup(ciph, ecgroup.GroupCurve{})
	if err != nil {
		return Server{}, err
	}
	return s.(Server), nil
}

func clientSetup(ciph string) (Client, error) {
	s, err := Client{}.Setup(ciph, ecgroup.GroupCurve{})
	if err != nil {
		return Client{}, err
	}
	return s.(Client), nil
}

func checkServerEval(t *testing.T, validCiphersuite string, n int) {
	s, _, eles, err := setupServerEval(validCiphersuite, n)
	if err != nil {
		t.Fatal(err)
	}
	ciph := s.Ciphersuite()
	pog := ciph.POG()

	// evaluate the OPRF
	ev, err := s.Eval(eles)
	if err != nil {
		t.Fatal(err)
	}

	// only one evaluation
	for i, Q := range ev.Elements {
		chkQ, err := eles[i].ScalarMult(s.SecretKey().K)
		if err != nil {
			t.Fatal(err)
		}
		if !Q.Equal(chkQ) {
			t.Fatal("Server evaluation returned inconsistent result")
		}
	}

	// verify proof if necessary
	if ciph.Verifiable() {
		proof := ev.Proof
		if n == 1 {
			assert.True(t, proof.Verify(pog, ciph.H3(), ciph.H5(), s.SecretKey().PubKey, eles[0], ev.Elements[0]))
		} else {
			assert.True(t, proof.BatchVerify(pog, ciph.H3(), ciph.H4(), ciph.H5(), s.SecretKey().PubKey, eles, ev.Elements))
		}
	}
}

func checkClientBlindUnblind(t *testing.T, validCiphersuite string, n int) {
	c, eval, inputs, eles, blinds, sk, err := clientSetupUnblind(validCiphersuite, n)
	if err != nil {
		t.Fatal(err)
	}

	// attempt unblind
	ret, err := c.Unblind(eval, eles, blinds)
	if err != nil {
		t.Fatal(err)
	}

	// check that the unblinded elements correspond
	for i, N := range ret {
		T, err := c.Ciphersuite().POG().EncodeToGroup(inputs[i])
		if err != nil {
			t.Fatal(err)
		}
		chkN, err := T.ScalarMult(sk)
		if err != nil {
			t.Fatal(err)
		}
		assert.True(t, N.Equal(chkN))
	}
}

func checkClientFinalize(t *testing.T, validCiphersuite string) {
	c, err := clientSetup(validCiphersuite)
	if err != nil {
		t.Fatal(err)
	}
	x := []byte{1, 2, 3, 4, 5}
	aux := []byte{6, 7, 8, 9, 10}
	pog := c.Ciphersuite().POG()
	P, err := pog.EncodeToGroup(x)
	if err != nil {
		t.Fatal(err)
	}
	y, err := c.Finalize(P, x, aux)
	if err != nil {
		t.Fatal(err)
	}

	// recompute
	bytesP, err := P.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	DST := []byte("oprf_derive_output")
	hmacChk := hmac.New(c.Ciphersuite().H3, DST)
	input := append(x, bytesP...)
	_, e := hmacChk.Write(input)
	if e != nil {
		t.Fatal(e)
	}
	dk := hmacChk.Sum(nil)
	hmacOutChk := hmac.New(c.Ciphersuite().H3, dk)
	_, e = hmacOutChk.Write(aux)
	if e != nil {
		t.Fatal(e)
	}
	yChk := hmacOutChk.Sum(nil)
	if !hmac.Equal(y, yChk) {
		t.Fatal("Finalize failed to produce the correct output")
	}
}

func checkFull(t *testing.T, validCiphersuite string, n int) {
	s, err := serverSetup(validCiphersuite)
	if err != nil {
		t.Fatal(err)
	}
	c, err := clientSetup(validCiphersuite)
	if err != nil {
		t.Fatal(err)
	}

	if c.Ciphersuite().Name() != s.Ciphersuite().Name() {
		t.Fatal("Ciphersuites are inconsistent")
	}

	auxFinal := []byte{6, 7, 8, 9, 10}
	c.pk = s.SecretKey().PubKey

	// create blinded points
	inputs := make([][]byte, n)
	eles := make([]gg.GroupElement, n)
	blinds := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		x := make([]byte, c.Ciphersuite().POG().ByteLength())
		rand.Read(x)
		P, r, err := c.Blind(x)
		if err != nil {
			t.Fatal(err)
		}
		assert.True(t, P.IsValid())
		inputs[i] = x
		eles[i] = P
		blinds[i] = r
	}

	// do server evaluation
	eval, err := s.Eval(eles)
	if err != nil {
		t.Fatal(err)
	}

	// do client unblinding
	ret, err := c.Unblind(eval, eles, blinds)
	if err != nil {
		t.Fatal(err)
	}

	// compute finalizations and check that they can also be recomputed by the
	// server
	for i, N := range ret {
		y, err := c.Finalize(N, inputs[i], auxFinal)
		if err != nil {
			t.Fatal(err)
		}

		// compute server finalization
		T, err := s.Ciphersuite().POG().EncodeToGroup(inputs[i])
		if err != nil {
			t.Fatal(err)
		}
		out, err := s.Eval([]gg.GroupElement{T})
		if err != nil {
			t.Fatal(err)
		}
		Z := out.Elements[0]
		yServer, err := c.Finalize(Z, inputs[i], auxFinal)
		if err != nil {
			t.Fatal(err)
		}

		// check that client & server agree
		assert.True(t, hmac.Equal(y, yServer))
	}
}

func setupServerEval(validCiphersuite string, n int) (Server, [][]byte, []gg.GroupElement, error) {
	s, err := serverSetup(validCiphersuite)
	if err != nil {
		return Server{}, nil, nil, err
	}
	ciph := s.Ciphersuite()
	pog := ciph.POG()
	inputs := make([][]byte, n)
	eles := make([]gg.GroupElement, n)
	for i := 0; i < n; i++ {
		x := make([]byte, pog.ByteLength())
		rand.Read(x)
		P, err := pog.EncodeToGroup(x)
		if err != nil {
			return Server{}, nil, nil, err
		}
		inputs[i] = x
		eles[i] = P
	}
	return s, inputs, eles, nil
}

func clientSetupUnblind(validCiphersuite string, n int) (Client, Evaluation, [][]byte, []gg.GroupElement, []*big.Int, *big.Int, error) {
	c, err := clientSetup(validCiphersuite)
	if err != nil {
		return Client{}, Evaluation{}, nil, nil, nil, nil, err
	}
	pog := c.Ciphersuite().POG()

	// create blinded points
	inputs := make([][]byte, n)
	eles := make([]gg.GroupElement, n)
	blinds := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		x := make([]byte, pog.ByteLength())
		rand.Read(x)
		P, r, err := c.Blind(x)
		if err != nil {
			return Client{}, Evaluation{}, nil, nil, nil, nil, err
		}
		if !P.IsValid() {
			return Client{}, Evaluation{}, nil, nil, nil, nil, errors.New("Point is not valid")
		}
		inputs[i] = x
		eles[i] = P
		blinds[i] = r
	}

	// dummy server for generating keys and evaluating OPRF
	// we need to do this as Unblind also checks the DLEQ proof in the
	// verifiable mode
	s, err := serverSetup(validCiphersuite)
	if err != nil {
		return Client{}, Evaluation{}, nil, nil, nil, nil, err
	}
	eval, err := s.Eval(eles)
	if err != nil {
		return Client{}, Evaluation{}, nil, nil, nil, nil, err
	}
	c.pk = s.sk.PubKey

	return c, eval, inputs, eles, blinds, s.SecretKey().K, err
}

/**
 * Benchmarks
 */

func BenchmarkServerOPRFSetupP384(b *testing.B) {
	benchServerSetup(b, validOPRFP384Ciphersuite)
}

func BenchmarkServerVOPRFSetupP384(b *testing.B) {
	benchServerSetup(b, validVOPRFP384Ciphersuite)
}

func BenchmarkServerOPRFSetupP521(b *testing.B) {
	benchServerSetup(b, validOPRFP521Ciphersuite)
}

func BenchmarkServerVOPRFSetupP521(b *testing.B) {
	benchServerSetup(b, validVOPRFP521Ciphersuite)
}

func benchServerSetup(b *testing.B, validCiphersuite string) {
	for i := 0; i < b.N; i++ {
		_, err := serverSetup(validCiphersuite)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkServerOPRFEvalP384_1(b *testing.B) {
	benchServerEval(b, validOPRFP384Ciphersuite, 1)
}

func BenchmarkServerOPRFEvalP384_5(b *testing.B) {
	benchServerEval(b, validOPRFP384Ciphersuite, 5)
}

func BenchmarkServerOPRFEvalP384_10(b *testing.B) {
	benchServerEval(b, validOPRFP384Ciphersuite, 10)
}

func BenchmarkServerOPRFEvalP384_25(b *testing.B) {
	benchServerEval(b, validOPRFP384Ciphersuite, 25)
}

func BenchmarkServerOPRFEvalP384_50(b *testing.B) {
	benchServerEval(b, validOPRFP384Ciphersuite, 50)
}

func BenchmarkServerOPRFEvalP384_100(b *testing.B) {
	benchServerEval(b, validOPRFP384Ciphersuite, 100)
}

func BenchmarkServerVOPRFEvalP384_1(b *testing.B) {
	benchServerEval(b, validVOPRFP384Ciphersuite, 1)
}

func BenchmarkServerVOPRFEvalP384_5(b *testing.B) {
	benchServerEval(b, validVOPRFP384Ciphersuite, 5)
}

func BenchmarkServerVOPRFEvalP384_10(b *testing.B) {
	benchServerEval(b, validVOPRFP384Ciphersuite, 10)
}

func BenchmarkServerVOPRFEvalP384_25(b *testing.B) {
	benchServerEval(b, validVOPRFP384Ciphersuite, 25)
}

func BenchmarkServerVOPRFEvalP384_50(b *testing.B) {
	benchServerEval(b, validVOPRFP384Ciphersuite, 50)
}

func BenchmarkServerVOPRFEvalP384_100(b *testing.B) {
	benchServerEval(b, validVOPRFP384Ciphersuite, 100)
}

func BenchmarkServerOPRFEvalP521_1(b *testing.B) {
	benchServerEval(b, validOPRFP521Ciphersuite, 1)
}

func BenchmarkServerOPRFEvalP521_5(b *testing.B) {
	benchServerEval(b, validOPRFP521Ciphersuite, 5)
}

func BenchmarkServerOPRFEvalP521_10(b *testing.B) {
	benchServerEval(b, validOPRFP521Ciphersuite, 10)
}

func BenchmarkServerOPRFEvalP521_25(b *testing.B) {
	benchServerEval(b, validOPRFP521Ciphersuite, 25)
}

func BenchmarkServerOPRFEvalP521_50(b *testing.B) {
	benchServerEval(b, validOPRFP521Ciphersuite, 50)
}

func BenchmarkServerOPRFEvalP521_100(b *testing.B) {
	benchServerEval(b, validOPRFP521Ciphersuite, 100)
}

func BenchmarkServerVOPRFEvalP521_1(b *testing.B) {
	benchServerEval(b, validVOPRFP521Ciphersuite, 1)
}

func BenchmarkServerVOPRFEvalP521_5(b *testing.B) {
	benchServerEval(b, validVOPRFP521Ciphersuite, 5)
}

func BenchmarkServerVOPRFEvalP521_10(b *testing.B) {
	benchServerEval(b, validVOPRFP521Ciphersuite, 10)
}

func BenchmarkServerVOPRFEvalP521_25(b *testing.B) {
	benchServerEval(b, validVOPRFP521Ciphersuite, 25)
}

func BenchmarkServerVOPRFEvalP521_50(b *testing.B) {
	benchServerEval(b, validVOPRFP521Ciphersuite, 50)
}

func BenchmarkServerVOPRFEvalP521_100(b *testing.B) {
	benchServerEval(b, validVOPRFP521Ciphersuite, 100)
}

func benchServerEval(b *testing.B, validCiphersuite string, n int) {
	s, _, eles, err := setupServerEval(validCiphersuite, n)
	if err != nil {
		b.Fatal(err)
	}

	// benchmark
	for i := 0; i < b.N; i++ {
		_, err := s.Eval(eles)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkClientBlindP384(b *testing.B) {
	benchClientBlind(b, validOPRFP384Ciphersuite)
}

func BenchmarkClientBlindP521(b *testing.B) {
	benchClientBlind(b, validOPRFP521Ciphersuite)
}

func benchClientBlind(b *testing.B, validCiphersuite string) {
	c, err := clientSetup(validCiphersuite)
	if err != nil {
		b.Fatal(err)
	}
	pog := c.Ciphersuite().POG()
	x := make([]byte, pog.ByteLength())
	rand.Read(x)

	// benchmark
	for i := 0; i < b.N; i++ {
		_, _, err := c.Blind(x)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkClientOPRFUnblindP384_1(b *testing.B) {
	benchClientUnblind(b, validOPRFP384Ciphersuite, 1)
}

func BenchmarkClientOPRFUnblindP384_5(b *testing.B) {
	benchClientUnblind(b, validOPRFP384Ciphersuite, 5)
}

func BenchmarkClientOPRFUnblindP384_10(b *testing.B) {
	benchClientUnblind(b, validOPRFP384Ciphersuite, 10)
}

func BenchmarkClientOPRFUnblindP384_25(b *testing.B) {
	benchClientUnblind(b, validOPRFP384Ciphersuite, 25)
}

func BenchmarkClientOPRFUnblindP384_50(b *testing.B) {
	benchClientUnblind(b, validOPRFP384Ciphersuite, 50)
}

func BenchmarkClientOPRFUnblindP384_100(b *testing.B) {
	benchClientUnblind(b, validOPRFP384Ciphersuite, 100)
}

func BenchmarkClientVOPRFUnblindP384_1(b *testing.B) {
	benchClientUnblind(b, validVOPRFP384Ciphersuite, 1)
}

func BenchmarkClientVOPRFUnblindP384_5(b *testing.B) {
	benchClientUnblind(b, validVOPRFP384Ciphersuite, 5)
}

func BenchmarkClientVOPRFUnblindP384_10(b *testing.B) {
	benchClientUnblind(b, validVOPRFP384Ciphersuite, 10)
}

func BenchmarkClientVOPRFUnblindP384_25(b *testing.B) {
	benchClientUnblind(b, validVOPRFP384Ciphersuite, 25)
}

func BenchmarkClientVOPRFUnblindP384_50(b *testing.B) {
	benchClientUnblind(b, validVOPRFP384Ciphersuite, 50)
}

func BenchmarkClientVOPRFUnblindP384_100(b *testing.B) {
	benchClientUnblind(b, validVOPRFP384Ciphersuite, 100)
}

func BenchmarkClientOPRFUnblindP521_1(b *testing.B) {
	benchClientUnblind(b, validOPRFP521Ciphersuite, 1)
}

func BenchmarkClientOPRFUnblindP521_5(b *testing.B) {
	benchClientUnblind(b, validOPRFP521Ciphersuite, 5)
}

func BenchmarkClientOPRFUnblindP521_10(b *testing.B) {
	benchClientUnblind(b, validOPRFP521Ciphersuite, 10)
}

func BenchmarkClientOPRFUnblindP521_25(b *testing.B) {
	benchClientUnblind(b, validOPRFP521Ciphersuite, 25)
}

func BenchmarkClientOPRFUnblindP521_50(b *testing.B) {
	benchClientUnblind(b, validOPRFP521Ciphersuite, 50)
}

func BenchmarkClientOPRFUnblindP521_100(b *testing.B) {
	benchClientUnblind(b, validOPRFP521Ciphersuite, 100)
}

func BenchmarkClientVOPRFUnblindP521_1(b *testing.B) {
	benchClientUnblind(b, validVOPRFP521Ciphersuite, 1)
}

func BenchmarkClientVOPRFUnblindP521_5(b *testing.B) {
	benchClientUnblind(b, validVOPRFP521Ciphersuite, 5)
}

func BenchmarkClientVOPRFUnblindP521_10(b *testing.B) {
	benchClientUnblind(b, validVOPRFP521Ciphersuite, 10)
}

func BenchmarkClientVOPRFUnblindP521_25(b *testing.B) {
	benchClientUnblind(b, validVOPRFP521Ciphersuite, 25)
}

func BenchmarkClientVOPRFUnblindP521_50(b *testing.B) {
	benchClientUnblind(b, validVOPRFP521Ciphersuite, 50)
}

func BenchmarkClientVOPRFUnblindP521_100(b *testing.B) {
	benchClientUnblind(b, validVOPRFP521Ciphersuite, 100)
}

func benchClientUnblind(b *testing.B, validCiphersuite string, n int) {
	c, eval, _, eles, blinds, _, err := clientSetupUnblind(validCiphersuite, n)
	if err != nil {
		b.Fatal(err)
	}

	// benchmark
	for i := 0; i < b.N; i++ {
		_, err := c.Unblind(eval, eles, blinds)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkClientFinalizeP384(b *testing.B) {
	benchClientFinalize(b, validOPRFP384Ciphersuite)
}

func BenchmarkClientFinalizeP521(b *testing.B) {
	benchClientFinalize(b, validOPRFP521Ciphersuite)
}

func benchClientFinalize(b *testing.B, validCiphersuite string) {
	c, err := clientSetup(validCiphersuite)
	if err != nil {
		b.Fatal(err)
	}
	pog := c.Ciphersuite().POG()
	x := make([]byte, pog.ByteLength())
	rand.Read(x)
	aux := []byte{6, 7, 8, 9, 10}
	P, err := pog.EncodeToGroup(x)
	if err != nil {
		b.Fatal(err)
	}

	// benchmark
	for i := 0; i < b.N; i++ {
		_, err := c.Finalize(P, x, aux)
		if err != nil {
			b.Fatal(err)
		}
	}
}
