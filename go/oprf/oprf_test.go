package oprf

import (
	"crypto/hmac"
	"math/big"
	"testing"

	oErr "github.com/alxdavids/oprf-poc/go/err"
	"github.com/alxdavids/oprf-poc/go/oprf/groups/ecgroup"
	"github.com/stretchr/testify/assert"
)

var (
	validOPRFP384Ciphersuite  = "OPRF-P384-HKDF-SHA512-SSWU-RO"
	validOPRFP521Ciphersuite  = "OPRF-P521-HKDF-SHA512-SSWU-RO"
	validVOPRFP384Ciphersuite = "VOPRF-P384-HKDF-SHA512-SSWU-RO"
	validVOPRFP521Ciphersuite = "VOPRF-P521-HKDF-SHA512-SSWU-RO"
)

func TestFullOPRFP384(t *testing.T) {
	checkFullOPRF(t, validOPRFP384Ciphersuite)
}

func TestFullOPRFP521(t *testing.T) {
	checkFullOPRF(t, validOPRFP521Ciphersuite)
}

func TestServerSetupP384(t *testing.T) {
	checkServerSetup(t, validOPRFP384Ciphersuite)
}

func TestServerSetupP521(t *testing.T) {
	checkServerSetup(t, validOPRFP521Ciphersuite)
}

func TestServerEvalP384(t *testing.T) {
	checkServerEval(t, validOPRFP384Ciphersuite)
}

func TestServerEvalP521(t *testing.T) {
	checkServerEval(t, validOPRFP521Ciphersuite)
}

func TestServerEvalVerifiable(t *testing.T) {
	s, err := serverSetup(validVOPRFP384Ciphersuite)
	if err != nil {
		t.Fatal(err)
	}
	pog := s.Ciphersuite().POG()
	_, err = s.Eval(s.SecretKey(), ecgroup.Point{}.New(pog).(ecgroup.Point))
	if err != oErr.ErrOPRFCiphersuiteUnsupportedFunction.Err() {
		t.Fatal("Verfiable Unblind should not be supported yet")
	}
}

func TestServerBlind(t *testing.T) {
	s, err := serverSetup(validOPRFP384Ciphersuite)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = s.Blind([]byte{})
	if err != oErr.ErrOPRFUnimplementedFunctionServer.Err() {
		t.Fatal("Function should be unimplemented")
	}
}

func TestServerUnblind(t *testing.T) {
	s, err := serverSetup(validOPRFP384Ciphersuite)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Unblind(ecgroup.Point{}, new(big.Int))
	if err != oErr.ErrOPRFUnimplementedFunctionServer.Err() {
		t.Fatal("Function should be unimplemented")
	}
}

func TestServerFinalize(t *testing.T) {
	s, err := serverSetup(validOPRFP384Ciphersuite)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Finalize(ecgroup.Point{}, []byte{}, []byte{})
	if err != oErr.ErrOPRFUnimplementedFunctionServer.Err() {
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
	checkClientBlindUnblind(t, validOPRFP384Ciphersuite)
}

func TestClientBlindUnblindP521(t *testing.T) {
	checkClientBlindUnblind(t, validOPRFP521Ciphersuite)
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
	_, err = c.Eval(SecretKey{}, ecgroup.Point{})
	if err != oErr.ErrOPRFUnimplementedFunctionClient.Err() {
		t.Fatal("Function should be unimplemented")
	}
}

func TestClientUnblindVerifiable(t *testing.T) {
	c, err := clientSetup(validVOPRFP384Ciphersuite)
	if err != nil {
		t.Fatal(err)
	}
	pog := c.Ciphersuite().POG()
	ufe, err := pog.UniformFieldElement()
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Unblind(ecgroup.Point{}.New(pog).(ecgroup.Point), ufe)
	if err != oErr.ErrOPRFCiphersuiteUnsupportedFunction.Err() {
		t.Fatal("Verfiable Unblind should not be supported yet")
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

func checkServerEval(t *testing.T, validCiphersuite string) {
	s, err := serverSetup(validOPRFP384Ciphersuite)
	if err != nil {
		t.Fatal(err)
	}
	ciph := s.Ciphersuite()
	pog := ciph.POG()
	x := []byte{1, 2, 3, 4, 6, 7}
	P, err := pog.EncodeToGroup(x)
	if err != nil {
		t.Fatal(err)
	}
	Q, err := s.Eval(s.SecretKey(), P)
	if err != nil {
		t.Fatal(err)
	}
	chkQ, err := P.ScalarMult(s.SecretKey().K)
	if err != nil {
		t.Fatal(err)
	}
	if !Q.Equal(chkQ) {
		t.Fatal("Server evaluation returned inconsistent result")
	}
}

func checkClientBlindUnblind(t *testing.T, validCiphersuite string) {
	c, err := clientSetup(validCiphersuite)
	if err != nil {
		t.Fatal(err)
	}
	x := []byte{1, 2, 3, 4, 5}
	P, blind, err := c.Blind(x)
	if err != nil {
		t.Fatal(err)
	}
	pog := c.Ciphersuite().POG()
	if !P.IsValid() {
		t.Fatal("Blinded point is not valid")
	}
	N, err := c.Unblind(P, blind)
	if err != nil {
		t.Fatal(err)
	}
	chkN, err := pog.EncodeToGroup(x)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, N.Equal(chkN))
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
	_, err = hmacChk.Write(input)
	if err != nil {
		t.Fatal(err)
	}
	dk := hmacChk.Sum(nil)
	hmacOutChk := hmac.New(c.Ciphersuite().H3, dk)
	_, err = hmacOutChk.Write(aux)
	if err != nil {
		t.Fatal(err)
	}
	yChk := hmacOutChk.Sum(nil)
	if !hmac.Equal(y, yChk) {
		t.Fatal("Finalize failed to produce the correct output")
	}
}

func checkFullOPRF(t *testing.T, validCiphersuite string) {
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

	clientInput := []byte{1, 2, 3, 4, 5}
	auxFinal := []byte{6, 7, 8, 9, 10}
	c.pk = s.SecretKey().PubKey

	// compute blinded point
	P, r, err := c.Blind(clientInput)
	if err != nil {
		t.Fatal(err)
	}

	// compute server evaluation
	Q, err := s.Eval(s.SecretKey(), P)
	if err != nil {
		t.Fatal(err)
	}

	// compute client unblinding
	N, err := c.Unblind(Q, r)
	if err != nil {
		t.Fatal(err)
	}

	// compute client finalization
	y, err := c.Finalize(N, clientInput, auxFinal)
	if err != nil {
		t.Fatal(err)
	}

	// compute server finalization
	T, err := s.Ciphersuite().POG().EncodeToGroup(clientInput)
	if err != nil {
		t.Fatal(err)
	}
	Z, err := s.Eval(s.SecretKey(), T)
	if err != nil {
		t.Fatal(err)
	}
	yServer, err := c.Finalize(Z, clientInput, auxFinal)
	if err != nil {
		t.Fatal(err)
	}

	// check that client & server agree
	assert.True(t, hmac.Equal(y, yServer))
}
