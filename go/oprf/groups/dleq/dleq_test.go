package dleq

import (
	"fmt"
	"testing"

	"github.com/alxdavids/oprf-poc/go/oprf"
	"github.com/alxdavids/oprf-poc/go/oprf/groups/ecgroup"
)

func TestValidDLEQP384(t *testing.T) {
	validateDLEQ(t, "P384")
}

func validateDLEQ(t *testing.T, groupName string) {
	ciphName := fmt.Sprintf("VOPRF-%s-HKDF-SHA512-SSWU-RO", groupName)
	ptpnt, err := oprf.Server{}.Setup(ciphName, ecgroup.GroupCurve{})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := oprf.CastServer(ptpnt)
	if err != nil {
		t.Fatal(err)
	}
	ciph := srv.Ciphersuite()
	pog := ciph.POG()
	h := ciph.H3()
	sk := srv.SecretKey()
	M, err := pog.EncodeToGroup([]byte("random_input"))
	if err != nil {
		t.Fatal(err)
	}
	Z, err := srv.Eval(M)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := Generate(pog, h, sk.K, sk.PubKey, M, Z)
	if err != nil {
		t.Fatal(err)
	}
	if !proof.Verify(pog, h, sk.PubKey, M, Z) {
		t.Fatal("Proof failed to validate")
	}
}
