package dleq

import (
	"fmt"
	"testing"

	"github.com/alxdavids/oprf-poc/go/oprf"
	gg "github.com/alxdavids/oprf-poc/go/oprf/groups"
	"github.com/alxdavids/oprf-poc/go/oprf/groups/ecgroup"
)

func TestValidDLEQP384(t *testing.T) {
	validateDLEQ(t, "P384")
}

func TestValidDLEQP521(t *testing.T) {
	validateDLEQ(t, "P521")
}

func TestValidBatchedDLEQP384(t *testing.T) {
	validateBatchedDLEQ(t, "P384")
}

func TestValidBatchedDLEQP521(t *testing.T) {
	validateBatchedDLEQ(t, "P521")
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
	M, Z, err := generateAndEval(srv, pog, "random_input")
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

func validateBatchedDLEQ(t *testing.T, groupName string) {
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
	h3 := ciph.H3()
	h4 := ciph.H4()
	h5 := ciph.H5()
	sk := srv.SecretKey()
	batchM := make([]gg.GroupElement, 5)
	batchZ := make([]gg.GroupElement, 5)
	for i := 0; i < len(batchM); i++ {
		batchM[i], batchZ[i], err = generateAndEval(srv, pog, fmt.Sprintf("random_input_%v", i))
		if err != nil {
			t.Fatal(err)
		}
	}

	proof, err := BatchGenerate(pog, h3, h4, h5, sk.K, sk.PubKey, batchM, batchZ)
	if err != nil {
		t.Fatal(err)
	}
	if !proof.BatchVerify(pog, h3, h4, h5, sk.PubKey, batchM, batchZ) {
		t.Fatal("Batch proof failed to verify")
	}
}

func generateAndEval(srv oprf.Server, pog gg.PrimeOrderGroup, lbl string) (gg.GroupElement, gg.GroupElement, error) {
	M, err := pog.EncodeToGroup([]byte(lbl))
	if err != nil {
		return nil, nil, err
	}
	Z, err := srv.Eval(M)
	if err != nil {
		return nil, nil, err
	}
	return M, Z, nil
}
