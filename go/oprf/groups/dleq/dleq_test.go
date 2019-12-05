package dleq

import (
	"fmt"
	"testing"

	"github.com/alxdavids/oprf-poc/go/oerr"
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

func TestBatchedDLEQInvalidLengths(t *testing.T) {
	ciphName := fmt.Sprintf("VOPRF-%s-HKDF-SHA512-SSWU-RO", "P384")
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
	extraZ, err := pog.EncodeToGroup([]byte("last_element"))
	if err != nil {
		t.Fatal(err)
	}
	badBatchZ := append(batchZ, extraZ)

	_, err = BatchGenerate(pog, h3, h4, h5, sk.K, sk.PubKey, batchM, badBatchZ)
	if err != oerr.ErrDLEQInvalidInput {
		t.Fatal(err)
	}

	proof, err := BatchGenerate(pog, h3, h4, h5, sk.K, sk.PubKey, batchM, batchZ)
	if err != nil {
		t.Fatal(err)
	}
	if proof.BatchVerify(pog, h3, h4, h5, sk.PubKey, batchM, badBatchZ) {
		t.Fatal("verification should have failed for bad lengths")
	}
}

func TestBatchedDLEQBadElement(t *testing.T) {
	ciphName := fmt.Sprintf("VOPRF-%s-HKDF-SHA512-SSWU-RO", "P384")
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

	// create bad element
	badZ, err := pog.EncodeToGroup([]byte("bad_element"))
	if err != nil {
		t.Fatal(err)
	}
	badBatchZ := batchM
	badBatchZ[2] = badZ

	// fail verify for bad proof
	badProof, err := BatchGenerate(pog, h3, h4, h5, sk.K, sk.PubKey, batchM, badBatchZ)
	if err != nil {
		t.Fatal(err)
	}
	if badProof.BatchVerify(pog, h3, h4, h5, sk.PubKey, batchM, badBatchZ) {
		t.Fatal("verification should have failed due to bad element")
	}

	// fail verify for good proof but bad verify input
	proof, err := BatchGenerate(pog, h3, h4, h5, sk.K, sk.PubKey, batchM, batchZ)
	if err != nil {
		t.Fatal(err)
	}
	if proof.BatchVerify(pog, h3, h4, h5, sk.PubKey, batchM, badBatchZ) {
		t.Fatal("verification should have failed for bad input element")
	}
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
