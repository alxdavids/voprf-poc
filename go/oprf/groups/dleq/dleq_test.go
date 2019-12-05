package dleq

import (
	"fmt"
	"hash"
	"math/big"
	"testing"

	"github.com/alxdavids/oprf-poc/go/oerr"
	gg "github.com/alxdavids/oprf-poc/go/oprf/groups"
	"github.com/alxdavids/oprf-poc/go/oprf/groups/ecgroup"
	"github.com/alxdavids/oprf-poc/go/oprf/utils"
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
	pog, h3, h4, h5, sk, pk, err := setup("P384")
	if err != nil {
		t.Fatal(err)
	}
	batchM := make([]gg.GroupElement, 5)
	batchZ := make([]gg.GroupElement, 5)
	for i := 0; i < len(batchM); i++ {
		batchM[i], batchZ[i], err = generateAndEval(pog, sk, fmt.Sprintf("random_input_%v", i))
		if err != nil {
			t.Fatal(err)
		}
	}
	extraZ, err := pog.EncodeToGroup([]byte("last_element"))
	if err != nil {
		t.Fatal(err)
	}
	badBatchZ := append(batchZ, extraZ)

	_, err = BatchGenerate(pog, h3, h4, h5, sk, pk, batchM, badBatchZ)
	if err != oerr.ErrDLEQInvalidInput {
		t.Fatal(err)
	}

	proof, err := BatchGenerate(pog, h3, h4, h5, sk, pk, batchM, batchZ)
	if err != nil {
		t.Fatal(err)
	}
	if proof.BatchVerify(pog, h3, h4, h5, pk, batchM, badBatchZ) {
		t.Fatal("verification should have failed for bad lengths")
	}
}

func TestBatchedDLEQBadElement(t *testing.T) {
	pog, h3, h4, h5, sk, pk, err := setup("P384")
	if err != nil {
		t.Fatal(err)
	}
	batchM := make([]gg.GroupElement, 5)
	batchZ := make([]gg.GroupElement, 5)
	for i := 0; i < len(batchM); i++ {
		batchM[i], batchZ[i], err = generateAndEval(pog, sk, fmt.Sprintf("random_input_%v", i))
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
	badProof, err := BatchGenerate(pog, h3, h4, h5, sk, pk, batchM, badBatchZ)
	if err != nil {
		t.Fatal(err)
	}
	if badProof.BatchVerify(pog, h3, h4, h5, pk, batchM, badBatchZ) {
		t.Fatal("verification should have failed due to bad element")
	}

	// fail verify for good proof but bad verify input
	proof, err := BatchGenerate(pog, h3, h4, h5, sk, pk, batchM, batchZ)
	if err != nil {
		t.Fatal(err)
	}
	if proof.BatchVerify(pog, h3, h4, h5, pk, batchM, badBatchZ) {
		t.Fatal("verification should have failed for bad input element")
	}
}

func validateDLEQ(t *testing.T, groupName string) {
	pog, h3, _, _, sk, pk, err := setup(groupName)
	if err != nil {
		t.Fatal(err)
	}
	M, Z, err := generateAndEval(pog, sk, "random_input")
	if err != nil {
		t.Fatal(err)
	}

	proof, err := Generate(pog, h3, sk, pk, M, Z)
	if err != nil {
		t.Fatal(err)
	}
	if !proof.Verify(pog, h3, pk, M, Z) {
		t.Fatal("Proof failed to validate")
	}
}

func validateBatchedDLEQ(t *testing.T, groupName string) {
	pog, h3, h4, h5, sk, pk, err := setup(groupName)
	if err != nil {
		t.Fatal(err)
	}
	batchM := make([]gg.GroupElement, 5)
	batchZ := make([]gg.GroupElement, 5)
	for i := 0; i < len(batchM); i++ {
		batchM[i], batchZ[i], err = generateAndEval(pog, sk, fmt.Sprintf("random_input_%v", i))
		if err != nil {
			t.Fatal(err)
		}
	}

	proof, err := BatchGenerate(pog, h3, h4, h5, sk, pk, batchM, batchZ)
	if err != nil {
		t.Fatal(err)
	}
	if !proof.BatchVerify(pog, h3, h4, h5, pk, batchM, batchZ) {
		t.Fatal("Batch proof failed to verify")
	}
}

func generateAndEval(pog gg.PrimeOrderGroup, sk *big.Int, lbl string) (gg.GroupElement, gg.GroupElement, error) {
	M, err := pog.EncodeToGroup([]byte(lbl))
	if err != nil {
		return nil, nil, err
	}
	Z, err := M.ScalarMult(sk)
	if err != nil {
		return nil, nil, err
	}
	return M, Z, nil
}

func setup(groupName string) (gg.PrimeOrderGroup, hash.Hash, hash.Hash, utils.ExtractorExpander, *big.Int, gg.GroupElement, error) {
	ciphName := fmt.Sprintf("VOPRF-%s-HKDF-SHA512-SSWU-RO", groupName)
	ciph, err := gg.Ciphersuite{}.FromString(ciphName, ecgroup.GroupCurve{})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	pog := ciph.POG()
	h3 := ciph.H3()
	h4 := ciph.H4()
	h5 := ciph.H5()
	sk, err := pog.UniformFieldElement()
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	pk, err := pog.GeneratorMult(sk)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	return pog, h3, h4, h5, sk, pk, nil
}
