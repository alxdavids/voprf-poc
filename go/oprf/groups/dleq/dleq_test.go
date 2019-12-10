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
	pog, h3, h4, h5, sk, pk, batchM, batchZ, proof, err := createBatchedProof("P384", 5)
	if err != nil {
		t.Fatal(err)
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
	if proof.BatchVerify(pog, h3, h4, h5, pk, batchM, badBatchZ) {
		t.Fatal("verification should have failed for bad lengths")
	}
}

func TestBatchedDLEQBadElement(t *testing.T) {
	pog, h3, h4, h5, sk, pk, batchM, _, proof, err := createBatchedProof("P384", 5)
	if err != nil {
		t.Fatal(err)
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
	if proof.BatchVerify(pog, h3, h4, h5, pk, batchM, badBatchZ) {
		t.Fatal("verification should have failed for bad input element")
	}
}

func validateDLEQ(t *testing.T, groupName string) {
	pog, h3, _, pk, M, Z, proof, err := createProof(groupName)
	if err != nil {
		t.Fatal(err)
	}
	if !proof.Verify(pog, h3, pk, M, Z) {
		t.Fatal("Proof failed to validate")
	}
}

func validateBatchedDLEQ(t *testing.T, groupName string) {
	pog, h3, h4, h5, _, pk, batchM, batchZ, proof, err := createBatchedProof(groupName, 5)
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

func createProof(groupName string) (gg.PrimeOrderGroup, hash.Hash, *big.Int, gg.GroupElement, gg.GroupElement, gg.GroupElement, Proof, error) {
	pog, h3, _, _, sk, pk, err := setup(groupName)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, Proof{}, err
	}
	M, Z, err := generateAndEval(pog, sk, "random_input")
	if err != nil {
		return nil, nil, nil, nil, nil, nil, Proof{}, err
	}

	proof, err := Generate(pog, h3, sk, pk, M, Z)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, Proof{}, err
	}
	return pog, h3, sk, pk, M, Z, proof, nil
}

func createBatchedProof(groupName string, n int) (gg.PrimeOrderGroup, hash.Hash, hash.Hash, utils.ExtractorExpander, *big.Int, gg.GroupElement, []gg.GroupElement, []gg.GroupElement, Proof, error) {
	pog, h3, h4, h5, sk, pk, err := setup("P384")
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, Proof{}, err
	}
	batchM := make([]gg.GroupElement, n)
	batchZ := make([]gg.GroupElement, n)
	for i := 0; i < n; i++ {
		batchM[i], batchZ[i], err = generateAndEval(pog, sk, fmt.Sprintf("random_input_%v", i))
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, nil, Proof{}, err
		}
	}

	proof, err := BatchGenerate(pog, h3, h4, h5, sk, pk, batchM, batchZ)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, Proof{}, err
	}

	return pog, h3, h4, h5, sk, pk, batchM, batchZ, proof, nil
}

/**
 * Benchmarks
 */

func BenchmarkGenerateP384(b *testing.B) {
	benchGenerate(b, "P384")
}

func BenchmarkGenerateP521(b *testing.B) {
	benchGenerate(b, "P521")
}

func benchGenerate(b *testing.B, groupName string) {
	pog, h3, sk, pk, M, Z, _, err := createProof(groupName)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		_, err := Generate(pog, h3, sk, pk, M, Z)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyP384(b *testing.B) {
	benchVerify(b, "P384")
}

func BenchmarkVerifyP521(b *testing.B) {
	benchVerify(b, "P521")
}

func benchVerify(b *testing.B, groupName string) {
	pog, h3, _, pk, M, Z, proof, err := createProof(groupName)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		if !proof.Verify(pog, h3, pk, M, Z) {
			b.Fatal("bad verification")
		}
	}
}

func BenchmarkGenerateP384_2(b *testing.B) {
	benchBatchedGenerate(b, "P384", 2)
}

func BenchmarkGenerateP384_5(b *testing.B) {
	benchBatchedGenerate(b, "P384", 5)
}

func BenchmarkGenerateP384_10(b *testing.B) {
	benchBatchedGenerate(b, "P384", 10)
}

func BenchmarkGenerateP384_25(b *testing.B) {
	benchBatchedGenerate(b, "P384", 25)
}

func BenchmarkGenerateP384_50(b *testing.B) {
	benchBatchedGenerate(b, "P384", 50)
}

func BenchmarkGenerateP384_100(b *testing.B) {
	benchBatchedGenerate(b, "P384", 100)
}

func BenchmarkGenerateP521_2(b *testing.B) {
	benchBatchedGenerate(b, "P521", 2)
}

func BenchmarkGenerateP521_5(b *testing.B) {
	benchBatchedGenerate(b, "P521", 5)
}

func BenchmarkGenerateP521_10(b *testing.B) {
	benchBatchedGenerate(b, "P521", 10)
}

func BenchmarkGenerateP521_25(b *testing.B) {
	benchBatchedGenerate(b, "P521", 25)
}

func BenchmarkGenerateP521_50(b *testing.B) {
	benchBatchedGenerate(b, "P521", 50)
}

func BenchmarkGenerateP521_100(b *testing.B) {
	benchBatchedGenerate(b, "P521", 100)
}

func benchBatchedGenerate(b *testing.B, groupName string, n int) {
	pog, h3, h4, h5, sk, pk, batchM, batchZ, _, err := createBatchedProof(groupName, n)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		_, err = BatchGenerate(pog, h3, h4, h5, sk, pk, batchM, batchZ)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyP384_2(b *testing.B) {
	benchBatchedVerify(b, "P384", 2)
}

func BenchmarkVerifyP384_5(b *testing.B) {
	benchBatchedVerify(b, "P384", 5)
}

func BenchmarkVerifyP384_10(b *testing.B) {
	benchBatchedVerify(b, "P384", 10)
}

func BenchmarkVerifyP384_25(b *testing.B) {
	benchBatchedVerify(b, "P384", 25)
}

func BenchmarkVerifyP384_50(b *testing.B) {
	benchBatchedVerify(b, "P384", 50)
}

func BenchmarkVerifyP384_100(b *testing.B) {
	benchBatchedVerify(b, "P384", 100)
}

func BenchmarkVerifyP521_2(b *testing.B) {
	benchBatchedVerify(b, "P521", 2)
}

func BenchmarkVerifyP521_5(b *testing.B) {
	benchBatchedVerify(b, "P521", 5)
}

func BenchmarkVerifyP521_10(b *testing.B) {
	benchBatchedVerify(b, "P521", 10)
}

func BenchmarkVerifyP521_25(b *testing.B) {
	benchBatchedVerify(b, "P521", 25)
}

func BenchmarkVerifyP521_50(b *testing.B) {
	benchBatchedVerify(b, "P521", 50)
}

func BenchmarkVerifyP521_100(b *testing.B) {
	benchBatchedVerify(b, "P521", 100)
}

func benchBatchedVerify(b *testing.B, groupName string, n int) {
	pog, h3, h4, h5, _, pk, batchM, batchZ, proof, err := createBatchedProof(groupName, n)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		if !proof.BatchVerify(pog, h3, h4, h5, pk, batchM, batchZ) {
			b.Fatal("bad batch verification")
		}
	}
}
