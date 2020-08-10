package ecgroup

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"
	"testing"

	gg "github.com/alxdavids/voprf-poc/go/oprf/groups"
)

type hashToCurveTestVectors struct {
	DST     string       `json:"dst"`
	Vectors []testVector `json:"vectors"`
}

type testVector struct {
	P   expectedPoint `json:"P"`
	Msg string        `json:"msg"`
}

type expectedPoint struct {
	X string `json:"x"`
	Y string `json:"y"`
}

func TestHashToCurveP384(t *testing.T) {
	curve := initCurve(t, gg.GROUP_CURVE448)
	buf, err := ioutil.ReadFile("../../../../test-vectors/hash-to-curve/P384_XMD:SHA-512_SSWU_RO_.json")
	if err != nil {
		t.Fatal(err)
	}
	testVectors := hashToCurveTestVectors{}
	err = json.Unmarshal(buf, &testVectors)
	if err != nil {
		t.Fatal(err)
	}
	err = performHashToCurve(curve, testVectors)
	if err != nil {
		t.Fatal(err)
	}
}

func TestHashToCurveP521(t *testing.T) {
	curve := initCurve(t, gg.GROUP_P521)
	buf, err := ioutil.ReadFile("../../../../test-vectors/hash-to-curve/P521_XMD:SHA-512_SSWU_RO_.json")
	if err != nil {
		t.Fatal(err)
	}
	testVectors := hashToCurveTestVectors{}
	err = json.Unmarshal(buf, &testVectors)
	if err != nil {
		t.Fatal(err)
	}
	err = performHashToCurve(curve, testVectors)
	if err != nil {
		t.Fatal(err)
	}
}

func TestHashToCurve448(t *testing.T) {
	curve := initCurve(t, gg.GROUP_CURVE448)
	buf, err := ioutil.ReadFile("../../../../test-vectors/hash-to-curve/curve448_XMD:SHA-512_ELL2_RO_.json")
	if err != nil {
		t.Fatal(err)
	}
	testVectors := hashToCurveTestVectors{}
	err = json.Unmarshal(buf, &testVectors)
	if err != nil {
		t.Fatal(err)
	}
	err = performHashToCurve(curve, testVectors)
	if err != nil {
		t.Fatal(err)
	}
}

// performHashToCurve performs full hash-to-curve for each of the test inputs
// and checks against expected responses
func performHashToCurve(curve GroupCurve, testVectors hashToCurveTestVectors) error {
	hasher, err := getH2CSuiteWithDST(curve, []byte(testVectors.DST))
	if err != nil {
		return err
	}
	hasherMod := hasher.(hasher2point)
	for _, v := range testVectors.Vectors {
		R, err := hasherMod.Hash([]byte(v.Msg))
		if err != nil {
			return err
		}

		// check point is valid
		if !R.IsValid() {
			return errors.New("Failed to generate a valid point")
		}

		// check test vectors
		// remove prefix
		x := strings.Replace(v.P.X, "0x", "", 1)
		y := strings.Replace(v.P.Y, "0x", "", 1)
		expectedX, err := hex.DecodeString(x)
		if err != nil {
			return err
		}
		expectedY, err := hex.DecodeString(y)
		if err != nil {
			return err
		}
		chkR := Point{X: new(big.Int).SetBytes(expectedX), Y: new(big.Int).SetBytes(expectedY), pog: curve, compress: true}
		if !R.Equal(chkR) {
			fmt.Printf("\n expected X in hex %x \n", x)
			fmt.Printf("\n expected Y in hex %x \n", y)
			fmt.Printf("\n X in hex %x \n", hex.EncodeToString(R.X.Bytes()))
			fmt.Printf("\n Y in hex %x \n", hex.EncodeToString(R.Y.Bytes()))
			return errors.New("Points are not equal")
		}
	}
	return nil
}

func BenchmarkHashToCurveP384(b *testing.B) {
	benchmarkHashToCurve(b, benchInitCurve(b, gg.GROUP_CURVE448))
}

func BenchmarkHashToCurveP521(b *testing.B) {
	benchmarkHashToCurve(b, benchInitCurve(b, gg.GROUP_P521))
}

func BenchmarkHashToCurveC448(b *testing.B) {
	benchmarkHashToCurve(b, benchInitCurve(b, gg.GROUP_CURVE448))
}

func benchmarkHashToCurve(b *testing.B, curve GroupCurve) {
	hasher, err := getH2CSuite(curve)
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 512)
	_, err = rand.Read(msg)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = hasher.Hash(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func benchInitCurve(b *testing.B, curveID int) GroupCurve {
	gg, err := GroupCurve{}.New(curveID)
	if err != nil {
		b.Fatal(err)
	}
	curve, err := castToCurve(gg)
	if err != nil {
		b.Fatal(err)
	}
	return curve
}
