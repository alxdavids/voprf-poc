package ecgroup

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/alxdavids/voprf-poc/go/oprf/utils"
	"github.com/cloudflare/circl/ecc/p384"
)

type hashToCurveTestVectors struct {
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
	curve := CreateNistCurve(p384.P384(), sha512.New(), utils.HKDFExtExp{})
	buf, err := ioutil.ReadFile("../../../../test-vectors/hash-to-curve/p384-sha512-sswu-ro-.json")
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
	curve := CreateNistCurve(elliptic.P521(), sha512.New(), utils.HKDFExtExp{})
	dir, _ := os.Getwd()
	fmt.Println(dir)
	buf, err := ioutil.ReadFile("../../../../test-vectors/hash-to-curve/p521-sha512-sswu-ro-.json")
	if err != nil {
		t.Fatal(err)
	}
<<<<<<< HEAD
	testVectors := hashToCurveTestVectors{}
	err = json.Unmarshal(buf, &testVectors)
=======
}

// These test vectors come from running
// https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/tree/master/poc
func TestEll2Curve448(t *testing.T) {
	curve := CreateCurve448(sha512.New(), utils.HKDFExtExp{})

	params, err := getH2CParams(curve)
	if err != nil {
		t.Fatal(err)
	}

	u, expU, expV := new(big.Int), new(big.Int), new(big.Int)
	u, _ = new(big.Int).SetString("531158213341481379438720561479166615757974252368106701931706243386594190504906772737779341137470819502538803513642877478909898080924700", 10)
	expU, _ = new(big.Int).SetString("475059367077818289758128910667396262190262234593598384316194642461546019506295030165533250828462826885463026651453766395722384985774943", 10)
	expV, _ = new(big.Int).SetString("374637763660393560818954983911528203279792857929498786368575860891959417533586012673301497308795212099780024735615233510543266766975738", 10)

	arr := []*big.Int{u}
	P, err := params.elligator2(arr)
	if err != nil {
		t.Fatal(err)
	}

	// check point is valid
	if !P.IsValid() {
		t.Fatal(err)
	}

	Q := Point{X: expU, Y: expV, pog: curve, compress: true}
	if !P.Equal(Q) {
		t.Fatal(err)
	}

	u, _ = new(big.Int).SetString("13286549665757675293110799743048869076811080173393053961806622826876856717004552933535923204521163438500332014368881740553999164062862", 10)
	expU, _ = new(big.Int).SetString("676823903729580992730290093819255051434774712407078465391179438953583600246952395190617150144373540186129895370849032085748480009405615", 10)
	expV, _ = new(big.Int).SetString("573002640115363041401045831713929918805259451095374773704372739049170404387928384413020573223078356788570345499697397900680655401975544", 10)

	arr = []*big.Int{u}
	P, err = params.elligator2(arr)
	if err != nil {
		t.Fatal(err)
	}

	// check point is valid
	if !P.IsValid() {
		t.Fatal(err)
	}

	Q = Point{X: expU, Y: expV, pog: curve, compress: true}
	if !P.Equal(Q) {
		t.Fatal(err)
	}

	u, _ = new(big.Int).SetString("65794201449915909195162482323557946028316250977501987402800747419941972621011984880029106987314603408049670541154930026746639891120679", 10)
	expU, _ = new(big.Int).SetString("519893819735499894756511465827647092157452391919753080921537124773807642984081599517868062928846779989242762286761148060085026375409121", 10)
	expV, _ = new(big.Int).SetString("602848029033798841945752448963295438634920082080698374368962120810443354157395268760073202605429244928907133690884408947460828569030989", 10)

	arr = []*big.Int{u}
	P, err = params.elligator2(arr)
	if err != nil {
		t.Fatal(err)
	}

	// check point is valid
	if !P.IsValid() {
		t.Fatal(err)
	}

	Q = Point{X: expU, Y: expV, pog: curve, compress: true}
	if !P.Equal(Q) {
		t.Fatal(err)
	}
}

// performHashToBase performs full hash-to-base for each of the test inputs and
// checks against expected responses
func performHashToBase(curve GroupCurve) error {
	params, err := getH2CParams(curve)
>>>>>>> Implement elligator2 for curve448 and add first test from sage output #9
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
	hasher, err := getH2CSuite(curve)
	if err != nil {
		return err
	}
	hasherMod := hasher.(hasher2point)
	hasherMod.dst = []byte("QUUX-V01-CS02")
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
			fmt.Println(x)
			fmt.Println(y)
			fmt.Println(hex.EncodeToString(R.X.Bytes()))
			fmt.Println(hex.EncodeToString(R.Y.Bytes()))
			return errors.New("Points are not equal")
		}
	}
	return nil
}

func BenchmarkHashToCurveP384(b *testing.B) {
	benchmarkHashToCurve(b, CreateNistCurve(p384.P384(), sha512.New(), utils.HKDFExtExp{}))
}

func BenchmarkHashToCurveP521(b *testing.B) {
	benchmarkHashToCurve(b, CreateNistCurve(p384.P384(), sha512.New(), utils.HKDFExtExp{}))
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
