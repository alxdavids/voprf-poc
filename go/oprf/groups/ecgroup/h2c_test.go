package ecgroup

import (
	"errors"
	"fmt"
	"math/big"
	"testing"
)

var (
	testInputs = []string{
		"",
		"1",
		"asdf",
		"test",
		"random",
	}

	expectedHashToBaseResponses = map[string](map[string]*big.Int){
		"P-384": map[string](*big.Int){
			"":       getBigIntFromDecString("15670280948239665018787050025088822552903093865230238970017602952833555416398748331082295637805213707088989441755988"),
			"1":      getBigIntFromDecString("1942715482632358166165565369095283869513634648389774012602448122359464835733690346035199729746417427046377204715303"),
			"asdf":   getBigIntFromDecString("24507112164256266255100924053603326775213507976390981967792131453083876194411216719447408537203841824718570787142464"),
			"test":   getBigIntFromDecString("6409376039185531560017287982748544597515854411296193693488280424481644496093326544690902528863962436268623496771541"),
			"random": getBigIntFromDecString("16247250678686872222869936093984092594492729196895879130498408114251281419554923530849483086336127849429159109128818"),
		},
	}

	expectedCurveEncodingResponses = map[string](map[string](map[string](map[string]*big.Int))){
		"P-384": map[string](map[string](map[string]*big.Int)){
			"sswu": map[string](map[string]*big.Int){
				"": map[string]*big.Int{
					"input": getBigIntFromDecString("15670280948239665018787050025088822552903093865230238970017602952833555416398748331082295637805213707088989441755988"),
					"x":     getBigIntFromDecString("15043091655123589139476535520316853145074562564067200072853707836963164937518115020044315814573473606362869394777187"),
					"y":     getBigIntFromDecString("33136250779564189967647894388148954739171786982148515795299597591669909884906353483262749333579115340263403769866626"),
				},
				"1": map[string]*big.Int{
					"input": getBigIntFromDecString("1942715482632358166165565369095283869513634648389774012602448122359464835733690346035199729746417427046377204715303"),
					"x":     getBigIntFromDecString("31712666608794813838450831245768352608061820731219254600083599907999316691595120493791689938289282078353090933837041"),
					"y":     getBigIntFromDecString("4206609551883326717841767788616124592725060605241985514692257065399455065867170452124896082541316335165985229730507"),
				},
				"asdf": map[string]*big.Int{
					"input": getBigIntFromDecString("24507112164256266255100924053603326775213507976390981967792131453083876194411216719447408537203841824718570787142464"),
					"x":     getBigIntFromDecString("293447988360561042611832928522597727479089496568847551940003813796772318506727270172476083341418873730785454701568"),
					"y":     getBigIntFromDecString("9761653435465566913614766398945376337690717880421211083207566458447975999387790669048364346983316135762944196549898"),
				},
				"test": map[string]*big.Int{
					"input": getBigIntFromDecString("6409376039185531560017287982748544597515854411296193693488280424481644496093326544690902528863962436268623496771541"),
					"x":     getBigIntFromDecString("31475109408547543147199457632396492796169708514999370150255421041761202109773477769740788427961884005032653705307760"),
					"y":     getBigIntFromDecString("33864641941997256225600777383976921381186308220482560482046046771370099718859942454304724377098962437161537347141181"),
				},
				"random": map[string]*big.Int{
					"input": getBigIntFromDecString("16247250678686872222869936093984092594492729196895879130498408114251281419554923530849483086336127849429159109128818"),
					"x":     getBigIntFromDecString("37310690097326955526874904412484957930185253899573931562503850700495595096900370544619577329930240463109907820476327"),
					"y":     getBigIntFromDecString("1835534565261005396339419959321852444925359938134835077886551094760311758797304939482177839199023849240736081211984"),
				},
			},
			"full": map[string](map[string]*big.Int){
				"": map[string]*big.Int{
					"x": getBigIntFromDecString("30080611775067838193475075004665419527937570396653956651519246592569896222441582047156381322632437363661635355059005"),
					"y": getBigIntFromDecString("20783652428854690810060531204648743925284619218538801076205938644463325455616369725402399433833851021039801860251878"),
				},
				"1": map[string]*big.Int{
					"x": getBigIntFromDecString("29650639659274268559136011553864194418207682311050323428173462440594796529912091771908609365933993237437866304383610"),
					"y": getBigIntFromDecString("3123044785607009045040711490412599434775424958141229760770582294918664212503090438091817468980366885107838379509098"),
				},
				"asdf": map[string]*big.Int{
					"x": getBigIntFromDecString("29969588127226151911382588418021312873012227179044443716367955445066566752849478826037970129940763289625714821443011"),
					"y": getBigIntFromDecString("17410069451102133321720859095615324374699361853698493986383537650837194987993565478405818082113600644209841551176018"),
				},
				"test": map[string]*big.Int{
					"x": getBigIntFromDecString("35545509722549146939660727050796900115452941653073989167788838920390302482004128874997252970331147295344750824226579"),
					"y": getBigIntFromDecString("27687865874587861560504941570144773748765286782363087596575730017098117334752417380625066587341878521688930304472033"),
				},
				"random": map[string]*big.Int{
					"x": getBigIntFromDecString("21634107956511686237571364665733337762160319624271853087423499351943896659075117271938533968539011259822501269661449"),
					"y": getBigIntFromDecString("24988434919453800168740599843788684084233292688651079542544278337911292329783936136946570334754766549649989066107853"),
				},
			},
		},
	}
)

func TestHashToBaseP384(t *testing.T) {
	curve := P384()
	err := performHashToBase(curve)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSswuP384(t *testing.T) {
	curve := P384()
	err := performSswu(curve)
	if err != nil {
		t.Fatal(err)
	}
}

func TestHashToCurveP384(t *testing.T) {
	curve := P384()
	err := performHashToCurve(curve)
	if err != nil {
		t.Fatal(err)
	}
}

// func TestHashToCurveP521(t *testing.T) {
// 	curve := P521()
// 	err := performHashToCurve(curve)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// }

func performHashToBase(curve GroupCurve) error {
	params, err := getH2CParams(curve)
	if err != nil {
		return err
	}
	for _, alpha := range testInputs {
		uArr, err := params.hashToBaseField([]byte(alpha), 0)
		if err != nil {
			return err
		}

		if len(uArr) != 1 {
			return fmt.Errorf("Only expecting one field element to be returned")
		}
		u := uArr[0]

		// check test vectors
		expected := expectedHashToBaseResponses[curve.Name()][alpha]
		cmp := u.Cmp(expected)
		if cmp != 0 {
			return fmt.Errorf("hash-to-base output for input alpha: %s is incorrect, expected: %s, got: %s", alpha, expected.String(), u.String())
		}
	}
	return nil
}

func performSswu(curve GroupCurve) error {
	params, err := getH2CParams(curve)
	if err != nil {
		return err
	}

	testVectors := expectedCurveEncodingResponses[curve.Name()]["sswu"]
	for _, alpha := range testInputs {
		vectors := testVectors[alpha]
		input := vectors["input"]
		Q, err := params.sswu([]*big.Int{input})
		if err != nil {
			return err
		}

		// check point is valid
		if !Q.IsValid(curve) {
			return errors.New("Failed to generate a valid point")
		}

		// check test vectors
		cmpX := Q.X.Cmp(vectors["x"])
		if cmpX != 0 {
			return fmt.Errorf("X coordinate for alpha: %s is incorrect, expected: %s, got: %s", alpha, vectors["x"].String(), Q.X.String())
		}
		cmpY := Q.Y.Cmp(vectors["y"])
		if cmpY != 0 {
			return fmt.Errorf("Y coordinate for alpha: %s is incorrect, expected: %s, got: %s", alpha, vectors["y"].String(), Q.Y.String())
		}
	}
	return nil
}

// performs hash to curve for each of the test inputs
func performHashToCurve(curve GroupCurve) error {
	params, err := getH2CParams(curve)
	if err != nil {
		return err
	}
	for _, alpha := range testInputs {
		R, err := params.hashToCurve([]byte(alpha))
		if err != nil {
			return err
		}

		// check point is valid
		if !R.IsValid(curve) {
			return errors.New("Failed to generate a valid point")
		}

		// check test vectors
		expected := expectedCurveEncodingResponses[curve.Name()]["full"][alpha]
		cmpX := R.X.Cmp(expected["x"])
		if cmpX != 0 {
			return fmt.Errorf("X coordinate for alpha: %s is incorrect, expected: %s, got: %s", alpha, expected["x"].String(), R.X.String())
		}
		cmpY := R.Y.Cmp(expected["y"])
		if cmpY != 0 {
			return fmt.Errorf("Y coordinate for alpha: %s is incorrect, expected: %s, got: %s", alpha, expected["y"].String(), R.Y.String())
		}
	}
	return nil
}

// getBigIntFromDecString returns a bigint (without success value) from a decimal
// string
func getBigIntFromDecString(s string) *big.Int {
	i, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("error creating big int")
	}
	return i
}
