package groups

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"hash"
	"math/big"
	"reflect"
	"strings"

	oc "github.com/alxdavids/oprf-poc/go/oprf/oprfCrypto"
)

var (
	// ErrUnsupportedGroup indicates that the requested group is not supported
	// the current implementation
	ErrUnsupportedGroup error = fmt.Errorf("The chosen group is not supported")
	// ErrUnsupportedEE indicates that the requested ExtractorExpander is not
	// supported.
	ErrUnsupportedEE error = fmt.Errorf("The chosen ExtractorExpander function is not supported, currently supported functions: [HKDF]")
	// ErrUnsupportedHash indicates that the requested function is not
	// supported.
	ErrUnsupportedHash error = fmt.Errorf("The chosen hash function is not supported, currently supported functions: [SHA512]")
	// ErrUnsupportedH2C indicates that the requested hash-to-curve function is
	// not supported.
	ErrUnsupportedH2C error = fmt.Errorf("The chosen hash-to-curve function is not supported, currently supported functions: [SSWU-RO (for NIST curves)]")
	// ErrIncompatibleGroupParams indicates that the requested group has a
	// parameter setting that is incompatible with our implementation
	ErrIncompatibleGroupParams error = fmt.Errorf("The chosen group has an incompatible parameter setting")
	// ErrInvalidGroupElement indicates that the element in possession is not
	// a part of the expected group
	ErrInvalidGroupElement error = fmt.Errorf("Group element is invalid")
	// ErrDeserializing indicates that the conversion of an octet-string into a
	// group element has failed
	ErrDeserializing error = fmt.Errorf("Error deserializing group element from octet string")
	// ErrInternalInstantiation indicates that an error occurred when attempting to
	// instantiate the group
	ErrInternalInstantiation error = fmt.Errorf("Internal error occurred with internal group instantiation")
)

// Ciphersuite corresponds to the OPRF ciphersuite that is chosen
//
// Even though groups == curves, we keep the abstraction to fit with curve
// implementations
type Ciphersuite struct {
	name       string
	pog        PrimeOrderGroup
	hash1      func([]byte) (GroupElement, error)
	hash2      func(func() hash.Hash, []byte) hash.Hash
	hash3      hash.Hash
	hash4      hash.Hash
	hash5      oc.ExtractorExpander
	verifiable bool
}

// FromString derives a ciphersuite from the string that was provided,
// corresponding to a given PrimeOrderGroup implementation
func (c Ciphersuite) FromString(s string, pog PrimeOrderGroup) (Ciphersuite, error) {
	split := strings.Split(s, "-")

	// construct the PrimeOrderGroup object
	var pogNew PrimeOrderGroup
	switch split[1] {
	case "P384":
		pogNew = pog.New("P-384")
		break
	case "P521":
		pogNew = pog.New("P-521")
		break
	default:
		return Ciphersuite{}, ErrUnsupportedGroup
	}

	// Check ExtractorExpander{} is supported (only HKDF currently)
	switch split[2] {
	case "HKDF":
		if reflect.TypeOf(pogNew.EE()).Name() != "HKDFExtExp" {
			return Ciphersuite{}, ErrUnsupportedEE
		}
		break
	default:
		return Ciphersuite{}, ErrUnsupportedEE
	}

	// check hash function support
	switch split[3] {
	case "SHA-512":
		if pog.Hash() != sha512.New() {
			return Ciphersuite{}, ErrUnsupportedHash
		}
		break
	default:
		return Ciphersuite{}, ErrUnsupportedHash
	}

	// check hash-to-curve support
	switch split[4] {
	case "SSWU-RO":
		// do nothing
		break
	default:
		return Ciphersuite{}, ErrUnsupportedH2C
	}

	// derive Ciphersuite object
	h1 := pogNew.EncodeToGroup
	h2 := hmac.New
	h3 := pogNew.Hash()
	h4 := pogNew.Hash()
	var h5 oc.ExtractorExpander
	verifiable := false
	if split[0] == "VOPRF" {
		verifiable = true
		h5 = pogNew.EE()
	}
	return Ciphersuite{
		name:       s,
		pog:        pogNew,
		hash1:      h1,
		hash2:      h2,
		hash3:      h3,
		hash4:      h4,
		hash5:      h5,
		verifiable: verifiable,
	}, nil
}

// PrimeOrderGroup is an interface that defines operations within a mathematical
// groups of prime order
type PrimeOrderGroup interface {
	New(string) PrimeOrderGroup
	Name() string
	Generator() GroupElement
	GeneratorMult(*big.Int) (GroupElement, error)
	Order() *big.Int
	ByteLength() int
	EncodeToGroup([]byte) (GroupElement, error)
	Hash() hash.Hash
	EE() oc.ExtractorExpander
}

// GroupElement is the interface that represents group elements in a given Group
// instantiation
type GroupElement interface {
	IsValid(PrimeOrderGroup) bool
	ScalarMult(PrimeOrderGroup, *big.Int) error
	Add(PrimeOrderGroup, GroupElement) error
	Serialize(PrimeOrderGroup) []byte
	Deserialize(PrimeOrderGroup) (GroupElement, error)
}
