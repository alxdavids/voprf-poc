package groups

import (
	"fmt"
	"hash"
	"math/big"
	"strings"

	oc "github.com/alxdavids/oprf-poc/go/oprf/oprfCrypto"
)

var (
	// ErrUnsupportedGroup indicates that the requested group is not supported
	// the current implementation
	ErrUnsupportedGroup error = fmt.Errorf("The chosen group is not supported")
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
	name  string
	pog   PrimeOrderGroup
	hash1 func([]byte) (GroupElement, error)
	hash2 oc.ExtractorExpander
	hash3 hash.Hash
	hash4 hash.Hash
	hash5 string
}

// FromString derives a ciphersuite from the string that was provided
func (c Ciphersuite) FromString(s string) Ciphersuite {
	split := strings.Split(s, "-")
	return Ciphersuite{}
}

// PrimeOrderGroup is an interface that defines operations within a mathematical
// groups of prime order
type PrimeOrderGroup interface {
	Generator() GroupElement
	GeneratorMult(*big.Int) (GroupElement, error)
	Order() *big.Int
	ByteLength() int
	EncodeToGroup([]byte) (GroupElement, error)
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
