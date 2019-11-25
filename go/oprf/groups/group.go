package groups

import (
	"fmt"
	"math/big"
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

// PrimeOrderGroup is an interface that defines operations within a mathematical
// groups of prime order
type PrimeOrderGroup interface {
	Generator() GroupElement
	Order() *big.Int
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
