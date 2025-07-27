package types

type TypeErrorMessages struct {
	TypeCastingError string
}

var TypeError = TypeErrorMessages{
	TypeCastingError: "Type casting error occurred",
}