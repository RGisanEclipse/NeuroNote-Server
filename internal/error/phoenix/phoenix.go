package phoenix

type Error struct {
	EmailDeliveryFailed string
}

var ErrorMessages = Error{
	EmailDeliveryFailed: "failed to deliver email",
}
