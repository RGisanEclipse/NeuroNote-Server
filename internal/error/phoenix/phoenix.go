package phoenix

type PhoenixError struct {
	EmailDeliveryFailed string
}

var PhoenixErrorMessages = PhoenixError{
	EmailDeliveryFailed: "failed to deliver email",
}