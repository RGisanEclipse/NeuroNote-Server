package phoenix

type BrevoRequest struct {
	Sender BrevoContact
	To BrevoContact
	Subject string
	HTMLContent string
}

type BrevoContact struct{
	Name string
	Email string
}