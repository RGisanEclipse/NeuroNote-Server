package phoenix

type EmailTemplate struct {
	Type        string 
	Subject     string
	BodyHTML    string
	BodyText    string
	Description string	// A brief description of the email template
}