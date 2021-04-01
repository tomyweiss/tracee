package model

type Input struct {
	RulesDir           string
	Rules              []string
	Tracee             []string
	Webhook            string
	WebhookTemplate    string
	WebhookContentType string
	List               bool
	OutputTemplate     string
}
