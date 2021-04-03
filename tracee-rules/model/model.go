package model

type RulesConfig struct {
	RulesDir           string
	Rules              []string
	InputMethods       []string
	Webhook            string
	WebhookTemplate    string
	WebhookContentType string
	OutputTemplate     string
	ListRules          bool
}
