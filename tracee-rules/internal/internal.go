package internal

import (
	"fmt"
	"os"

	"github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"
	"github.com/aquasecurity/tracee/tracee-rules/engine"
	"github.com/aquasecurity/tracee/tracee-rules/input"
	"github.com/aquasecurity/tracee/tracee-rules/model"
	"github.com/aquasecurity/tracee/tracee-rules/output"
	"github.com/aquasecurity/tracee/tracee-rules/signature"
)

func InitPackageMode(inputChan chan []byte) (chan external.Event, error) {
	inputData := model.Input{
		RulesDir:           "",
		Rules:              nil,
		Tracee:             []string{"goChannel"},
		Webhook:            "",
		WebhookTemplate:    "",
		WebhookContentType: "",
		List:               false,
		OutputTemplate:     "",
	}

	o, err := InitTraceeRules(inputData)
	return o.ProducerChannel, err
}

func InitTraceeRules(c model.Input) (*input.TraceeInputOptions, error) {
	sigs, err := signature.GetSignatures(c.RulesDir, c.Rules)
	if err != nil {
		return nil, err
	}

	var loadedSigIDs []string
	for _, s := range sigs {
		m, err := s.GetMetadata()
		if err != nil {
			fmt.Println("failed to load signature: ", err)
			continue
		}
		loadedSigIDs = append(loadedSigIDs, m.ID)
	}

	fmt.Println("Loaded signature(s): ", loadedSigIDs)

	if c.List {
		return nil, signature.ListSigs(os.Stdout, sigs)
	}

	var inputs engine.EventSources
	opts, err := input.ParseTraceeInputOptions(c.Tracee)
	if err == input.ErrHelp {
		input.PrintHelp()
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	inputs.Tracee, err = input.SetupTraceeInputSource(opts)
	if err != nil {
		return nil, err
	}

	if inputs == (engine.EventSources{}) {
		return nil, err
	}

	output, err := output.SetupOutput(os.Stdout, c.Webhook, c.WebhookTemplate, c.WebhookContentType, c.OutputTemplate)
	if err != nil {
		return nil, err
	}
	e := engine.NewEngine(sigs, inputs, output, os.Stderr)
	e.Start(signature.SigHandler())
	return opts, nil
}
