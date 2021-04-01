package initlogic

import (
	"fmt"
	"os"

	"github.com/aquasecurity/tracee/tracee-ebpf/tests/engine"
	"github.com/aquasecurity/tracee/tracee-ebpf/tests/input"
	"github.com/aquasecurity/tracee/tracee-ebpf/tests/model"
	"github.com/aquasecurity/tracee/tracee-ebpf/tests/output"
	"github.com/aquasecurity/tracee/tracee-ebpf/tests/signature"
	"github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"
)

func InitPackageMode() (chan external.Event, error) {
	inputData := model.Input{
		RulesDir:           "",
		Rules:              nil,
		Tracee:             []string{"goChannel:goChannel"},
		Webhook:            "",
		WebhookTemplate:    "",
		WebhookContentType: "",
		List:               false,
		OutputTemplate:     "",
	}

	o, err := InitTraceeRules(inputData)
	return o.ProducerChannel, err
}

func InitTraceeRules(c model.Input) (input.TraceeInputOptions, error) {
	sigs, err := signature.GetSignatures(c.RulesDir, c.Rules)
	if err != nil {
		return input.TraceeInputOptions{}, err
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
		return input.TraceeInputOptions{}, signature.ListSigs(os.Stdout, sigs)
	}

	var inputs engine.EventSources
	opts, err := input.ParseTraceeInputOptions(c.Tracee)
	if err == input.ErrHelp {
		input.PrintHelp()
		return input.TraceeInputOptions{}, nil
	}
	if err != nil {
		return input.TraceeInputOptions{}, err
	}
	inputs.Tracee, err = input.SetupTraceeInputSource(opts)
	if err != nil {
		return input.TraceeInputOptions{}, err
	}

	if inputs == (engine.EventSources{}) {
		return input.TraceeInputOptions{}, err
	}

	output, err := output.SetupOutput(os.Stdout, c.Webhook, c.WebhookTemplate, c.WebhookContentType, c.OutputTemplate)
	if err != nil {
		return input.TraceeInputOptions{}, err
	}
	e := engine.NewEngine(sigs, inputs, output, os.Stderr)
	e.Start(signature.SigHandler())
	return *opts, nil
}
