package initlogic

import (
	"github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"
	"github.com/aquasecurity/tracee/tracee-rules/input"
	"github.com/aquasecurity/tracee/tracee-rules/model"
)

func InitPackageMode() (chan external.Event, error) {
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
	//sigs, err := GetSignatures(c.RulesDir, c.Rules)
	//if err != nil {
	//	return nil, err
	//}
	//
	//var loadedSigIDs []string
	//for _, s := range sigs {
	//	m, err := s.GetMetadata()
	//	if err != nil {
	//		fmt.Println("failed to load signature: ", err)
	//		continue
	//	}
	//	loadedSigIDs = append(loadedSigIDs, m.ID)
	//}
	//
	//fmt.Println("Loaded signature(s): ", loadedSigIDs)
	//
	//if c.List {
	//	return nil, ListSigs(os.Stdout, sigs)
	//}
	//
	//var inputs engine.EventSources
	//opts, err := input.ParseTraceeInputOptions(c.Tracee)
	//if err == input.ErrHelp {
	//	input.PrintHelp()
	//	return nil, nil
	//}
	//if err != nil {
	//	return nil, err
	//}
	//inputs.Tracee, err = input.SetupTraceeInputSource(opts)
	//if err != nil {
	//	return nil, err
	//}
	//
	//if inputs == (engine.EventSources{}) {
	//	return nil, err
	//}
	//
	//output, err := output.SetupOutput(os.Stdout, c.Webhook, c.WebhookTemplate, c.WebhookContentType, c.OutputTemplate)
	//if err != nil {
	//	return nil, err
	//}
	//e := engine.NewEngine(sigs, inputs, output, os.Stderr)
	//e.Start(SigHandler())
	//return opts, nil
	return nil, nil
}
