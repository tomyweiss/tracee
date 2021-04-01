package rules

import (
	"github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"
	"github.com/aquasecurity/tracee/tracee-rules/signatures"
)

func TraceeRules() external.Event {
	_, err := signatures.GetSignatures("", []string{})
	if err != nil {
		return external.Event{}
	}

	return external.Event{}
	//var loadedSigIDs []string
	//for _, s := range sigs {
	//	m, err := s.GetMetadata()
	//	if err != nil {
	//		fmt.Println("failed to load signature: ", err)
	//		continue
	//	}
	//	loadedSigIDs = append(loadedSigIDs, m.ID)
	//}
	//fmt.Println("Loaded signature(s): ", loadedSigIDs)
	//
	//if c.Bool("list") {
	//	return listSigs(os.Stdout, sigs)
	//}
	//
	//var inputs engine.EventSources
	//opts, err := parseTraceeInputOptions(c.StringSlice("input-tracee"))
	//if err == errHelp {
	//	printHelp()
	//	return nil
	//}
	//if err != nil {
	//	return err
	//}
	//inputs.Tracee, err = setupTraceeInputSource(opts)
	//if err != nil {
	//	return err
	//}
	//
	//if inputs == (engine.EventSources{}) {
	//	return err
	//}
	//
	//output, err := setupOutput(os.Stdout, c.String("webhook"), c.String("webhook-template"), c.String("webhook-content-type"), c.String("output-template"))
	//if err != nil {
	//	return err
	//}
	//e := engine.NewEngine(sigs, inputs, output, os.Stderr)
	//e.Start(sigHandler())
	//return nil
}
