package logic

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/aquasecurity/tracee/tracee-rules/types"

	"github.com/aquasecurity/tracee/tracee-rules/engine"
	"github.com/aquasecurity/tracee/tracee-rules/input"
	"github.com/aquasecurity/tracee/tracee-rules/model"
	"github.com/aquasecurity/tracee/tracee-rules/output"
	"github.com/aquasecurity/tracee/tracee-rules/signatures"
)

func InitTraceeRules(config model.RulesConfig) error {
	sigs, err := signatures.GetSignatures(config.RulesDir, config.Rules)
	if err != nil {
		return err
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

	if config.ListRules {
		return ListSigs(os.Stdout, sigs)
	}

	var inputs engine.EventSources
	opts, err := input.ParseTraceeInputOptions(config.InputMethods)
	if err == input.ErrHelp {
		input.PrintHelp()
		return nil
	}
	if err != nil {
		return err
	}
	inputs.Tracee, err = input.SetupTraceeInputSource(opts)
	if err != nil {
		return err
	}

	if inputs == (engine.EventSources{}) {
		return err
	}

	o, err := output.SetupOutput(os.Stdout, config.Webhook, config.WebhookTemplate, config.WebhookContentType, config.OutputTemplate)
	if err != nil {
		return err
	}
	e := engine.NewEngine(sigs, inputs, o, os.Stderr)
	e.Start(sigHandler())

	return nil
}

func sigHandler() chan bool {
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		done <- true
	}()
	return done
}

func ListSigs(w io.Writer, sigs []types.Signature) error {
	fmt.Fprintf(w, "%-10s %-35s %s %s\n", "ID", "NAME", "VERSION", "DESCRIPTION")
	for _, sig := range sigs {
		meta, err := sig.GetMetadata()
		if err != nil {
			continue
		}
		fmt.Fprintf(w, "%-10s %-35s %-7s %s\n", meta.ID, meta.Name, meta.Version, meta.Description)
	}
	return nil
}
