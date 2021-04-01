package signature

import (
	_ "embed"
	"io"
	"os/signal"
	"syscall"

	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/aquasecurity/tracee/tracee-ebpf/tests/signature/signatures/rego/regosig"
	"github.com/aquasecurity/tracee/tracee-ebpf/tests/types"
)

//go:embed signatures/rego/helpers.rego
var regoHelpersCode string

func GetSignatures(rulesDir string, rules []string) ([]types.Signature, error) {
	if rulesDir == "" {
		exePath, err := os.Executable()
		if err != nil {
			log.Print(err)
		}
		rulesDir = filepath.Join(filepath.Dir(exePath), "rules")
	}
	gosigs, err := findGoSigs(rulesDir)
	if err != nil {
		return nil, err
	}
	opasigs, err := findRegoSigs(rulesDir)
	if err != nil {
		return nil, err
	}
	sigs := append(gosigs, opasigs...)
	var res []types.Signature
	if rules == nil {
		res = sigs
	} else {
		for _, s := range sigs {
			for _, r := range rules {
				if m, err := s.GetMetadata(); err == nil && m.ID == r {
					res = append(res, s)
				}
			}
		}
	}
	fmt.Println(res)
	return res, nil
}

func findGoSigs(dir string) ([]types.Signature, error) {
	//files, err := ioutil.ReadDir(dir)
	//if err != nil {
	//	return nil, fmt.Errorf("error reading plugins directory %s: %v", dir, err)
	//}
	//var res [	]types.Signature
	//for _, file := range files {
	//	if filepath.Ext(file.Name()) != ".so" {
	//		continue
	//	}
	//	p, err := plugin.Open(filepath.Join(dir, file.Name()))
	//	if err != nil {
	//		log.Printf("error opening plugin %s: %v", file.Name(), err)
	//		continue
	//	}
	//	export, err := p.Lookup("ExportedSignatures")
	//	if err != nil {
	//		log.Printf("missing Export symbol in plugin %s", file.Name())
	//		continue
	//	}
	//	sigs := *export.(*[]types.Signature)
	//	res = append(res, sigs...)
	//}
	//return res, nil
	return nil, nil
}

func findRegoSigs(dir string) ([]types.Signature, error) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("error reading plugins directory %s: %v", dir, err)
	}

	var res []types.Signature

	for _, file := range files {
		if filepath.Ext(file.Name()) != ".rego" {
			continue
		}
		if file.Name() == "helpers.rego" {
			continue
		}
		regoCode, err := ioutil.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			log.Printf("error reading file %s/%s: %v", dir, file, err)
			continue
		}
		sig, err := regosig.NewRegoSignature(string(regoCode), regoHelpersCode)
		if err != nil {
			log.Printf("error creating rego signature with: %s: %v ", regoCode[0:20], err)
			continue
		}
		res = append(res, sig)
	}
	return res, nil
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

func SigHandler() chan bool {
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		done <- true
	}()
	return done
}
