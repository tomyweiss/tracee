package regosig

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/aquasecurity/tracee/tracee-ebpf/tests/types"
	tracee "github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

// RegoSignature is an abstract signature that is implemented in rego
// each struct instance is associated with a rego file
// the rego file declares the following rules:
// __rego_metadoc__: a *document* rule that defines the rule's metadata (see GetMetadata())
// tracee_selected_events: a *set* rule that defines the event selectors (see GetSelectedEvent())
// tracee_match: a *boolean*, or a *document* rule that defines the logic of the signature (see OnEvent())
type RegoSignature struct {
	cb             types.SignatureHandler
	compiledRego   *ast.Compiler
	matchPQ        rego.PreparedEvalQuery
	metadata       types.SignatureMetadata
	selectedEvents []types.SignatureEventSelector
}

const queryMatch string = "data.%s.tracee_match"
const querySelectedEvents string = "data.%s.tracee_selected_events"
const queryMetadata string = "data.%s.__rego_metadoc__"
const packageNameRegex string = `package\s.*`

// NewRegoSignature creates a new RegoSignature with the provided rego code string
func NewRegoSignature(regoCodes ...string) (types.Signature, error) {
	var err error
	res := RegoSignature{}
	regoMap := make(map[string]string)

	re := regexp.MustCompile(packageNameRegex)

	var pkgName string
	for _, regoCode := range regoCodes {
		regoModuleName := strings.Split(re.FindString(regoCode), " ")[1]
		if !strings.Contains(regoCode, "package tracee.helpers") {
			pkgName = regoModuleName
		}
		regoMap[regoModuleName] = regoCode
	}

	res.compiledRego, err = ast.CompileModules(regoMap)
	if err != nil {
		return nil, err
	}

	res.matchPQ, err = rego.New(
		rego.Compiler(res.compiledRego),
		rego.Query(fmt.Sprintf(queryMatch, pkgName)),
	).PrepareForEval(context.TODO())
	if err != nil {
		return nil, err
	}
	res.metadata, err = res.getMetadata(pkgName)
	if err != nil {
		return nil, err
	}
	res.selectedEvents, err = res.getSelectedEvents(pkgName)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// Init implements the Signature interface by resetting internal state
func (sig *RegoSignature) Init(cb types.SignatureHandler) error {
	sig.cb = cb
	return nil
}

// GetMetadata implements the Signature interface by evaluating the Rego policy's __rego_metadoc__ rule
// this is a *document* rule that defines the rule's metadata
// based on WIP Rego convention for describing policy metadata: https://hackmd.io/@ZtQnh19kS26YiNlJLqKJnw/H1gAv5nBw
func (sig *RegoSignature) GetMetadata() (types.SignatureMetadata, error) {
	return sig.metadata, nil
}

func (sig *RegoSignature) getMetadata(pkgName string) (types.SignatureMetadata, error) {
	evalRes, err := sig.evalQuery(fmt.Sprintf(queryMetadata, pkgName))
	if err != nil {
		return types.SignatureMetadata{}, err
	}
	resJSON, err := json.Marshal(evalRes)
	if err != nil {
		return types.SignatureMetadata{}, err
	}
	dec := json.NewDecoder(bytes.NewBuffer(resJSON))
	dec.UseNumber()
	var res types.SignatureMetadata
	err = dec.Decode(&res)
	if err != nil {
		return types.SignatureMetadata{}, err
	}
	return res, nil
}

// GetSelectedEvents implements the Signature interface by evaluating the Rego policy's tracee_selected_events rule
// this is a *set* rule that defines the rule's SelectedEvents
func (sig *RegoSignature) GetSelectedEvents() ([]types.SignatureEventSelector, error) {
	return sig.selectedEvents, nil
}

func (sig *RegoSignature) getSelectedEvents(pkgName string) ([]types.SignatureEventSelector, error) {
	evalRes, err := sig.evalQuery(fmt.Sprintf(querySelectedEvents, pkgName))
	if err != nil {
		return nil, err
	}
	resJSON, err := json.Marshal(evalRes)
	if err != nil {
		return nil, err
	}
	var res []types.SignatureEventSelector
	err = json.Unmarshal(resJSON, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// OnEvent implements the Signature interface by evaluating the Rego policy's tracee_match rule
// this is a *boolean* or a *document* rule that defines the logic of the signature
// if bool is "returned", a true evaluation will generate a Finding with no data
// if document is "returned", any non-empty evaluation will generate a Finding with the document as the Finding's "Data"
func (sig *RegoSignature) OnEvent(e types.Event) error {

	ee, ok := e.(tracee.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}
	fmt.Println(ee)
	results, err := sig.matchPQ.Eval(context.TODO(), rego.EvalInput(ee))
	if err != nil {
		return err
	}
	if len(results) > 0 && len(results[0].Expressions) > 0 && results[0].Expressions[0].Value != nil {
		switch v := results[0].Expressions[0].Value.(type) {
		case bool:
			if v {
				sig.cb(types.Finding{
					Data:        nil,
					Context:     ee,
					SigMetadata: sig.metadata,
				})
			}
		case map[string]interface{}:
			sig.cb(types.Finding{
				Data:        v,
				Context:     ee,
				SigMetadata: sig.metadata,
			})
		}
	}
	return nil
}

// OnSignal implements the Signature interface by handling lifecycle events of the signature
func (sig *RegoSignature) OnSignal(signal types.Signal) error {
	return fmt.Errorf("function OnSignal is not implemented")
}

func (sig *RegoSignature) evalQuery(query string) (interface{}, error) {
	pq, err := rego.New(
		rego.Compiler(sig.compiledRego),
		rego.Query(query),
	).PrepareForEval(context.TODO())
	if err != nil {
		return nil, err
	}
	evalRes, err := pq.Eval(context.TODO())
	if err != nil {
		return nil, err
	}
	if len(evalRes) > 0 && len(evalRes[0].Expressions) > 0 && evalRes[0].Expressions[0].Value != nil {
		return evalRes[0].Expressions[0].Value, nil
	}
	return nil, nil
}
