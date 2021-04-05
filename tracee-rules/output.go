package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig"
	tracee "github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

const DefaultDetectionOutputTemplate string = `
*** Detection ***
Time: {{ dateInZone "2006-01-02T15:04:05Z" (now) "UTC" }}
Signature ID: {{ .SigMetadata.ID }}
Signature: {{ .SigMetadata.Name }}
Data: {{ .Data }}
Command: {{ .Context.ProcessName }}
Hostname: {{ .Context.HostName }}
`

func setupTemplate(inputTemplateFile string) (*template.Template, error) {
	switch {
	case inputTemplateFile != "":
		return template.New(filepath.Base(inputTemplateFile)).
			Funcs(sprig.TxtFuncMap()).
			ParseFiles(inputTemplateFile)
	default:
		return template.New("default").
			Funcs(sprig.TxtFuncMap()).
			Parse(DefaultDetectionOutputTemplate)
	}
}

func setupOutput(w io.Writer, webhook string, webhookTemplate string, contentType string, outputTemplate string) (chan types.Finding, error) {
	out := make(chan types.Finding)
	var err error

	var tWebhook *template.Template
	tWebhook, err = setupTemplate(webhookTemplate)
	if err != nil && webhookTemplate != "" {
		return nil, fmt.Errorf("error preparing webhook template: %v", err)
	}

	var tOutput *template.Template
	tOutput, err = setupTemplate(outputTemplate)
	if err != nil && outputTemplate != "" {
		return nil, fmt.Errorf("error preparing output template: %v", err)
	}

	go func(w io.Writer, tWebhook, tOutput *template.Template) {
		for res := range out {
			switch res.Context.(type) {
			case tracee.Event:
				serializedObject, err := json.Marshal(res)
				if err != nil {
					log.Printf("Error when trying to parse tracee event: %v\n", err)
					continue
				}

				bs := make([]byte, 4)
				binary.LittleEndian.PutUint32(bs, uint32(len(serializedObject)))

				// ensure data is in the same buffer (instead of writing performing consecutive writes)
				data := bytes.Join([][]byte{bs, serializedObject}, []byte(""))
				err = binary.Write(os.Stdout, binary.LittleEndian, data)
				if err != nil {
					log.Printf("Error when trying to write event: %v\n", err)
				}
			default:
				log.Printf("unsupported event detected: %T\n", res.Context)
				continue
			}

			if webhook != "" {
				if err := sendToWebhook(tWebhook, res, webhook, webhookTemplate, contentType); err != nil {
					log.Println(err)
				}
			}
		}
	}(w, tWebhook, tOutput)
	return out, nil
}

func sendToWebhook(t *template.Template, res types.Finding, webhook string, webhookTemplate string, contentType string) error {
	var payload string

	switch {
	case webhookTemplate != "":
		if t == nil {
			return fmt.Errorf("error writing to template: template not initialized")
		}
		if contentType == "" {
			log.Println("content-type was not set for the custom template: ", webhookTemplate)
		}
		buf := bytes.Buffer{}
		if err := t.Execute(&buf, res); err != nil {
			return fmt.Errorf("error writing to the template: %v", err)
		}
		payload = buf.String()
	default:
		return errors.New("error sending to webhook: --webhook-template flag is required when using --webhook flag")
	}

	resp, err := http.Post(webhook, contentType, strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("error calling webhook %v", err)
	}
	_ = resp.Body.Close()
	return nil
}
