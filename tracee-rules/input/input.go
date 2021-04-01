package input

import (
	"bufio"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"
	tracee "github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

var ErrHelp = errors.New("user has requested help text")

type inputFormat uint8

const (
	invalidInputFormat inputFormat = iota
	jsonInputFormat
	gobInputFormat
	goChannel
)

type TraceeInputOptions struct {
	inputFile       *os.File
	inputFormat     inputFormat
	ProducerChannel chan external.Event
}

func SetupTraceeInputSource(opts *TraceeInputOptions) (chan types.Event, error) {

	if opts.inputFormat == jsonInputFormat {
		return setupTraceeJSONInputSource(opts)
	}

	if opts.inputFormat == gobInputFormat {
		return setupTraceeGobInputSource(opts)
	}

	if opts.inputFormat == goChannel {
		return setupTraceeGoChannel(opts)
	}

	return nil, errors.New("could not set up producerChannel source")
}

func setupTraceeGobInputSource(opts *TraceeInputOptions) (chan types.Event, error) {
	dec := gob.NewDecoder(opts.inputFile)
	res := make(chan types.Event)
	go func() {
		for {
			var event tracee.Event
			err := dec.Decode(&event)
			if err != nil {
				if err == io.EOF {
					break
				} else {
					log.Printf("Error while decoding event: %v", err)
				}
			} else {
				res <- event
			}
		}
		opts.inputFile.Close()
		close(res)
	}()
	return res, nil
}

func setupTraceeGoChannel(opts *TraceeInputOptions) (chan types.Event, error) {
	res := make(chan types.Event)
	go func() {
		for e := range opts.ProducerChannel {
			res <- e
		}
		close(res)
	}()
	return res, nil
}

func setupTraceeJSONInputSource(opts *TraceeInputOptions) (chan types.Event, error) {
	res := make(chan types.Event)
	scanner := bufio.NewScanner(opts.inputFile)
	go func() {
		for scanner.Scan() {
			event := scanner.Bytes()
			var e tracee.Event
			err := json.Unmarshal(event, &e)
			if err != nil {
				log.Printf("invalid json in %s: %v", string(event), err)
			}
			res <- e
		}
		opts.inputFile.Close()
		close(res)
	}()
	return res, nil
}

func ParseTraceeInputOptions(inputOptions []string) (*TraceeInputOptions, error) {
	var (
		inputSourceOptions TraceeInputOptions
		err                error
	)

	if len(inputOptions) == 0 {
		return nil, errors.New("no tracee producerChannel options specified")
	}

	for i := range inputOptions {
		if inputOptions[i] == "help" {
			return nil, ErrHelp
		}

		kv := strings.Split(inputOptions[i], ":")
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid producerChannel-tracee option: %s", inputOptions[i])
		}
		if kv[0] == "" || kv[1] == "" {
			return nil, fmt.Errorf("empty key or value passed: key: >%s< value: >%s<", kv[0], kv[1])
		}
		if kv[0] == "file" {
			err = parseTraceeInputFile(&inputSourceOptions, kv[1])
			if err != nil {
				return nil, err
			}
		} else if kv[0] == "format" {
			err = parseTraceeInputFormat(&inputSourceOptions, kv[1])
			if err != nil {
				return nil, err
			}
		} else if kv[0] == "gochannel" {
			inputSourceOptions.ProducerChannel = make(chan external.Event)
			err = parseTraceeInputFormat(&inputSourceOptions, kv[1])
			if err != nil {
				return &inputSourceOptions, err
			}
		} else {
			return nil, fmt.Errorf("invalid producerChannel-tracee option key: %s", kv[0])
		}
	}
	return &inputSourceOptions, nil
}

func parseTraceeInputFile(option *TraceeInputOptions, fileOpt string) error {

	if fileOpt == "stdin" {
		option.inputFile = os.Stdin
		return nil
	}
	_, err := os.Stat(fileOpt)
	if err != nil {
		return fmt.Errorf("invalid Tracee producerChannel file: %s", fileOpt)
	}
	f, err := os.Open(fileOpt)
	if err != nil {
		return fmt.Errorf("invalid file: %s", fileOpt)
	}
	option.inputFile = f
	return nil
}

func parseTraceeInputFormat(option *TraceeInputOptions, formatString string) error {
	formatString = strings.ToUpper(formatString)

	if formatString == "JSON" {
		option.inputFormat = jsonInputFormat
	} else if formatString == "GOB" {
		option.inputFormat = gobInputFormat
	} else if formatString == "goChannel" {
		option.inputFormat = goChannel
	} else {
		option.inputFormat = invalidInputFormat
		return fmt.Errorf("invalid tracee producerChannel format specified: %s", formatString)
	}
	return nil
}

func PrintHelp() {
	traceeInputHelp := `
tracee-rules --producerChannel-tracee <key:value>,<key:value> --producerChannel-tracee <key:value>

Specify various key value pairs for producerChannel options tracee-ebpf. The following key options are available:

'file'   - Input file source. You can specify a relative or absolute path. You may also specify 'stdin' for standard producerChannel.
'format' - Input format. Options currently include 'JSON' and 'GOB'. Both can be specified as output formats from tracee-ebpf.

Examples:

'tracee-rules --producerChannel-tracee file:./events.json --producerChannel-tracee format:json'
'tracee-rules --producerChannel-tracee file:./events.gob --producerChannel-tracee format:gob'
'sudo tracee-ebpf -o format:gob | tracee-rules --producerChannel-tracee file:stdin --producerChannel-tracee format:gob'
`

	fmt.Println(traceeInputHelp)
}
