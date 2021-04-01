module github.com/aquasecurity/tracee/tracee-ebpf

go 1.16

replace github.com/aquasecurity/tracee/tracee-rules v0.0.0-20210401082657-44eaf56edcd1 => github.com/tomyweiss/tracee/tracee-rules v0.0.0-20210401085515-c2a4de5decd5

require (
	github.com/aquasecurity/tracee/libbpfgo v0.0.0-20210318031738-f66f7bedda26
	github.com/aquasecurity/tracee/tracee-rules v0.0.0-20210401082657-44eaf56edcd1
	github.com/stretchr/testify v1.5.1
	github.com/syndtr/gocapability v0.0.0-20180916011248-d98352740cb2
	github.com/urfave/cli/v2 v2.3.0
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
