module ValidateComplianceCow

go 1.21.3

require (
	applicationtypes v0.0.0-00010101000000-000000000000
	cowlibrary v0.0.0-00010101000000-000000000000
	github.com/google/uuid v1.3.1
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/charmbracelet/bubbletea v0.24.2 // indirect
	github.com/containerd/console v1.0.4-0.20230313162750-1ae8d489ac81 // indirect
	github.com/go-resty/resty/v2 v2.7.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.14 // indirect
	github.com/muesli/ansi v0.0.0-20211018074035-2e021307bc4b // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/reflow v0.3.0 // indirect
	github.com/muesli/termenv v0.15.1 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
	golang.org/x/term v0.24.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

replace cowlibrary => ../../../../../src/cowlibrary

replace applicationtypes => ../../
