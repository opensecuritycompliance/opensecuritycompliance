module cowctl

go 1.20

replace cowlibrary => ../cowlibrary

replace applicationtypes => ../../catalog/applicationtypes/go

require (
	cowlibrary v0.0.0-00010101000000-000000000000
	github.com/arul-g/go-prompt v1.0.0
	github.com/briandowns/spinner v1.23.0
	github.com/charmbracelet/bubbles v0.16.1
	github.com/charmbracelet/bubbletea v0.24.2
	github.com/charmbracelet/lipgloss v0.7.1
	github.com/chriswalz/complete/v3 v3.0.13
	github.com/dmnlk/stringUtils v0.0.0-20150214151148-aa88c62978f5
	github.com/fatih/color v1.15.0
	github.com/go-playground/validator/v10 v10.14.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/iancoleman/strcase v0.2.0
	github.com/kyokomi/emoji v2.2.4+incompatible
	github.com/olekukonko/tablewriter v0.0.5
	github.com/rs/zerolog v1.29.0
	github.com/spf13/cobra v1.7.0
	golang.org/x/exp v0.0.0-20230321023759-10a507213a29
	gopkg.in/yaml.v2 v2.4.0
)

require (
	applicationtypes v0.0.0-00010101000000-000000000000 // indirect
	github.com/atotto/clipboard v0.1.4 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/containerd/console v1.0.4-0.20230313162750-1ae8d489ac81 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fako1024/topo v1.0.3 // indirect
	github.com/gabriel-vasile/mimetype v1.4.2 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-resty/resty/v2 v2.7.0 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/uuid v1.3.1 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-multierror v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/jwalton/go-supportscolor v1.1.0 // indirect
	github.com/klauspost/compress v1.16.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.4 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/leodido/go-urn v1.2.4 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.18 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.14 // indirect
	github.com/mattn/go-tty v0.0.3 // indirect
	github.com/mcuadros/go-version v0.0.0-20190830083331-035f6764e8d2 // indirect
	github.com/minio/md5-simd v1.1.2 // indirect
	github.com/minio/minio-go v6.0.14+incompatible // indirect
	github.com/minio/minio-go/v7 v7.0.50 // indirect
	github.com/minio/sha256-simd v1.0.0 // indirect
	github.com/mitchellh/colorstring v0.0.0-20190213212951-d06e56a500db // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/muesli/ansi v0.0.0-20211018074035-2e021307bc4b // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/reflow v0.3.0 // indirect
	github.com/muesli/termenv v0.15.1 // indirect
	github.com/otiai10/copy v1.9.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pkg/term v1.2.0-beta.2 // indirect
	github.com/posener/script v1.1.5 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/rs/xid v1.4.0 // indirect
	github.com/sahilm/fuzzy v0.1.0 // indirect
	github.com/schollz/progressbar/v3 v3.13.1 // indirect
	github.com/sirupsen/logrus v1.9.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/tidwall/gjson v1.14.4 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/term v0.13.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
