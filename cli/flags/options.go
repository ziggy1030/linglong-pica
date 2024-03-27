package flags

import "github.com/spf13/pflag"

type CliOptions struct {
	Verbose bool
	Debug   bool
}

func NewCliOptions() *CliOptions {
	return &CliOptions{}
}

func (c *CliOptions) InstallFlags(flags *pflag.FlagSet) {
	// flags.BoolVarP(&c.Verbose, "verbose", "V", false, "verbose output")
}
