package main

import (
	"flag"
	"fmt"
)

type selectionOption struct {
	flag     *flag.Flag
	value    flag.Value
	supplied bool
	repeated bool
	invalid  bool
}

func (o *selectionOption) String() string {
	if o.value == nil {
		return ""
	}
	return o.value.String()
}

func (o *selectionOption) IsBoolFlag() bool {
	v, ok := o.value.(interface{ IsBoolFlag() bool })
	return ok && v.IsBoolFlag()
}

func (o *selectionOption) Set(raw string) error {
	if o.supplied {
		o.repeated = true
		// Do not replace the first selection or return a parsing error: flag
		// would echo raw, and JSON framing is configured after parsing.
		return nil
	}
	o.supplied = true
	o.invalid = o.value.Set(raw) != nil
	return nil
}

// Keep each trust, resource, input and execution selector unique. Presentation
// options remain ordinary flags, and expect-context retains its own guard.
// Validate before files, state locks or RPC; defaults and single selections
// continue using the existing flag values and policy checks.
func registerSelectionGuards(fs *flag.FlagSet) func() error {
	var guarded []*selectionOption
	fs.VisitAll(func(f *flag.Flag) {
		if f.Name != "json" && f.Name != "show-context" && f.Name != "expect-context" {
			o := &selectionOption{flag: f, value: f.Value}
			f.Value = o
			guarded = append(guarded, o)
		}
	})
	// Preserve ordinary default/help formatting while the parser is wrapped.
	usage := fs.Usage
	fs.Usage = func() {
		for _, o := range guarded {
			o.flag.Value = o.value
		}
		defer func() {
			for _, o := range guarded {
				o.flag.Value = o
			}
		}()
		usage()
	}
	return func() error {
		var repeated, invalid string
		for _, o := range guarded {
			o.flag.Value = o.value
			if o.repeated && repeated == "" {
				repeated = o.flag.Name
			}
			if o.invalid && invalid == "" {
				invalid = o.flag.Name
			}
		}
		if repeated != "" {
			return fmt.Errorf("--%s must occur at most once", repeated)
		}
		if invalid != "" {
			return fmt.Errorf("--%s has an invalid value", invalid)
		}
		return nil
	}
}
