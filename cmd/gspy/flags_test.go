// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"flag"
	"io"
	"reflect"
	"testing"
)

func TestOptionsAfterPIDAreParsed(t *testing.T) {
	for _, arguments := range [][]string{
		{"123", "--json", "--readonly", "--filter", "net"},
		{"--json", "123", "--readonly", "--filter=net"},
		{"--filter", "net", "--readonly", "--json", "123"},
	} {
		t.Run(arguments[0], func(t *testing.T) {
			flags := flag.NewFlagSet("gspy", flag.ContinueOnError)
			jsonMode := flags.Bool("json", false, "")
			readonly := flags.Bool("readonly", false, "")
			filter := flags.String("filter", "all", "")
			if err := parseCommandLine(flags, arguments); err != nil {
				t.Fatal(err)
			}
			if !*jsonMode || !*readonly || *filter != "net" {
				t.Fatalf("ignored options: json=%v readonly=%v filter=%s", *jsonMode, *readonly, *filter)
			}
			if !reflect.DeepEqual(flags.Args(), []string{"123"}) {
				t.Fatalf("unexpected positional arguments: %v", flags.Args())
			}
		})
	}
}

func TestInvalidTrailingOptionsAreRejected(t *testing.T) {
	for _, arguments := range [][]string{{"123", "--typo"}, {"123", "--filter"}} {
		flags := flag.NewFlagSet("gspy", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		flags.String("filter", "all", "")
		if err := parseCommandLine(flags, arguments); err == nil {
			t.Fatalf("accepted invalid trailing options: %v", arguments)
		}
	}
}

func TestOptionTerminatorPreservesPositionalArguments(t *testing.T) {
	flags := flag.NewFlagSet("gspy", flag.ContinueOnError)
	json := flags.Bool("json", false, "")
	if err := parseCommandLine(flags, []string{"123", "--", "--json"}); err != nil {
		t.Fatal(err)
	}
	if *json || len(flags.Args()) != 2 || flags.Args()[1] != "--json" {
		t.Fatalf("option terminator ignored: json=%v args=%v", *json, flags.Args())
	}
}
