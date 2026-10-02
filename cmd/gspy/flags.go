// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"flag"
	"fmt"
	"strings"
)

func parseCommandLine(flags *flag.FlagSet, arguments []string) error {
	var options, positional []string
	for i := 0; i < len(arguments); i++ {
		argument := arguments[i]
		if argument == "--" {
			positional = append(positional, arguments[i+1:]...)
			break
		}
		if !strings.HasPrefix(argument, "-") || argument == "-" {
			positional = append(positional, argument)
			continue
		}
		options = append(options, argument)
		name, _, hasValue := strings.Cut(strings.TrimLeft(argument, "-"), "=")
		option := flags.Lookup(name)
		if option == nil || hasValue {
			continue
		}
		if boolean, ok := option.Value.(interface{ IsBoolFlag() bool }); ok && boolean.IsBoolFlag() {
			continue
		}
		if i+1 == len(arguments) {
			return fmt.Errorf("flag needs an argument: %s", argument)
		}
		i++
		options = append(options, arguments[i])
	}
	return flags.Parse(append(append(options, "--"), positional...))
}
