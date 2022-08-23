// Copyright 2022 SLSA Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package verify

import (
	"fmt"
	"strings"

	serrors "github.com/slsa-framework/slsa-verifier/errors"
	"github.com/spf13/cobra"
)

type Interface interface {
	// AddFlags adds this options' flags to the cobra command.
	AddFlags(cmd *cobra.Command)
}

// VerifyOptions is the top-level options for all `verify` commands.
type VerifyOptions struct {
	ProvenancePath  string
	BuilderID       string
	Source          string
	Branch          string
	Tag             string
	VersionTag      string
	Inputs          workflowInputs
	PrintProvenance bool
}

var _ Interface = (*VerifyOptions)(nil)

// AddFlags implements Interface
func (o *VerifyOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.ProvenancePath, "provenance-path", "",
		"path to a provenance file")

	cmd.Flags().StringVar(&o.BuilderID, "builder-id", "", "EXPERIMENTAL: the unique builder ID who created the provenance")

	cmd.Flags().StringVar(&o.Source, "source", "",
		"expected source repository that should have produced the binary, e.g. github.com/some/repo")

	cmd.Flags().StringVar(&o.Branch, "branch", "", "[optional] expected branch the binary was compiled from")

	cmd.Flags().StringVar(&o.Tag, "tag", "", "[optional] expected tag the binary was compiled from")

	cmd.Flags().StringVar(&o.VersionTag, "versioned-tag", "",
		"[optional] expected version the binary was compiled from. Uses semantic version to match the tag")

	cmd.Flags().BoolVar(&o.PrintProvenance, "print-provenance", false,
		"print the verified provenance to std out")

	cmd.Flags().Var(&o.Inputs, "workflow-input",
		"[optional] a workflow input provided by a user at trigger time in the format 'key=value'. (Only for 'workflow_dispatch' events).")

	cmd.MarkFlagRequired("source")
	cmd.MarkFlagsMutuallyExclusive("versioned-tag", "tag")
}

type workflowInputs struct {
	kv map[string]string
}

func (i *workflowInputs) Type() string {
	return fmt.Sprintf("%v", i.kv)
}

func (i *workflowInputs) String() string {
	return fmt.Sprintf("%v", i.kv)
}

func (i *workflowInputs) Set(value string) error {
	l := strings.Split(value, "=")
	if len(l) != 2 {
		return fmt.Errorf("%w: expected 'key=value' format, got '%s'", serrors.ErrorInvalidFormat, value)
	}
	i.kv[l[0]] = l[1]
	return nil
}

func (i *workflowInputs) AsMap() map[string]string {
	return i.kv
}