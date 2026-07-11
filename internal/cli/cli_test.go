package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootHelpListsAllModes(t *testing.T) {
	var output bytes.Buffer
	if err := Run([]string{"help"}, &output, &output); err != nil {
		t.Fatalf("Run(help) error = %v", err)
	}
	for _, command := range []string{"server", "client", "web", "keygen"} {
		if !strings.Contains(output.String(), command) {
			t.Errorf("root help does not list %q", command)
		}
	}
}

func TestSubcommandHelpUsesIndependentFlags(t *testing.T) {
	for _, test := range []struct {
		command string
		flag    string
	}{
		{"server", "-root"},
		{"client", "-path"},
		{"web", "-listen"},
		{"keygen", "-rsa-bits"},
	} {
		var output bytes.Buffer
		if err := Run([]string{test.command, "-help"}, &output, &output); err != nil {
			t.Fatalf("Run(%s -help) error = %v", test.command, err)
		}
		if !strings.Contains(output.String(), test.flag) {
			t.Errorf("%s help does not contain %q", test.command, test.flag)
		}
	}
}

func TestUnknownSubcommandReturnsActionableError(t *testing.T) {
	var output bytes.Buffer
	err := Run([]string{"unknown"}, &output, &output)
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("Run(unknown) error = %v", err)
	}
}

func TestInvalidSubcommandFlagWritesDiagnosticsToStderr(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Run([]string{"client", "-definitely-invalid"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("Run(client -definitely-invalid) error = nil")
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "definitely-invalid") {
		t.Fatalf("stderr = %q, want invalid flag diagnostic", stderr.String())
	}
}
