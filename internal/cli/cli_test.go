package cli

import (
	"bytes"
	"path/filepath"
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

func TestServerWithoutConfiguredKeysCreatesDefaultCredentialsAndPrintsPairingTokenOnce(t *testing.T) {
	configurationDirectory := t.TempDir()
	t.Setenv("UDPFILE_CONFIG_DIR", configurationDirectory)
	t.Setenv("UDPFILE_ENV", filepath.Join(configurationDirectory, "missing.env"))
	t.Setenv("UDPFILE_SHARED_SECRET", "")
	t.Setenv("UDPFILE_RSA_PRIVATE_KEY", "")

	arguments := []string{"server", "-addr", "127.0.0.1:0", "-root", filepath.Join(configurationDirectory, "missing-root")}
	var firstOutput bytes.Buffer
	if err := Run(arguments, &firstOutput, &firstOutput); err == nil {
		t.Fatal("first server run with missing root error = nil")
	}
	if !strings.Contains(firstOutput.String(), "UDF2-") || !strings.Contains(firstOutput.String(), "配对") {
		t.Fatalf("first server output = %q, want pairing token", firstOutput.String())
	}

	var secondOutput bytes.Buffer
	if err := Run(arguments, &secondOutput, &secondOutput); err == nil {
		t.Fatal("second server run with missing root error = nil")
	}
	if strings.Contains(secondOutput.String(), "UDF2-") {
		t.Fatalf("second server output exposed pairing token again: %q", secondOutput.String())
	}

	var requestedOutput bytes.Buffer
	showArguments := append(append([]string(nil), arguments...), "-show-pairing-token")
	if err := Run(showArguments, &requestedOutput, &requestedOutput); err == nil {
		t.Fatal("server run with missing root error = nil")
	}
	if !strings.Contains(requestedOutput.String(), "UDF2-") {
		t.Fatalf("server -show-pairing-token output = %q, want pairing token", requestedOutput.String())
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
