package cli

import (
	"strings"
	"testing"
)

func TestLicensesCheck_RejectsUnknownDenyCategory(t *testing.T) {
	// The SBOM path doesn't exist: the category check must fire before
	// anything is read, so this can only fail for the reason under test.
	_, err := runCLI(t, "licenses", "check", "--sbom", "/nonexistent/sbom.json", "--deny-category", "copyleftt")
	requireErrContains(t, err, "copyleftt")
	requireErrContains(t, err, "weak-copyleft")
	if strings.Contains(err.Error(), "read SBOM") {
		t.Errorf("error = %q: the category check should run before the SBOM is read", err.Error())
	}
}
