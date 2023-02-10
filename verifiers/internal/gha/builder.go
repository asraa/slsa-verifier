package gha

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/mod/semver"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

var (
	trustedBuilderRepository = "slsa-framework/slsa-github-generator"
	e2eTestRepository        = "slsa-framework/example-package"
	certOidcIssuer           = "https://token.actions.githubusercontent.com"
	// This is used in cosign's CheckOpts for validating the certificate. We
	// do specific builder verification after this.
	certSubjectRegexp = "https://github.com/*"
	// Delegator workflow path. This requires special logic when checking the
	// builder ID in the provenance.
	delegatorPath = trustedBuilderRepository + "/.github/workflows/delegator_generic_slsa3.yml"
)

var defaultArtifactTrustedReusableWorkflows = map[string]bool{
	trustedBuilderRepository + "/.github/workflows/generator_generic_slsa3.yml": true,
	trustedBuilderRepository + "/.github/workflows/builder_go_slsa3.yml":        true,
	delegatorPath: true,
}

var defaultContainerTrustedReusableWorkflows = map[string]bool{
	trustedBuilderRepository + "/.github/workflows/generator_container_slsa3.yml": true,
}

// VerifyWorkflowIdentity verifies the signing certificate information
// Builder IDs are verified against an expected builder ID provided in the
// builerOpts, or against the set of defaultBuilders provided.
func VerifyWorkflowIdentity(id *WorkflowIdentity,
	builderOpts *options.BuilderOpts, source string,
	defaultBuilders map[string]bool,
) (*utils.TrustedBuilderID, error) {
	// cert URI path is /org/repo/path/to/workflow@ref
	workflowPath := strings.SplitN(id.JobWobWorkflowRef, "@", 2)
	if len(workflowPath) < 2 {
		return nil, fmt.Errorf("%w: workflow uri: %s", serrors.ErrorMalformedURI, id.JobWobWorkflowRef)
	}

	// Verify trusted workflow.
	reusableWorkflowPath := strings.Trim(workflowPath[0], "/")
	reusableWorkflowTag := strings.Trim(workflowPath[1], "/")
	builderID, err := verifyTrustedBuilderID(reusableWorkflowPath, reusableWorkflowTag,
		builderOpts.ExpectedID, defaultBuilders)
	if err != nil {
		return nil, err
	}
	reusableWorkflowID, err := utils.TrustedBuilderIDNew("https://github.com" + id.JobWobWorkflowRef)
	if err != nil {
		return nil, err
	}

	// Verify the ref is a full semantic version tag.
	if err := verifyTrustedBuilderRef(id, reusableWorkflowID); err != nil {
		return nil,
			fmt.Errorf("%s: %w", "verifying signing certificate ID", err)
	}

	// Issuer verification.
	if !strings.EqualFold(id.Issuer, certOidcIssuer) {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidOIDCIssuer, id.Issuer)
	}

	// The caller repository in the x509 extension is not fully qualified. It only contains
	// {org}/{repository}.
	expectedSource := strings.TrimPrefix(source, "git+https://")
	expectedSource = strings.TrimPrefix(expectedSource, "github.com/")
	if !strings.EqualFold(id.CallerRepository, expectedSource) {
		return nil, fmt.Errorf("%w: expected source '%s', got '%s'", serrors.ErrorMismatchSource,
			expectedSource, id.CallerRepository)
	}

	// Return the builder and its tag.
	// Note: the tag has the format `refs/tags/v1.2.3`.
	return builderID, nil
}

// Verifies the builder ID at path against an expected builderID.
// If an expected builderID is not provided, uses the defaultBuilders.
func verifyTrustedBuilderID(certPath, certTag string, expectedBuilderID *string, defaultBuilders map[string]bool) (*utils.TrustedBuilderID, error) {
	var trustedBuilderID *utils.TrustedBuilderID
	var err error
	certBuilderName := "https://github.com/" + certPath
	// WARNING: we don't validate the tag here, because we need to allow
	// refs/heads/main for e2e tests. See verifyTrustedBuilderRef().

	// The user MUST provide an expected builderID (TRW) when using the delegator.
	hasExpectedBuilderID := expectedBuilderID != nil && *expectedBuilderID != ""
	if certPath == delegatorPath && !hasExpectedBuilderID {
		return nil, fmt.Errorf("%w: a --builder-id MUST be specified when using a delegator workflow",
			serrors.ErrorInvalidBuilderID)
	}

	// No builder ID provided by user: use the default trusted workflows.
	if !hasExpectedBuilderID {
		if _, ok := defaultBuilders[certPath]; !ok {
			return nil, fmt.Errorf("%w: %s got %t", serrors.ErrorUntrustedReusableWorkflow, certPath, expectedBuilderID == nil)
		}
		// Construct the builderID using the certificate's builder's name and tag.
		trustedBuilderID, err = utils.TrustedBuilderIDNew(certBuilderName + "@" + certTag)
		if err != nil {
			return nil, err
		}
	} else {
		// Verify the builderID against an expected builder ID.
		// We only accept IDs on github.com.
		trustedBuilderID, err = utils.TrustedBuilderIDNew(certBuilderName + "@" + certTag)
		if err != nil {
			return nil, err
		}

		// If this is the delegator builder, then the builderID may be any TRW.
		if certPath == delegatorPath {
			return trustedBuilderID, nil
		}

		// Otherwise, BuilderID provided by user should match the certificate.
		// Note: the certificate builderID has the form `name@refs/tags/v1.2.3`,
		// so we pass `allowRef = true`.
		if err := trustedBuilderID.Matches(*expectedBuilderID, true); err != nil {
			return nil, fmt.Errorf("%w: %v", serrors.ErrorUntrustedReusableWorkflow, err)
		}
	}

	return trustedBuilderID, nil
}

// Only allow `@refs/heads/main` for the builder and the e2e tests that need to work at HEAD.
// This lets us use the pre-build builder binary generated during release (release happen at main).
// For other projects, we only allow semantic versions that map to a release.
func verifyTrustedBuilderRef(id *WorkflowIdentity,
	trustedBuilder *utils.TrustedBuilderID) error {
	ref := trustedBuilder.Version()
	// The e2e test repository is allowed to call workflows in slsa-github-generator
	// at main.
	if (id.CallerRepository == e2eTestRepository &&
		strings.HasPrefix(trustedBuilder.Name(), "https://github.com/"+trustedBuilderRepository)) &&
		strings.EqualFold("refs/heads/main", ref) {
		return nil
	}

	// Check if workflow is in the same repository that the trusted builder
	// is hosted.
	sameRepository := strings.HasPrefix(trustedBuilder.Name(),
		"https://github.com/"+id.CallerRepository)
	// Verify that this is a local call inside a test workflow.
	ci, ciOK := os.LookupEnv("CI")
	repo, repoOK := os.LookupEnv("GITHUB_REPOSITORY")
	localTestWorkflow := (repoOK && repo == id.CallerRepository) &&
		(ciOK && ci == "true")

	// Workflows in the same repository where the trusted builder is hosted
	// are allowed to call the workflow at main inside the test workflow.
	if (sameRepository && localTestWorkflow) &&
		strings.EqualFold("refs/heads/main", ref) {
		return nil
	}

	// Extract the pin.
	pin, err := utils.TagFromGitHubRef(ref)
	if err != nil {
		return err
	}

	// Valid semver of the form vX.Y.Z with no metadata.
	if !(semver.IsValid(pin) &&
		len(strings.Split(pin, ".")) == 3 &&
		semver.Prerelease(pin) == "" &&
		semver.Build(pin) == "") {
		return fmt.Errorf("%w: %s: not of the form vX.Y.Z", serrors.ErrorInvalidRef, pin)
	}
	return nil
}

func getExtension(cert *x509.Certificate, oid string) string {
	for _, ext := range cert.Extensions {
		if strings.Contains(ext.Id.String(), oid) {
			return string(ext.Value)
		}
	}
	return ""
}

type WorkflowIdentity struct {
	// The caller repository
	CallerRepository string `json:"caller"`
	// The commit SHA where the workflow was triggered
	CallerHash string `json:"commit"`
	// Current workflow (reuseable workflow) ref
	JobWobWorkflowRef string `json:"job_workflow_ref"`
	// Trigger
	Trigger string `json:"trigger"`
	// Issuer
	Issuer string `json:"issuer"`
}

// GetWorkflowFromCertificate gets the workflow identity from the Fulcio authenticated content.
func GetWorkflowInfoFromCertificate(cert *x509.Certificate) (*WorkflowIdentity, error) {
	if len(cert.URIs) == 0 {
		return nil, errors.New("missing URI information from certificate")
	}

	return &WorkflowIdentity{
		CallerRepository:  getExtension(cert, "1.3.6.1.4.1.57264.1.5"),
		Issuer:            getExtension(cert, "1.3.6.1.4.1.57264.1.1"),
		Trigger:           getExtension(cert, "1.3.6.1.4.1.57264.1.2"),
		CallerHash:        getExtension(cert, "1.3.6.1.4.1.57264.1.3"),
		JobWobWorkflowRef: cert.URIs[0].Path,
	}, nil
}
