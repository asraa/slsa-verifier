package gha

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/rekor/pkg/client"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/register"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils/container"
)

const VerifierName = "GHA"

//nolint:gochecknoinits
func init() {
	register.RegisterVerifier(VerifierName, GHAVerifierNew())
}

type GHAVerifier struct{}

func GHAVerifierNew() *GHAVerifier {
	return &GHAVerifier{}
}

// IsAuthoritativeFor returns true of the verifier can verify provenance
// generated by the builderID.
func (v *GHAVerifier) IsAuthoritativeFor(builderID string) bool {
	// This verifier only supports builders defined on GitHub.
	return strings.HasPrefix(builderID, "https://github.com/")
}

func verifyEnvAndCert(env *dsse.Envelope,
	cert *x509.Certificate,
	provenanceOpts *options.ProvenanceOpts,
	builderOpts *options.BuilderOpts,
	defaultBuilders map[string]bool,
) ([]byte, *utils.TrustedBuilderID, error) {
	/* Verify properties of the signing identity. */
	// Get the workflow info given the certificate information.
	workflowInfo, err := GetWorkflowInfoFromCertificate(cert)
	if err != nil {
		return nil, nil, err
	}

	// Verify the workflow identity.
	builderID, err := VerifyWorkflowIdentity(workflowInfo, builderOpts,
		provenanceOpts.ExpectedSourceURI, defaultBuilders)
	if err != nil {
		return nil, nil, err
	}

	// Verify properties of the SLSA provenance.
	// Unpack and verify info in the provenance, including the Subject Digest.
	provenanceOpts.ExpectedBuilderID = builderID.String()
	if err := VerifyProvenance(env, provenanceOpts); err != nil {
		return nil, nil, err
	}

	fmt.Fprintf(os.Stderr, "Verified build using builder https://github.com%s at commit %s\n",
		workflowInfo.JobWobWorkflowRef,
		workflowInfo.CallerHash)
	// Return verified provenance.
	r, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, nil, err
	}

	return r, builderID, nil
}

// VerifyArtifact verifies provenance for an artifact.
func (v *GHAVerifier) VerifyArtifact(ctx context.Context,
	provenance []byte, artifactHash string,
	provenanceOpts *options.ProvenanceOpts,
	builderOpts *options.BuilderOpts,
) ([]byte, *utils.TrustedBuilderID, error) {
	// This includes a default retry count of 3.
	rClient, err := client.GetRekorClient(defaultRekorAddr)
	if err != nil {
		return nil, nil, err
	}

	trustedRoot, err := GetTrustedRoot(ctx)
	if err != nil {
		return nil, nil, err
	}

	/* Verify signature on the intoto attestation. */
	// TODO(https://github.com/slsa-framework/slsa-github-generator/issues/716):
	// We will also need to support bundles when those are complete.
	signedAtt, err := VerifyProvenanceSignature(ctx, trustedRoot, rClient,
		provenance, artifactHash)
	if err != nil {
		return nil, nil, err
	}

	return verifyEnvAndCert(signedAtt.Envelope, signedAtt.SigningCert,
		provenanceOpts, builderOpts,
		defaultArtifactTrustedReusableWorkflows)
}

// VerifyImage verifies provenance for an OCI image.
func (v *GHAVerifier) VerifyImage(ctx context.Context,
	provenance []byte, artifactImage string,
	provenanceOpts *options.ProvenanceOpts,
	builderOpts *options.BuilderOpts,
) ([]byte, *utils.TrustedBuilderID, error) {
	/* Retrieve any valid signed attestations that chain up to Fulcio root CA. */
	roots, err := fulcio.GetRoots()
	if err != nil {
		return nil, nil, err
	}
	opts := &cosign.CheckOpts{
		RootCerts: roots,
	}

	atts, _, err := container.RunCosignImageVerification(ctx,
		artifactImage, opts)
	if err != nil {
		return nil, nil, err
	}

	/* Now verify properties of the attestations */
	var errs []error
	var builderID *utils.TrustedBuilderID
	var verifiedProvenance []byte
	for _, att := range atts {
		pyld, err := att.Payload()
		if err != nil {
			fmt.Fprintf(os.Stderr, "unexpected error getting payload from OCI registry %s", err)
			continue
		}
		env, err := EnvelopeFromBytes(pyld)
		if err != nil {
			fmt.Fprintf(os.Stderr, "unexpected error parsing envelope from OCI registry %s", err)
			continue
		}
		cert, err := att.Cert()
		if err != nil {
			fmt.Fprintf(os.Stderr, "unexpected error getting certificate from OCI registry %s", err)
			continue
		}
		verifiedProvenance, builderID, err = verifyEnvAndCert(env,
			cert, provenanceOpts, builderOpts,
			defaultContainerTrustedReusableWorkflows)
		if err == nil {
			return verifiedProvenance, builderID, nil
		}
		errs = append(errs, err)
	}

	// Return the first error.
	if len(errs) > 0 {
		var s string
		if len(errs) > 1 {
			s = fmt.Sprintf(": %v", errs[1:])
		}
		return nil, nil, fmt.Errorf("%w%s", errs[0], s)
	}
	return nil, nil, fmt.Errorf("%w", serrors.ErrorNoValidSignature)
}
