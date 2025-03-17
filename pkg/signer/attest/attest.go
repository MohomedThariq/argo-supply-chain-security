package attest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/MohomedThariq/argo-supply-chain-security/pkg/config"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/signer/auth"
	"github.com/MohomedThariq/argo-supply-chain-security/pkg/signer/sign"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/attest"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	csign "github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/attestation"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	cremote "github.com/sigstore/cosign/v2/pkg/cosign/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/cosign/v2/pkg/types"
	rclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

func AttestOci(ctx context.Context, cfg config.Config, rcfg config.RuntimeConfig, ociImage, keyRef string, payload []byte) (err error) {
	o := &options.AttestOptions{
		Key:            keyRef,
		RekorEntryType: "dsse",
		TlogUpload:     cfg.Transparency,
		Rekor: options.RekorOptions{
			URL: cfg.TransparencyURL,
		},
		Predicate: options.PredicateLocalOptions{
			PredicateOptions: options.PredicateOptions{
				Type: options.PredicateSLSA,
			},
		},
	}
	oidcClientSecret := "" // default
	ko := options.KeyOpts{
		KeyRef:                   o.Key,
		PassFunc:                 generate.GetPass,
		Sk:                       o.SecurityKey.Use,
		Slot:                     o.SecurityKey.Slot,
		FulcioURL:                o.Fulcio.URL,
		IDToken:                  o.Fulcio.IdentityToken,
		FulcioAuthFlow:           o.Fulcio.AuthFlow,
		InsecureSkipFulcioVerify: o.Fulcio.InsecureSkipFulcioVerify,
		RekorURL:                 o.Rekor.URL,
		OIDCIssuer:               o.OIDC.Issuer,
		OIDCClientID:             o.OIDC.ClientID,
		OIDCClientSecret:         oidcClientSecret,
		OIDCRedirectURL:          o.OIDC.RedirectURL,
		OIDCProvider:             o.OIDC.Provider,
		SkipConfirmation:         o.SkipConfirmation,
		TSAServerURL:             o.TSAServerURL,
	}
	c := attest.AttestCommand{
		KeyOpts:                 ko,
		RegistryOptions:         o.Registry,
		CertPath:                o.Cert,
		CertChainPath:           o.CertChain,
		NoUpload:                o.NoUpload,
		PredicateType:           o.Predicate.PredicateOptions.Type,
		Replace:                 o.Replace,
		TlogUpload:              o.TlogUpload,
		RekorEntryType:          o.RekorEntryType,
		RecordCreationTimestamp: o.RecordCreationTimestamp,
	}

	ref, err := name.ParseReference(ociImage)
	if err != nil {
		return fmt.Errorf("parsing reference: %w", err)
	}
	digest, ok := ref.(name.Digest)
	if !ok {
		return fmt.Errorf("digest not awailable in oci ref")
	}
	h, _ := v1.NewHash(digest.Identifier())

	ociremoteOpts, err := auth.RegistryClientOptsWithK8s(ctx, rcfg.InclusterClient, rcfg.Namespace, rcfg.Workflow)
	if err != nil {
		return fmt.Errorf("constructing oci client options: %w", err)
	}

	sv, err := sign.SignerFromKeyOpts(ctx, ko, false)
	if err != nil {
		return fmt.Errorf("getting signer: %w", err)
	}
	defer sv.Close()
	wrapped := dsse.WrapSigner(sv, types.IntotoPayloadType)
	dd := cremote.NewDupeDetector(sv)

	sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
		Predicate: bytes.NewReader(payload),
		Type:      c.PredicateType,
		Digest:    h.Hex,
		Repo:      digest.Repository.String(),
	})
	if err != nil {
		return err
	}

	payloadwithStatements, err := json.Marshal(sh)
	if err != nil {
		return err
	}

	signedPayload, err := wrapped.SignMessage(bytes.NewReader(payloadwithStatements), signatureoptions.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("signing: %w", err)
	}

	opts := []static.Option{static.WithLayerMediaType(types.DssePayloadType)}
	if sv.Cert != nil {
		opts = append(opts, static.WithCertChain(sv.Cert, sv.Chain))
	}

	predicateType, err := options.ParsePredicateType(c.PredicateType)
	if err != nil {
		return err
	}

	predicateTypeAnnotation := map[string]string{
		"predicateType": predicateType,
	}
	opts = append(opts, static.WithAnnotations(predicateTypeAnnotation))

	if c.TlogUpload {
		bundle, err := uploadToTlog(ctx, sv, c.RekorURL, func(r *rclient.Rekor, b []byte) (*models.LogEntryAnon, error) {
			return cosign.TLogUploadDSSEEnvelope(ctx, r, signedPayload, b)
		})
		if err != nil {
			return err
		}
		opts = append(opts, static.WithBundle(bundle))
	}

	sig, err := static.NewAttestation(signedPayload, opts...)
	if err != nil {
		return err
	}
	se := ociremote.SignedUnknown(digest, ociremoteOpts...)

	signOpts := []mutate.SignOption{
		mutate.WithDupeDetector(dd),
		mutate.WithRecordCreationTimestamp(c.RecordCreationTimestamp),
	}

	// Attach the attestation to the entity.
	newSE, err := mutate.AttachAttestationToEntity(se, sig, signOpts...)
	if err != nil {
		return err
	}

	// Publish the attestations associated with this entity
	return ociremote.WriteAttestations(digest.Repository, newSE, ociremoteOpts...)
}

type tlogUploadFn func(*rclient.Rekor, []byte) (*models.LogEntryAnon, error)

func uploadToTlog(ctx context.Context, sv *csign.SignerVerifier, rekorURL string, upload tlogUploadFn) (*cbundle.RekorBundle, error) {
	rekorBytes, err := sv.Bytes(ctx)
	if err != nil {
		return nil, err
	}

	rekorClient, err := rekor.NewClient(rekorURL)
	if err != nil {
		return nil, err
	}
	entry, err := upload(rekorClient, rekorBytes)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, "tlog entry created with index:", *entry.LogIndex)
	return cbundle.EntryToBundle(entry), nil
}

const (
	SampleAtt string = `{
  "builder": {
    "id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0"
  },
  "buildType": "https://github.com/slsa-framework/slsa-github-generator/container@v1",
  "invocation": {
    "configSource": {
      "uri": "git+https://github.com/argoproj/argo-cd@refs/tags/v2.14.2",
      "digest": {
        "sha1": "ad2724661b66ede607db9b5bd4c3c26491f5be67"
      },
      "entryPoint": ".github/workflows/release.yaml"
    },
    "parameters": {},
    "environment": {
      "github_actor": "leoluz",
      "github_actor_id": "44989",
      "github_base_ref": "",
      "github_event_name": "push",
      "github_event_payload": {
        "after": "ad2724661b66ede607db9b5bd4c3c26491f5be67",
        "base_ref": "refs/heads/release-2.14",
        "before": "0000000000000000000000000000000000000000",
        "commits": [],
        "compare": "https://github.com/argoproj/argo-cd/compare/v2.14.2",
        "created": true,
        "deleted": false,
        "forced": false,
        "head_commit": {
          "author": {
            "email": "41898282+github-actions[bot]@users.noreply.github.com",
            "name": "github-actions[bot]",
            "username": "github-actions[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "ad2724661b66ede607db9b5bd4c3c26491f5be67",
          "message": "Bump version to 2.14.2 on release-2.14 branch (#21797)\n\nSigned-off-by: github-actions[bot] \u003c41898282+github-actions[bot]@users.noreply.github.com\u003e\r\nCo-authored-by: leoluz \u003c44989+leoluz@users.noreply.github.com\u003e",
          "timestamp": "2025-02-05T18:39:56-05:00",
          "tree_id": "61f9f222f3db3228b96f0a7efadc6f5c8ad1ad54",
          "url": "https://github.com/argoproj/argo-cd/commit/ad2724661b66ede607db9b5bd4c3c26491f5be67"
        },
        "organization": {
          "avatar_url": "https://avatars.githubusercontent.com/u/30269780?v=4",
          "description": "Get stuff done with Kubernetes!",
          "events_url": "https://api.github.com/orgs/argoproj/events",
          "hooks_url": "https://api.github.com/orgs/argoproj/hooks",
          "id": 30269780,
          "issues_url": "https://api.github.com/orgs/argoproj/issues",
          "login": "argoproj",
          "members_url": "https://api.github.com/orgs/argoproj/members{/member}",
          "node_id": "MDEyOk9yZ2FuaXphdGlvbjMwMjY5Nzgw",
          "public_members_url": "https://api.github.com/orgs/argoproj/public_members{/member}",
          "repos_url": "https://api.github.com/orgs/argoproj/repos",
          "url": "https://api.github.com/orgs/argoproj"
        },
        "pusher": {
          "email": "leoluz@users.noreply.github.com",
          "name": "leoluz"
        },
        "ref": "refs/tags/v2.14.2",
        "repository": {
          "allow_forking": true,
          "archive_url": "https://api.github.com/repos/argoproj/argo-cd/{archive_format}{/ref}",
          "archived": false,
          "assignees_url": "https://api.github.com/repos/argoproj/argo-cd/assignees{/user}",
          "blobs_url": "https://api.github.com/repos/argoproj/argo-cd/git/blobs{/sha}",
          "branches_url": "https://api.github.com/repos/argoproj/argo-cd/branches{/branch}",
          "clone_url": "https://github.com/argoproj/argo-cd.git",
          "collaborators_url": "https://api.github.com/repos/argoproj/argo-cd/collaborators{/collaborator}",
          "comments_url": "https://api.github.com/repos/argoproj/argo-cd/comments{/number}",
          "commits_url": "https://api.github.com/repos/argoproj/argo-cd/commits{/sha}",
          "compare_url": "https://api.github.com/repos/argoproj/argo-cd/compare/{base}...{head}",
          "contents_url": "https://api.github.com/repos/argoproj/argo-cd/contents/{+path}",
          "contributors_url": "https://api.github.com/repos/argoproj/argo-cd/contributors",
          "created_at": 1518174721,
          "custom_properties": {},
          "default_branch": "master",
          "deployments_url": "https://api.github.com/repos/argoproj/argo-cd/deployments",
          "description": "Declarative Continuous Deployment for Kubernetes",
          "disabled": false,
          "downloads_url": "https://api.github.com/repos/argoproj/argo-cd/downloads",
          "events_url": "https://api.github.com/repos/argoproj/argo-cd/events",
          "fork": false,
          "forks": 5677,
          "forks_count": 5677,
          "forks_url": "https://api.github.com/repos/argoproj/argo-cd/forks",
          "full_name": "argoproj/argo-cd",
          "git_commits_url": "https://api.github.com/repos/argoproj/argo-cd/git/commits{/sha}",
          "git_refs_url": "https://api.github.com/repos/argoproj/argo-cd/git/refs{/sha}",
          "git_tags_url": "https://api.github.com/repos/argoproj/argo-cd/git/tags{/sha}",
          "git_url": "git://github.com/argoproj/argo-cd.git",
          "has_discussions": true,
          "has_downloads": true,
          "has_issues": true,
          "has_pages": true,
          "has_projects": true,
          "has_wiki": true,
          "homepage": "https://argo-cd.readthedocs.io",
          "hooks_url": "https://api.github.com/repos/argoproj/argo-cd/hooks",
          "html_url": "https://github.com/argoproj/argo-cd",
          "id": 120896210,
          "is_template": false,
          "issue_comment_url": "https://api.github.com/repos/argoproj/argo-cd/issues/comments{/number}",
          "issue_events_url": "https://api.github.com/repos/argoproj/argo-cd/issues/events{/number}",
          "issues_url": "https://api.github.com/repos/argoproj/argo-cd/issues{/number}",
          "keys_url": "https://api.github.com/repos/argoproj/argo-cd/keys{/key_id}",
          "labels_url": "https://api.github.com/repos/argoproj/argo-cd/labels{/name}",
          "language": "Go",
          "languages_url": "https://api.github.com/repos/argoproj/argo-cd/languages",
          "license": {
            "key": "apache-2.0",
            "name": "Apache License 2.0",
            "node_id": "MDc6TGljZW5zZTI=",
            "spdx_id": "Apache-2.0",
            "url": "https://api.github.com/licenses/apache-2.0"
          },
          "master_branch": "master",
          "merges_url": "https://api.github.com/repos/argoproj/argo-cd/merges",
          "milestones_url": "https://api.github.com/repos/argoproj/argo-cd/milestones{/number}",
          "mirror_url": null,
          "name": "argo-cd",
          "node_id": "MDEwOlJlcG9zaXRvcnkxMjA4OTYyMTA=",
          "notifications_url": "https://api.github.com/repos/argoproj/argo-cd/notifications{?since,all,participating}",
          "open_issues": 3640,
          "open_issues_count": 3640,
          "organization": "argoproj",
          "owner": {
            "avatar_url": "https://avatars.githubusercontent.com/u/30269780?v=4",
            "email": null,
            "events_url": "https://api.github.com/users/argoproj/events{/privacy}",
            "followers_url": "https://api.github.com/users/argoproj/followers",
            "following_url": "https://api.github.com/users/argoproj/following{/other_user}",
            "gists_url": "https://api.github.com/users/argoproj/gists{/gist_id}",
            "gravatar_id": "",
            "html_url": "https://github.com/argoproj",
            "id": 30269780,
            "login": "argoproj",
            "name": "argoproj",
            "node_id": "MDEyOk9yZ2FuaXphdGlvbjMwMjY5Nzgw",
            "organizations_url": "https://api.github.com/users/argoproj/orgs",
            "received_events_url": "https://api.github.com/users/argoproj/received_events",
            "repos_url": "https://api.github.com/users/argoproj/repos",
            "site_admin": false,
            "starred_url": "https://api.github.com/users/argoproj/starred{/owner}{/repo}",
            "subscriptions_url": "https://api.github.com/users/argoproj/subscriptions",
            "type": "Organization",
            "url": "https://api.github.com/users/argoproj",
            "user_view_type": "public"
          },
          "private": false,
          "pulls_url": "https://api.github.com/repos/argoproj/argo-cd/pulls{/number}",
          "pushed_at": 1738799012,
          "releases_url": "https://api.github.com/repos/argoproj/argo-cd/releases{/id}",
          "size": 125559,
          "ssh_url": "git@github.com:argoproj/argo-cd.git",
          "stargazers": 18594,
          "stargazers_count": 18594,
          "stargazers_url": "https://api.github.com/repos/argoproj/argo-cd/stargazers",
          "statuses_url": "https://api.github.com/repos/argoproj/argo-cd/statuses/{sha}",
          "subscribers_url": "https://api.github.com/repos/argoproj/argo-cd/subscribers",
          "subscription_url": "https://api.github.com/repos/argoproj/argo-cd/subscription",
          "svn_url": "https://github.com/argoproj/argo-cd",
          "tags_url": "https://api.github.com/repos/argoproj/argo-cd/tags",
          "teams_url": "https://api.github.com/repos/argoproj/argo-cd/teams",
          "topics": [
            "argo",
            "argo-cd",
            "cd",
            "ci-cd",
            "cicd",
            "continuous-delivery",
            "continuous-deployment",
            "devops",
            "docker",
            "gitops",
            "hacktoberfest",
            "helm",
            "jsonnet",
            "kubernetes",
            "kustomize",
            "pipeline"
          ],
          "trees_url": "https://api.github.com/repos/argoproj/argo-cd/git/trees{/sha}",
          "updated_at": "2025-02-05T22:19:25Z",
          "url": "https://github.com/argoproj/argo-cd",
          "visibility": "public",
          "watchers": 18594,
          "watchers_count": 18594,
          "web_commit_signoff_required": true
        },
        "sender": {
          "avatar_url": "https://avatars.githubusercontent.com/u/44989?v=4",
          "events_url": "https://api.github.com/users/leoluz/events{/privacy}",
          "followers_url": "https://api.github.com/users/leoluz/followers",
          "following_url": "https://api.github.com/users/leoluz/following{/other_user}",
          "gists_url": "https://api.github.com/users/leoluz/gists{/gist_id}",
          "gravatar_id": "",
          "html_url": "https://github.com/leoluz",
          "id": 44989,
          "login": "leoluz",
          "node_id": "MDQ6VXNlcjQ0OTg5",
          "organizations_url": "https://api.github.com/users/leoluz/orgs",
          "received_events_url": "https://api.github.com/users/leoluz/received_events",
          "repos_url": "https://api.github.com/users/leoluz/repos",
          "site_admin": false,
          "starred_url": "https://api.github.com/users/leoluz/starred{/owner}{/repo}",
          "subscriptions_url": "https://api.github.com/users/leoluz/subscriptions",
          "type": "User",
          "url": "https://api.github.com/users/leoluz",
          "user_view_type": "public"
        }
      },
      "github_head_ref": "",
      "github_ref": "refs/tags/v2.14.2",
      "github_ref_type": "tag",
      "github_repository_id": "120896210",
      "github_repository_owner": "argoproj",
      "github_repository_owner_id": "30269780",
      "github_run_attempt": "1",
      "github_run_id": "13168689639",
      "github_run_number": "457",
      "github_sha1": "ad2724661b66ede607db9b5bd4c3c26491f5be67"
    }
  },
  "metadata": {
    "buildInvocationID": "13168689639-1",
    "completeness": {
      "parameters": true,
      "environment": false,
      "materials": false
    },
    "reproducible": false
  },
  "materials": [
    {
      "uri": "git+https://github.com/argoproj/argo-cd@refs/tags/v2.14.2",
      "digest": {
        "sha1": "ad2724661b66ede607db9b5bd4c3c26491f5be67"
      }
    }
  ]
}`
)
