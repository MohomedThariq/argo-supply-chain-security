package syft

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/google/go-containerregistry/pkg/authn"
)

func GenerateSBOMwithSyft(ctx context.Context, keychain authn.Keychain, oci string) ([]byte, error) {
	syftSourceOpts := syft.DefaultGetSourceConfig()
	syftSourceOpts.SourceProviderConfig.RegistryOptions = &image.RegistryOptions{
		Keychain: keychain,
	}

	src, err := syft.GetSource(ctx, oci, syftSourceOpts)
	if err != nil {
		if strings.Contains(err.Error(), "unknown layer media type") {
			return nil, err
		}
		return nil, fmt.Errorf("fetching image source: %w", err)
	}

	sbom, err := syft.CreateSBOM(ctx, src, syft.DefaultCreateSBOMConfig())
	if err != nil {
		return nil, fmt.Errorf("generating SBOM: %w", err)
	}

	// convert the SBOM into a CycloneDX format
	encoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		return nil, fmt.Errorf("creating CycloneDX encoder: %w", err)
	}
	var buffer bytes.Buffer
	if err := encoder.Encode(&buffer, *sbom); err != nil {
		return nil, fmt.Errorf("encoding SBOM: %w", err)
	}

	return buffer.Bytes(), nil
}
