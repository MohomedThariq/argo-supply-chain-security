#!/bin/bash

# Check if input file is provided
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 [image1 image2 ...]"
    exit 1
fi

IMAGE_LIST=("$@")

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
key="k8s://argo-slsa/signing-secret"

check_multi_arch() {
    local image="$1"
    # Get manifest and check for manifest list using regctl
    if regctl manifest get "$image" --format {{.MediaType}} 2>/dev/null | grep -q "application/vnd.docker.distribution.manifest.list.v2+json"; then
        echo "true"
    else
        echo "false"
    fi
}

verify_image_signature() {
    local image="$1"
    # Verify the image signature using cosign
    if cosign verify --key ${key} "$image" 2>/dev/null; then
        echo "true"
    else
        echo "false"
    fi
}

check_for_SLSA_provenance() {
    local image="$1"
    # Check for SLSA provenance using cosign
    if cosign verify-attestation --key ${key} --type slsaprovenance1 "$image" 2>/dev/null; then
        echo "true"
    else
        echo "false"
    fi
}

get_sbom() {
    local image="$1"
    # Get the SBOM using cosign
    if cosign verify-attestation --key ${key} --type cyclonedx "$image" | jq -r ".payload" | base64 -d | jq -r ".predicate" > sbom.json; then
        echo "true"
    else
        echo "false"
    fi
}

for image in "${IMAGE_LIST[@]}"; do
    # Check if the image is signed
    if verify_image_signature "$image" | grep -q "true"; then
        signed=0
    else 
        signed=1
    fi

    # Check for SLSA provenance
    if check_for_SLSA_provenance "$image" | grep -q "true"; then
        slsa=0
    else 
        slsa=1
    fi

    # Check if the image is a manifest list
    if check_multi_arch "$image" | grep -q "true"; then
        multiArch=0
    else 
        multiArch=1
    fi

    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Image Analysis Results${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Image:${NC} $image"
    
    if [ $signed -eq 0 ]; then
        echo -e "${YELLOW}Signature:${NC} ${GREEN}✓ Verified${NC}"
    else
        echo -e "${YELLOW}Signature:${NC} ${RED}✗ Not verified${NC}"
    fi
    
    if [ $slsa -eq 0 ]; then
        echo -e "${YELLOW}SLSA Compliance:${NC} ${GREEN}✓ Verified${NC}"
    else
        echo -e "${YELLOW}SLSA Compliance:${NC} ${RED}✗ Not verified${NC}"
    fi
    
    if [ $multiArch -eq 0 ]; then
        echo -e "${YELLOW}Multi-arch:${NC} ${GREEN}✓ Supported${NC}"
    else
        echo -e "${YELLOW}Multi-arch:${NC} ${RED}✗ Not supported${NC}"
    fi

    if [ $multiArch -ne 0 ]; then
        if get_sbom "$image" | grep -q "true"; then
            echo -e "${YELLOW}SBOM:${NC} ${GREEN}✓ Retrieved${NC}"

            echo -e "${YELLOW}Vulnerability Scan result:${NC}"
            grype sbom:./sbom.json
            echo ""
            rm sbom.json
        else
            echo -e "${YELLOW}SBOM:${NC} ${RED}✗ Not retrieved${NC}"
        fi
    else
        echo ""
        regctl manifest get --format raw-body $image | \
            jq -r '.manifests[] | "\(.platform.os)/\(.platform.architecture) \(.digest)"' | \
            while read -r platform digest; do
                if get_sbom "$image@$digest" 2>/dev/null | grep -q "true"; then
                    echo -e "${YELLOW}SBOM for $platform:${NC} ${GREEN}✓ Retrieved${NC}"

                    echo -e "${YELLOW}Vulnerability Scan result for $platform:${NC}"
                    grype sbom:./sbom.json
                    echo ""
                    rm sbom.json
                else
                    echo -e "${YELLOW}SBOM:${NC} ${RED}✗ Not retrieved${NC}"
                fi
            done
    fi
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════════════════════════════════════${NC}\n"
done