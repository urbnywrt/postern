# syntax=docker/dockerfile:1

# The image of a Postern node: postern-node and the launcher of deploy/node on
# the runner image of every Postern container. It is started with the command
# that the panel shows on the page of a node (docker run ... -e POSTERN_JOIN=...),
# and its entrypoint, postern-node bootstrap, joins the panel, lays out
# POSTERN_HOME as install.sh does, puts the binary, its signature and the
# launcher of the image into POSTERN_HOME/bin and runs the launcher there.
#
# Build from the root of the repository:
#
#   docker build -f deploy/node/Dockerfile -t postern-node:dev .
#
# Build arguments VERSION, COMMIT and DATE are what "postern-node version" says
# (the defaults say that it is a local build); EXTRA_PUBLIC_KEYS, minisign public
# keys apart by commas, are test keys that the binary trusts as well (for the
# end-to-end test). For both architectures:
#
#   docker buildx build --platform linux/amd64,linux/arm64 -f deploy/node/Dockerfile ...
#
# The build stage runs on the architecture of the machine that builds and
# cross-compiles; only the last stage runs on the architecture of the image.
#
# The image of a release is not built from the source but from the signed
# binaries of the release, which scripts/release.sh writes to dist/:
#
#   docker build --build-arg PREBUILT=dist -f deploy/node/Dockerfile .
#
# PREBUILT is a directory of the build context. The image then takes
# postern-node-linux-<architecture of the image> from there, byte for byte, with
# its signature (<file>.minisig) when there is one, and builds nothing. Without
# PREBUILT the binary is built from the source and has no signature.
ARG PREBUILT=
# The stage that the binary comes from: binary-source or binary-prebuilt.
ARG BINARY=${PREBUILT:+prebuilt}

# ---- the binary ----------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
ARG EXTRA_PUBLIC_KEYS=
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -e; \
    ldflags="-s -w \
      -X github.com/urbnywrt/postern/internal/version.Version=${VERSION} \
      -X github.com/urbnywrt/postern/internal/version.Commit=${COMMIT} \
      -X github.com/urbnywrt/postern/internal/version.Date=${DATE}"; \
    if [ -n "$EXTRA_PUBLIC_KEYS" ]; then \
      ldflags="$ldflags -X github.com/urbnywrt/postern/internal/release.extraPublicKeys=${EXTRA_PUBLIC_KEYS} \
        -X github.com/urbnywrt/postern/internal/release.productionReleaseKeys= \
        -X github.com/urbnywrt/postern/internal/release.productionStableKeys="; \
    fi; \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false -ldflags "$ldflags" -o /out/postern-node ./cmd/node

# ---- the binary: built above, or that of a release -----------------------------
# Either stage holds /postern-node, the prebuilt one also /postern-node.minisig
# when dist/ has it. Only the stages that the image needs are built: with
# PREBUILT, the Go stage does not run.
FROM scratch AS binary-source
COPY --from=build --chmod=0755 /out/postern-node /postern-node

FROM scratch AS binary-prebuilt
ARG PREBUILT
ARG TARGETARCH
COPY --chmod=0755 ${PREBUILT}/postern-node-linux-${TARGETARCH} /postern-node
# The character class in .minisi[g] makes it a wildcard, and a wildcard that
# matches nothing copies nothing: the build does not fail without a signature.
COPY --chmod=0644 ${PREBUILT}/postern-node-linux-${TARGETARCH}.minisi[g] /postern-node.minisig

FROM binary-${BINARY:-source} AS binary

# ---- the image -----------------------------------------------------------------
# The runner image of every Postern container, pinned by digest. Its
# ca-certificates-bundle is /etc/ssl/certs/ca-certificates.crt, which the TLS
# client of Go reads (the join, the registry of the releases).
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
ARG VERSION=dev
ARG COMMIT=none
ARG SOURCE=

# The whole of the binary stage is copied: it must hold postern-node and its
# signature and nothing else (the release integration test pins the listing of
# /usr/local/lib/postern).
COPY --from=binary / /usr/local/lib/postern/
COPY --chmod=0755 deploy/node/launcher.sh /usr/local/lib/postern/launcher.sh

LABEL postern.managed=true \
      postern.role=agent \
      postern.id=agent \
      org.opencontainers.image.source=${SOURCE} \
      org.opencontainers.image.version=${VERSION} \
      org.opencontainers.image.revision=${COMMIT}

ENV POSTERN_HOME=/opt/postern

# Root, on purpose: the agent manages the containers of the node through the
# Docker socket and writes the root-owned directories of POSTERN_HOME.
ENTRYPOINT ["/usr/local/lib/postern/postern-node"]
CMD ["bootstrap"]
