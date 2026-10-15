# syntax=docker/dockerfile:1

# The image of the Postern panel. The web UI is built in one stage and the Go
# binaries in another, so neither toolchain is in the image; what is in it is the
# runner image of every Postern container, su-exec, the binary and two scripts,
# and the node kit: postern-node of the same version for amd64 and arm64 with the
# installer of deploy/node, which the panel serves for the manual install of nodes.
#
# Build from the root of the repository:
#
#   docker build -f deploy/panel/Dockerfile -t postern-panel:dev .
#
# Build arguments VERSION, COMMIT and DATE are what "postern-panel version" and
# "postern-node version" say (the defaults say that it is a local build). Build an
# image that nodes are installed from with --build-arg VERSION=<version>: install.sh
# installs the binary of the kit under the version that it prints, and a "dev"
# binary can be installed only once per host under that name. For both
# architectures of the panel:
#
#   docker buildx build --platform linux/amd64,linux/arm64 -f deploy/panel/Dockerfile ...
#
# The two build stages run on the architecture of the machine that builds and
# cross-compile; only the last stage runs on the architecture of the image.
#
# The image of a release is not built from the source but from the signed
# binaries of the release, which scripts/release.sh writes to dist/:
#
#   docker build --build-arg PREBUILT=dist -f deploy/panel/Dockerfile .
#
# PREBUILT is a directory of the build context. The image then takes
# postern-panel-linux-<architecture of the image> and both postern-node-linux-amd64
# and postern-node-linux-arm64 from there, byte for byte, the node binaries with
# their signatures (<file>.minisig), and builds nothing: no UI, no Go. The kit then
# has <arch>/postern-node.minisig next to each binary, and VERSION, COMMIT and DATE
# are those of the release, which its binaries carry. Without PREBUILT the
# binaries are built from the source, the UI first, and the kit is not signed.
ARG PREBUILT=
# The stage that the binaries come from: binaries-source or binaries-prebuilt.
ARG BINARIES=${PREBUILT:+prebuilt}

# ---- the web UI ----------------------------------------------------------------
FROM --platform=$BUILDPLATFORM node:24-alpine AS web
WORKDIR /web
# Without a web/ directory, or without web/package.json in it, there is no UI to
# build: the stage is empty and the panel gets the placeholder page that is in the
# source tree. The character class in we[b] keeps the COPY lines from failing for
# a directory that is not there; a wildcard that matches nothing copies nothing.
COPY we[b]/package.json we[b]/package-lock.json* ./
RUN if [ -f package.json ]; then npm ci --no-audit --no-fund; fi
COPY we[b]/ ./
RUN mkdir /out \
 && if [ -f package.json ]; then \
      npm run build && cp -r dist/. /out/; \
    else \
      echo "web/package.json does not exist: the image gets the placeholder page, not the UI" >&2; \
    fi

# ---- the binaries --------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
# NODE_IMAGE is the default node image of the panel (version.NodeImage), e.g.
# ghcr.io/<OWNER>/postern-node; POSTERN_NODE_IMAGE overrides it. Empty for none.
# Only the panel is built with it; with PREBUILT the panel binary keeps the one
# that it was built with.
ARG NODE_IMAGE=
# One set of flags for the panel and the node binaries, so that a node installed
# from the kit has the version of the panel.
ENV POSTERN_LDFLAGS="-s -w \
    -X github.com/urbnywrt/postern/internal/version.Version=${VERSION} \
    -X github.com/urbnywrt/postern/internal/version.Commit=${COMMIT} \
    -X github.com/urbnywrt/postern/internal/version.Date=${DATE}"
WORKDIR /src
COPY . .
# The module and build caches are kept between builds. Nothing is downloaded that
# a build of the panel does not need.
#
# The node binaries of the kit, for both architectures that nodes run on, whatever
# the architecture of the panel. They do not need the UI, so they are built while
# the web stage runs.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -e; \
    for arch in amd64 arm64; do \
      CGO_ENABLED=0 GOOS=linux GOARCH=$arch \
      go build -trimpath -buildvcs=false -ldflags "$POSTERN_LDFLAGS" \
        -o /out/node-kit/$arch/postern-node ./cmd/node; \
    done
# The UI that was built above goes over the placeholder page. Of the directory,
# .dockerignore lets only the placeholder in, so no file of an older build is left
# next to the new ones.
COPY --from=web /out/ internal/panel/webui/dist/
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false \
      -ldflags "$POSTERN_LDFLAGS -X github.com/urbnywrt/postern/internal/version.NodeImage=${NODE_IMAGE}" \
      -o /out/postern-panel ./cmd/panel

# ---- the binaries: built above, or those of a release --------------------------
# Either stage holds /postern-panel and /node-kit/<arch>/postern-node, and the
# image takes them from the one that BINARIES names. Only the stages that the
# image needs are built: with PREBUILT, neither the UI nor the Go stage runs.
FROM scratch AS binaries-source
COPY --from=build --chmod=0755 /out/postern-panel /postern-panel
COPY --from=build --chmod=0755 /out/node-kit/ /node-kit/

FROM scratch AS binaries-prebuilt
ARG PREBUILT
ARG TARGETARCH
COPY --chmod=0755 ${PREBUILT}/postern-panel-linux-${TARGETARCH} /postern-panel
COPY --chmod=0755 ${PREBUILT}/postern-node-linux-amd64 /node-kit/amd64/postern-node
COPY --chmod=0644 ${PREBUILT}/postern-node-linux-amd64.minisig /node-kit/amd64/postern-node.minisig
COPY --chmod=0755 ${PREBUILT}/postern-node-linux-arm64 /node-kit/arm64/postern-node
COPY --chmod=0644 ${PREBUILT}/postern-node-linux-arm64.minisig /node-kit/arm64/postern-node.minisig

FROM binaries-${BINARIES:-source} AS binaries

# ---- the image -----------------------------------------------------------------
# The runner image of every Postern container, pinned by digest.
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8

# su-exec is how entrypoint.sh gives up root. The version is that of the package in
# this release of Alpine, so that a build does not change under the same digest.
RUN apk add --no-cache su-exec=0.2-r3 \
 && mkdir /data /keys \
 && chown 65532:65532 /data /keys \
 && chmod 0700 /data /keys

COPY --from=binaries /postern-panel /usr/local/bin/postern-panel
COPY --chmod=0755 deploy/panel/launcher.sh deploy/panel/entrypoint.sh /usr/local/bin/

# The node kit (POSTERN_NODE_KIT_DIR): the installer with the two files that it
# installs, and postern-node for each architecture in a directory of its own,
# with its signature in the image of a release.
COPY --chmod=0755 deploy/node/install.sh deploy/node/launcher.sh /usr/local/share/postern/node-kit/
COPY --chmod=0644 deploy/node/compose.yaml /usr/local/share/postern/node-kit/
COPY --from=binaries /node-kit/ /usr/local/share/postern/node-kit/

ENV POSTERN_DATA=/data \
    POSTERN_KEYS=/keys \
    POSTERN_LISTEN=:8080 \
    POSTERN_NODE_KIT_DIR=/usr/local/share/postern/node-kit

EXPOSE 8080
# /data is the database and what the panel downloads; /keys is the master key, a
# volume of its own so that a copy of /data does not give the secrets away.
VOLUME ["/data", "/keys"]

# There is no USER line on purpose. The container has to start as root for
# entrypoint.sh to make /data and /keys belong to the panel's user when they are
# bind mounts that belong to somebody else; it then drops root with su-exec to
# 65532:65532, before it runs the launcher or the binary, so the panel itself never
# runs as root. Starting the container with --user skips the step, and the panel
# runs as that user.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["serve"]
