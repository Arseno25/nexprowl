# syntax=docker/dockerfile:1

# ─── build ────────────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS build

# Version metadata, injected at link time. Override on the build command line:
#   docker build --build-arg VERSION=0.1.0 --build-arg COMMIT=$(git rev-parse HEAD) .
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

WORKDIR /src

# Dependencies first so the module cache survives source-only changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=0
RUN go build -trimpath \
    -ldflags="-s -w \
      -X github.com/Arseno25/nexprowl/internal/scanner.Version=${VERSION} \
      -X github.com/Arseno25/nexprowl/internal/scanner.Commit=${COMMIT} \
      -X github.com/Arseno25/nexprowl/internal/scanner.Date=${DATE}" \
    -o /out/nexprowl .

# ─── runtime ──────────────────────────────────────────────────────────────
# distroless/static ships CA certificates and a nonroot user, and nothing else:
# no shell, no package manager, no interpreters.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/nexprowl /usr/local/bin/nexprowl

# Scan output lands here. Mount a host directory over it to keep results:
#   docker run --rm -v "$PWD/results:/results" ghcr.io/arseno25/nexprowl example.com
WORKDIR /results

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/nexprowl"]
CMD ["--help"]

# ─── limitations ──────────────────────────────────────────────────────────
# -screenshot does NOT work in this image. It shells out to an installed
# Chrome/Chromium, and adding a browser would grow the image from ~10 MB to
# several hundred MB and reintroduce a shell and a large CVE surface. Run
# screenshot scans with a natively installed binary, or build your own image
# FROM this one with chromium plus its font and library dependencies added.
#
# The container runs as an unprivileged user. Raw-socket features are not used
# by NexProwl (port scanning is a TCP connect scan), so no extra capabilities
# are required.
