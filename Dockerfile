FROM golang:1.27.2-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" -o /out/scan ./cmd/scan

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/scan /scan
COPY LICENSE THIRD_PARTY_NOTICES.md /licenses/
USER 65532:65532
ENTRYPOINT ["/scan"]
CMD ["--help"]
