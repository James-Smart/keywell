FROM golang:1.27 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" -o /out/keywell ./cmd/keywell \
 && mkdir /out/data

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/keywell /keywell
# An empty data directory owned by the nonroot user. A named volume copies its
# contents and ownership from the image the first time it is used, so this is
# what lets `keywell init` write the config and database as that user.
COPY --from=build --chown=65532:65532 /out/data /var/lib/keywell
VOLUME /var/lib/keywell
EXPOSE 8080
ENTRYPOINT ["/keywell"]
CMD ["serve", "--config", "/var/lib/keywell/keywell.yaml"]
