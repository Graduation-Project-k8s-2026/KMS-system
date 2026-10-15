ARG GO_IMAGE=docker.io/library/golang@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c
ARG RUNTIME_IMAGE=docker.io/library/debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
FROM ${GO_IMAGE} AS source
WORKDIR /src
ENV GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download
COPY . .
FROM source AS verify
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-yaml && rm -rf /var/lib/apt/lists/*
RUN go vet ./...
RUN CGO_ENABLED=1 go test -race ./...
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./...
RUN bash scripts/verify-release-contract.sh
RUN touch /verified
FROM source AS build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o /out/server ./cmd/server
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o /out/admin-api ./cmd/admin-api
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o /out/bench ./cmd/bench
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o /out/demo-app ./cmd/demo-app
FROM ${RUNTIME_IMAGE} AS runtime
USER 10001:10001
FROM runtime AS server
COPY --from=verify /verified /verified
COPY --from=build /out/server /usr/local/bin/server
ENTRYPOINT ["/usr/local/bin/server"]
FROM runtime AS admin-api
COPY --from=verify /verified /verified
COPY --from=build /out/admin-api /usr/local/bin/admin-api
ENTRYPOINT ["/usr/local/bin/admin-api"]
FROM runtime AS bench
COPY --from=verify /verified /verified
COPY --from=build /out/bench /usr/local/bin/bench
ENTRYPOINT ["/usr/local/bin/bench"]
FROM runtime AS demo-app
COPY --from=verify /verified /verified
COPY --from=build /out/demo-app /usr/local/bin/demo-app
ENTRYPOINT ["/usr/local/bin/demo-app"]
