FROM golang:1.18 AS build
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && apt-get install -y --no-install-recommends libpcap-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
COPY ./capture-fwd ./capture-fwd
WORKDIR /src/capture-fwd
RUN go build

FROM debian:bullseye-slim
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /
COPY --from=build /src/capture-fwd/capture-fwd .
ENTRYPOINT ["/capture-fwd"]
RUN /capture-fwd -help
