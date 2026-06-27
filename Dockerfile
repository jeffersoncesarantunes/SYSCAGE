FROM alpine:3.20 AS builder
RUN apk add --no-cache gcc musl-dev make linux-headers
WORKDIR /src
COPY Makefile src/ include/ tests/ ./
RUN make clean && make

FROM scratch
COPY --from=builder /src/bin/syscage /syscage
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
USER 65534:65534
ENTRYPOINT ["/syscage"]
