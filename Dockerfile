# ---- build ----
FROM golang:1.22-alpine AS build
WORKDIR /src
ENV GOPROXY=https://goproxy.io,direct
COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/singbox-gen .

# ---- run ----
FROM scratch
COPY --from=build /out/singbox-gen /singbox-gen
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
EXPOSE 8090
ENTRYPOINT ["/singbox-gen", "-data", "/data"]