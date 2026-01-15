FROM golang:1.22-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY . .
RUN go build -o /out/threat-intel .

FROM alpine:3.19
WORKDIR /app
COPY --from=build /out/threat-intel /usr/local/bin/threat-intel
EXPOSE 9090
ENTRYPOINT ["threat-intel"]
