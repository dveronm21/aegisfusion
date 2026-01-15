FROM golang:1.22-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY . .
RUN go build -o /out/sandbox .

FROM alpine:3.19
WORKDIR /app
COPY --from=build /out/sandbox /usr/local/bin/sandbox
ENTRYPOINT ["sandbox"]
