FROM golang:1.22-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY . .
RUN go build -o /out/api .

FROM alpine:3.19
WORKDIR /app
COPY --from=build /out/api /usr/local/bin/api
EXPOSE 8081
ENTRYPOINT ["api"]
