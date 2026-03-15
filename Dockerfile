FROM golang:1.25 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /handler .

FROM public.ecr.aws/lambda/provided:al2023

COPY --from=builder /handler /var/runtime/bootstrap
CMD ["handler"]
