FROM golang:1.19.5-alpine3.17 AS builder

# Copy the repository into the working directory
WORKDIR /atomic-threat-hunter
COPY . .

# Compile the helper executable
RUN go build helper.go

# Remove .git files to avoid repository disclosure
RUN rm -rf .git .gitignore README.md docker-compose.yaml Dockerfile src/ go.mod helper.go LICENSE

# Install the necessary CLI tools for reconaissance and scanning
RUN apk add --no-cache gcc musl-dev
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/OWASP/Amass/v3/...@master
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Switch to Alpine image as a final base
FROM alpine:3.17.1 AS helper

# Get the Go binaries that we'll need into our executable path
COPY --from=builder /go/bin /bin/

# Copy built artifacts from builder container
WORKDIR /atomic-threat-hunter
COPY --from=builder /atomic-threat-hunter ./

ENTRYPOINT ["/atomic-threat-hunter/helper"]
