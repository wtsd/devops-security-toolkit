# Container for the defensive security toolkit
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git jq nmap python3 python3-pip php-cli php-xml php-mbstring \
    bash coreutils grep sed findutils procps iproute2 net-tools \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY docker/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# Optional: install gitleaks
RUN curl -sSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
  | jq -r '.assets[] | select(.name | test("linux_x64.tar.gz$")) | .browser_download_url' \
  | xargs -I {} sh -c 'curl -sSL {} -o /tmp/gitleaks.tgz && tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks || true'

# Optional: install trufflehog (v3 single binary)
RUN curl -sSL https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest \
  | jq -r '.assets[] | select(.name | test("linux_amd64$")) | .browser_download_url' \
  | xargs -I {} sh -c 'curl -sSL {} -o /usr/local/bin/trufflehog && chmod +x /usr/local/bin/trufflehog || true'

WORKDIR /toolkit
COPY . .

# Default workdir to mounted workspace
WORKDIR /workspace
ENTRYPOINT ["/bin/bash"]
