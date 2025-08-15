SHELL := /bin/bash

.PHONY: help
help:
	@echo "Targets:"
	@echo "  docker-build   Build the toolkit container"
	@echo "  docker-run     Run the container with current dir mounted"
	@echo "  scan-network   Example safe network scan (requires AUTH_OK=1)"
	@echo "  scan-secrets   Example secrets scan of current dir"

docker-build:
	docker build -t security-toolkit ./docker

docker-run:
	docker run --rm -it -v "$$PWD:/workspace" --net=host -e AUTH_OK=1 security-toolkit bash

scan-network:
	AUTH_OK=1 scripts/bash/net_scan.sh 127.0.0.1 -sV --top-ports 50

scan-secrets:
	scripts/bash/secrets_scan.sh .
