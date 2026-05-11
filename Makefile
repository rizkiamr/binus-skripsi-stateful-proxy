# Variables
IFACE ?= ens33
BPF_TARGET = bpfel-unknown-none
CARGO = cargo
SUDO = sudo

.PHONY: all build build-ebpf build-user setup run detach clean help

all: build

## @ Build Targets
build: build-ebpf build-user ## Build both eBPF and User-space components

build-ebpf: ## Build the eBPF XDP program
	$(CARGO) build -p ebpf --release --target $(BPF_TARGET) -Z build-std=core

build-user: ## Build the user-space loader
	$(CARGO) build -p user --release

## @ Operational Targets
setup: ## Enable BPF statistics for performance measurement
	$(SUDO) sysctl -w kernel.bpf_stats_enabled=1

run: build ## Build and run the proxy (Usage: make run IFACE=ens33)
	$(SUDO) IFACE=$(IFACE) ./target/release/user

detach: ## Detach the XDP program from the interface
	$(SUDO) ip link set dev $(IFACE) xdp off

## @ Cleanup Targets
clean: ## Clean build artifacts
	$(CARGO) clean

help: ## Display this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
