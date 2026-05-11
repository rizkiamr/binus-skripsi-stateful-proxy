# Stateful "Memory Tax" Proxy

## 1. Project Overview

The Stateful "Memory Tax" Proxy is an architectural eBPF/XDP proxy designed to simulate the performance characteristics of current state-of-the-art (SOTA) load balancers (e.g., Meta's Katran).

Its primary role in this research is to serve as the **"Memory-bound"** baseline. By utilizing standard eBPF map-based connection tracking (`BPF_MAP_TYPE_LRU_HASH`), we force the kernel to traverse the memory hierarchy (fetching cache lines, managing bucket locks, processing LRU evictions). This allows for the precise measurement of the "Memory Tax"—the computational overhead introduced by stateful memory lookups compared to register-bound, stateless algorithms.

## 2. Architecture & Project Structure

This project is built using the [Aya-rs](https://github.com/aya-rs/aya) framework and follows a strict workspace structure to separate kernel-space code, user-space loaders, and shared data structures.

```plain
stateful-proxy/
├── Cargo.toml               # Workspace configuration
├── README.md                # This file
├── common/                  # Shared data structures (`no_std`)
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs           # Defines `FlowKey` and `BackendInfo`
├── ebpf/                    # The eBPF XDP program
│   ├── Cargo.toml
│   ├── .cargo/
│   │   └── config.toml      # Target configuration (bpfel-unknown-none)
│   └── src/
│       └── main.rs          # XDP logic: Parsing, LRU Lookup, IPIP DSR, Checksums
├── user/                    # User-space control plane
│   ├── Cargo.toml
│   └── src/
│       └── main.rs          # Loads the XDP program, populates BACKENDS map
└── xtask/                   # Build automation
    ├── Cargo.toml
    └── src/
        └── main.rs          # `cargo xtask build-ebpf` runner
```

### Component Details
- `common`: Contains the `#[repr(C)]` structs. Specifically, the 5-tuple `FlowKey` (used as the LRU map key) and `BackendInfo` (Target IP and MAC).
- `ebpf`: The core forwarding engine. It intercepts packets at the XDP hook, parses Ethernet/IPv4/TCP headers, performs a 5-tuple lookup in the `CT_MAP` (`LruHashMap` of size 524,288), handles cache misses via a modulo hashing fallback, implements RFC 2003 IP-in-IP Direct Server Return (DSR), and modifies the packet via `bpf_xdp_adjust_head`.
- `user`: The Rust executable that attaches the compiled `.o` file to the specified network interface and manages the `BACKENDS` array.

## 3. Technical Constraints & Design Choices

- Strict Memory Bound: The `LruHashMap` size is explicitly set to `524,288` entries. This is designed to intentionally exceed L1/L2 cache capacities under synthetic traffic loads, forcing L3/DRAM accesses to accurately capture the "Memory Tax".
- No Register Optimization: The map lookup logic is strictly maintained for every single packet to ensure standard production-grade statefulness is accurately simulated.
- Control Variable (DSR): The IP-in-IP encapsulation logic perfectly mirrors the stateless variant of this proxy to ensure that the delta in instruction count and CPU cycles is exclusively attributed to the map lookup latency.

## 4. Prerequisites

To build and run this project, you need a modern Linux kernel (5.15.0+) and the Rust eBPF toolchain.

```bash
# 1. Install Rust nightly (required by Aya)
curl --proto '=https' --tlsv1.2 -sSf [https://sh.rustup.rs](https://sh.rustup.rs) | sh
rustup toolchain install nightly --component rust-src

# 2. Install bpf-linker
cargo install bpf-linker

# 3. Install bpftool (for profiling the Memory Tax)
sudo apt-get install linux-tools-common linux-tools-generic linux-tools-$(uname -r)
```

## 5. How to Build

We use the `xtask` pattern to compile the eBPF code into BPF bytecode (`.o`), followed by building the user-space loader.

```bash
# Step 1: Build the eBPF XDP program (outputs to target/bpfel-unknown-none/...)
cargo xtask build-ebpf --release

# Step 2: Build the user-space loader
cargo build --release
```

## 6. How to Run

The proxy requires `root` privileges to attach XDP programs and manipulate kernel maps.

```bash
# Replace 'eth0' with your target ingress interface
sudo RUST_LOG=info ./target/release/user --iface eth0
```

*The user-space process will remain running, keeping the XDP program attached. Press Ctrl+C to detach the proxy and exit.*

## 7. How to Test & Benchmark the "Memory Tax"

The primary goal of this repository is to measure the instruction count and CPU cycles per packet. To achieve this, use a synthetic traffic injector (e.g., `pktgen`, `TRex`, or `iperf3` with many parallel streams) alongside `bpftool`.

### Capturing the Baseline Metric

1. Start your synthetic traffic injector targeting the proxy's VIP.
2. Ensure you are generating enough unique flows to trigger LRU evictions and cache misses (e.g., > 1 Million PPS with randomized source ports/IPs).
3. While under load, profile the XDP program:

    ```bash
    # Find the Program ID of our XDP proxy
    sudo bpftool prog show
        
    # Profile the execution (Replace <PROG_ID> with the actual ID)
    # This measures instructions and CPU cycles over a 10-second window
    sudo bpftool prog profile <PROG_ID> duration 10
    ```

### Expected Results

You should observe a noticeably higher `instructions per packet` and `cycles per packet` compared to the stateless proxy. The delta between these two values represents the quantitative Memory Tax for this architecture.