.PHONY: run build bindings test integration-tests unit-tests
run: bindings
	RUST_LOG=info cargo run --release --config 'target."cfg(all())".runner="sudo -E"' 2>&1
build: bindings
	cargo build --release
bindings: ipvs-tcp-from-scratch-ebpf/src/tracepoint_gen.rs ipvs-tcp-from-scratch-ebpf/src/ktypes.rs
	:
unit-tests:
	RUST_LOG=info cargo test
integration-tests:
	RUST_LOG=info cargo test --config 'target."cfg(all())".runner="firetest"' -- --ignored

test: unit-tests integration-tests
	:

ipvs-tcp-from-scratch-ebpf/src/tracepoint_gen.rs: Makefile
	aya-tool generate trace_event_raw_inet_sock_set_state trace_event_raw_tcp_event_sk_skb trace_event_raw_tcp_event_sk > $@
ipvs-tcp-from-scratch-ebpf/src/ktypes.rs: Makefile
	aya-tool generate nf_inet_addr sock netns_ipvs > $@
