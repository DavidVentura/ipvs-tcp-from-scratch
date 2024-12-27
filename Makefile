.PHONY: run build bindings
run:
	RUST_LOG=info cargo run --release --config 'target."cfg(all())".runner="sudo -E"' 2>&1 | grep --line-buffered -vE "127.0.0.1:8000|0.0.0.0"
build:
	cargo build --release
bindings: ipvs-tcp-from-scratch-ebpf/src/tracepoint_gen.rs
	:
ipvs-tcp-from-scratch-ebpf/src/tracepoint_gen.rs: Makefile
	aya-tool generate trace_event_raw_inet_sock_set_state trace_event_raw_tcp_event_sk_skb trace_event_raw_tcp_event_sk > ipvs-tcp-from-scratch-ebpf/src/tracepoint_gen.rs
