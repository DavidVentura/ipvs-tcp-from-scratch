.PHONY: run build bindings
run:
	cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
build:
	cargo build --release
bindings: ipvs-tcp-from-scratch-ebpf/src/tracepoint_gen.rs
	:
ipvs-tcp-from-scratch-ebpf/src/tracepoint_gen.rs: Makefile
	aya-tool generate trace_event_raw_inet_sock_set_state trace_event_raw_tcp_event_sk_skb trace_event_raw_tcp_event_sk > ipvs-tcp-from-scratch-ebpf/src/tracepoint_gen.rs
