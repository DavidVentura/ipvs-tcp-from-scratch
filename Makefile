.PHONY: run build
run:
	cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
build:
	cargo build --release
