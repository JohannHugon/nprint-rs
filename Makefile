.PHONY: all test distclean

CMD = cargo
BUILD = build --release
FORMAT = fmt --check
CLIPPY = clippy --all
TEST = test --all

SOURCES = $(wildcard **/*.rs)
TESTS = $(wildcard **/*.rs)
TARGET = target/release/libnprint_rs.rlib

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CMD) $(BUILD)

test: $(TARGET)
	$(CMD) $(FORMAT) && \
	$(CMD) $(CLIPPY) && \
	$(CMD) $(TEST)

distclean:
	rm -rf target Cargo.lock
