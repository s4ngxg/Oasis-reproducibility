CXX ?= g++
CPPFLAGS ?= -Iinclude
CXXFLAGS ?= -std=c++17 -O2 -pthread -Wall -Wextra -Wpedantic -Werror
LDLIBS ?= -lssl -lcrypto

BUILD := build
ADAPTER := bin/oasis_arc_adapter
TRANSPORT := bin/oasis_transport
CONFORMANCE := bin/oasis_core_conformance
BINARIES := $(ADAPTER) $(TRANSPORT) $(CONFORMANCE)
CORE_OBJECT := $(BUILD)/core.o

.PHONY: all sanitize clean

all: $(BINARIES)

$(BUILD) bin:
	mkdir -p $@

$(BUILD)/core.o: src/core.cpp include/oasis/core.hpp | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

$(BUILD)/oasis_arc_adapter.o: src/oasis_arc_adapter.cpp include/oasis/core.hpp | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

$(BUILD)/oasis_core_conformance.o: src/oasis_core_conformance.cpp include/oasis/core.hpp | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

$(BUILD)/oasis_transport.o: src/oasis_transport.cpp include/oasis/core.hpp | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

$(ADAPTER): $(CORE_OBJECT) $(BUILD)/oasis_arc_adapter.o | bin
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)

$(TRANSPORT): $(CORE_OBJECT) $(BUILD)/oasis_transport.o | bin
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)

$(CONFORMANCE): $(CORE_OBJECT) $(BUILD)/oasis_core_conformance.o | bin
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)

sanitize:
	mkdir -p /tmp/oasis-preswap-sanitize
	$(CXX) $(CPPFLAGS) -std=c++17 -O1 -g -pthread -Wall -Wextra \
		-Wpedantic -Werror -fsanitize=address,undefined \
		-fno-omit-frame-pointer src/core.cpp src/oasis_core_conformance.cpp \
		-o /tmp/oasis-preswap-sanitize/oasis_core_conformance $(LDLIBS)
	$(CXX) $(CPPFLAGS) -std=c++17 -O1 -g -pthread -Wall -Wextra \
		-Wpedantic -Werror -fsanitize=address,undefined \
		-fno-omit-frame-pointer src/core.cpp src/oasis_transport.cpp \
		-o /tmp/oasis-preswap-sanitize/oasis_transport $(LDLIBS)
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
		/tmp/oasis-preswap-sanitize/oasis_core_conformance --vectors 200
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
		/tmp/oasis-preswap-sanitize/oasis_transport test --vectors 200

clean:
	rm -f $(BUILD)/*.o $(BINARIES)
