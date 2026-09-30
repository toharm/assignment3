CXX      := g++
CXXFLAGS := -std=c++20 -O2 -Wall -Wno-deprecated-declarations
OPENSSL  ?= /opt/homebrew/opt/openssl@3
ifneq ($(wildcard $(OPENSSL)/lib/libcrypto.dylib),)
CXXFLAGS += -I$(OPENSSL)/include
LDLIBS   := $(OPENSSL)/lib/libcrypto.dylib
else
LDLIBS   := -lcrypto
endif

SRC  := main.cpp
BIN  := aes_modes
BMPS := cp-logo.bmp mustang.bmp

.PHONY: all run clean

all: $(BIN)

$(BIN): $(SRC)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

run: $(BIN)
	@for f in $(BMPS); do \
		echo "encrypting $$f"; \
		./$(BIN) $$f || exit 1; \
	done

clean:
	rm -f $(BIN) encrypted_ecb_*.bmp encrypted_cbc_*.bmp submit_file submit_enc verify_file verify_dec