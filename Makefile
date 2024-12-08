CC = gcc
CFLAGS = -Wall -Ishared -O2


# Directories
SHARED_DIR = shared
PROXY_DIR = proxy

# Source files
SHARED_SRC = $(wildcard $(SHARED_DIR)/*.c)
PROXY_SRC = $(wildcard $(PROXY_DIR)/*.c)

# Output executables
PROXY_OUT = proxy.out


# Ensure both server and clients are both built by default
all: $(PROXY_OUT)
server: $(PROXY_OUT) 

# Build the server executable
$(PROXY_OUT): $(PROXY_SRC) $(SHARED_SRC)
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto -lcurl

# Clean up the build files
clean:
	rm -f $(PROXY_OUT)
	rm certificates/*.pem
	rm openssl_custom.cnf

