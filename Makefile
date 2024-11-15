CC = gcc
CFLAGS = -Wall -Ishared

#LDFLAGS = -lssl -lcrypto

# Directories
SHARED_DIR = shared
PROXY_DIR = proxy
CLIENT_DIR = client
TEST_DIR = test

# Source files
SHARED_SRC = $(wildcard $(SHARED_DIR)/*.c)
SERVER_SRC = $(wildcard $(PROXY_DIR)/*.c)
CLIENT_SRC = $(wildcard $(CLIENT_DIR)/*.c)
TEST_SRC = $(wildcard $(TEST_DIR)/*.c)

# Output executables
SERVER_OUT = server.out
CLIENT_OUT = client.out
TEST_OUT = test.out

# Ensure both server and clients are both built by default
all: $(SERVER_OUT) $(CLIENT_OUT) $(TEST_OUT)

# Build the server executable
$(SERVER_OUT): $(SERVER_SRC) $(SHARED_SRC)
	$(CC) $(CFLAGS) -o $@ $^

# Build the client executable
$(CLIENT_OUT): $(CLIENT_SRC) $(SHARED_SRC)
	$(CC) $(CFLAGS) -o $@ $^

# Build the client executable
$(TEST_OUT): $(TEST_SRC) $(SHARED_SRC) proxy/proxy.c client/client.c
	$(CC) $(CFLAGS) -o $@ $^

test_client.out: 
	gcc -o test_client.out openssl-bio-fetch.c

# Clean up the build files
clean:
	rm -f $(SERVER_OUT) $(CLIENT_OUT) $(TEST_OUT)

