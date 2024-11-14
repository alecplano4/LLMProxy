CC = gcc
CFLAGS = -Wall -Ishared

# Directories
SHARED_DIR = shared
PROXY_DIR = proxy
CLIENT_DIR = client

# Source files
SHARED_SRC = $(wildcard $(SHARED_DIR)/*.c)
SERVER_SRC = $(wildcard $(PROXY_DIR)/*.c)
CLIENT_SRC = $(wildcard $(CLIENT_DIR)/*.c)

# Output executables
SERVER_OUT = server.out
CLIENT_OUT = client.out

# Ensure both server and clients are both built by default
all: $(SERVER_OUT) $(CLIENT_OUT)

# Build the server executable
$(SERVER_OUT): $(SERVER_SRC) $(SHARED_SRC)
	$(CC) $(CFLAGS) -o $@ $^

# Build the client executable
$(CLIENT_OUT): $(CLIENT_SRC) $(SHARED_SRC)
	$(CC) $(CFLAGS) -o $@ $^

# Clean up the build files
clean:
	rm -f $(SERVER_OUT) $(CLIENT_OUT)

