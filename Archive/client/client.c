//----HEADER---------------------------------------------------------------------------------------
// Date:        November 2024
// Script:      client.c
// Usage:       Implementation file for client
//*************************************************************************************************
#include "client.h"

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h> 
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

// ----GLOBAL VARIABLES----------------------------------------------------------------------------

//----FUNCTIONS------------------------------------------------------------------------------------

// Given server port, connect to server and return client socket
int connect_to_server(int SERVER_PORT){
    int client_socket;
    struct sockaddr_in server_addr;
    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);

    // Create socket for server connection
    client_socket = socket(AF_INET, SOCK_STREAM, 0);

    // Initialize fields of struct for server address
    memset(&server_addr, 0, sizeof(server_addr));  // Set structure to 0's, ensuring sin_zero is all zeros
    server_addr.sin_family = AF_INET;              // Set address family to IPv4
    server_addr.sin_addr.s_addr = INADDR_ANY;      // Set IP address to all IP addresses of machine
    server_addr.sin_port = htons(SERVER_PORT);     // Set port number

    // Connect to server
    if(connect(client_socket, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("Unable to connect to server");
        close(client_socket);
    }

    // Get the local address and port of the socket (source port)
    if (getsockname(client_socket, (struct sockaddr*)&local_addr, &addr_len) == -1) {
        perror("getsockname() failed");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    // Print the local port (source port)
    printf("Source port: %d\n", ntohs(local_addr.sin_port));

    printf("Connected to the server\n");
    return client_socket;
}

// Given client socket, disconnect from server
void disconnect_from_server(int client_socket){
    close(client_socket);
}



//-------------------------------------------------------------------------------------------------
