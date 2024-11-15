//----HEADER---------------------------------------------------------------------------------------
// Date:        November 2024
// Script:      proxy.c
// Usage:       Implementation file for proxy
//*************************************************************************************************
#include "proxy.h"

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h> // Provides sockaddr_in struct
#include <errno.h>      // Allows for printing of perror()
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

// ----GLOBAL VARIABLES----------------------------------------------------------------------------
#define MAX_CLIENT_CONNECTIONS 10

//----FUNCTIONS------------------------------------------------------------------------------------

void initialize_proxy(int listening_port) {

    // Declare variables
    int listening_socket;
    struct sockaddr_in server_addr;
    char IP_address[INET_ADDRSTRLEN];

    // Create listening socket using TCP
    listening_socket = socket(AF_INET, SOCK_STREAM, 0);
    if(listening_socket < 0) {
        perror("Error creating listening socket");
        exit(EXIT_FAILURE);
    }

    // Initialize fields of struct for server address
    memset(&server_addr, 0, sizeof(server_addr));  // Set structure to 0's, ensuring sin_zero is all zeros
    server_addr.sin_family = AF_INET;              // Set address family to IPv4
    server_addr.sin_addr.s_addr = INADDR_ANY;      // Set IP address to all IP addresses of machine
    server_addr.sin_port = htons(listening_port);  // Set port number

    // Bind socket to IP address and port
    if(bind(listening_socket, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0 ){
        perror("Error binding listening socket");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections requests on "listening socket"
    listen(listening_socket, MAX_CLIENT_CONNECTIONS);
    inet_ntop(AF_INET, &(server_addr.sin_addr), IP_address, INET_ADDRSTRLEN);
    printf("Listening for incoming connection requests... \nIP Address: %s \nPort: %d\n\n", IP_address, listening_port);

    // Close socket
    close(listening_socket);

}


    //Assumption
    //ALEC: Assume getting an encrypted messgae
    //funciton will need string header, key from client to decrypte

void forward_header(){
    printf("heheh\n");
    //Decrypte header from client
    //encrytp https request
    //send it to internet
    //recieve message back
    //unencrypt message

}

//-------------------------------------------------------------------------------------------------
