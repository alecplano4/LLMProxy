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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>






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


    int clientfd;
    struct sockaddr_in peeraddr;
    socklen_t peeraddr_len = sizeof(peeraddr);
    
    SSL_CTX* ctx;
    ssl_init(&ctx, "ca.crt", "ca.key");

    //clientfd = accept(servfd, (struct sockaddr *)&peeraddr, &peeraddr_len);

    if (clientfd < 0){
        printf("accept()");
        exit(EXIT_FAILURE);
    }

    //ssl_client_init(&client, clientfd, SSLMODE_SERVER);

    // while(1){
    //     //add port to list

    //}
    // Close socket
    close(listening_socket);

}


    //Assumption
    //ALEC: Assume getting an encrypted messgae
    //funciton will need string header, key from client to decrypte

void proxy_connect_client(){

}

void ssl_init(SSL_CTX** ctx, const char *certfile, const char *keyfile){

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    #if OPENSSL_VERSION_MAJOR < 3
    ERR_load_BIO_strings(); // deprecated since OpenSSL 3.0
    #endif
    ERR_load_crypto_strings();

    /* create the SSL server context */
    *ctx = SSL_CTX_new(TLS_method());
    if (!ctx) {
        printf("SSL_CTX_new()");
        exit(EXIT_FAILURE);
    }

    /* Load certificate and private key files, and check consistency */
    if (certfile && keyfile) {
        if (SSL_CTX_use_certificate_file(*ctx, certfile,  SSL_FILETYPE_PEM) != 1)
            printf("SSL_CTX_use_certificate_file failed");

        if (SSL_CTX_use_PrivateKey_file(*ctx, keyfile, SSL_FILETYPE_PEM) != 1)
            printf("SSL_CTX_use_PrivateKey_file failed");

        /* Make sure the key and certificate file match. */
        if (SSL_CTX_check_private_key(*ctx) != 1)
            printf("SSL_CTX_check_private_key failed");
        else
            printf("certificate and private key loaded and verified\n");
    }


    /* Recommended to avoid SSLv2 & SSLv3 */
    SSL_CTX_set_options(*ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
}