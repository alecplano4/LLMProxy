//----HEADER---------------------------------------------------------------------------------------
// Date:        November 2024
// Script:      proxy.c
// Usage:       Implementation file for proxy
//*************************************************************************************************
#include "proxy.h"

#include <stdio.h>
#include <sys/socket.h>
#include <errno.h>      // Allows for printing of perror()
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>



// ----GLOBAL VARIABLES----------------------------------------------------------------------------
#define MAX_CLIENT_CONNECTIONS 10

//----FUNCTIONS------------------------------------------------------------------------------------
// Given port number and pointer to address struct, create TCP socket,
// bind to port number, and begin listening. Return socket file descriptor 
// and address struct
int create_socket(int port, struct sockaddr_in* server_addr)
{
    int listening_socket_fd;
    char IP_address[INET_ADDRSTRLEN];

    // Initialize fields of struct for server address
    memset(server_addr, 0, sizeof(struct sockaddr_in));  // Set structure to 0's, ensuring sin_zero is all zeros
    server_addr->sin_family = AF_INET;                   // Set address family to IPv4
    server_addr->sin_addr.s_addr = htonl(INADDR_ANY);    // Set IP address to all IP addresses of machine
    server_addr->sin_port = htons(port);                 // Set port number

    listening_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listening_socket_fd < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(listening_socket_fd, (struct sockaddr*) server_addr, sizeof(struct sockaddr_in)) < 0) {
        perror("Error binding listening socket");
        exit(EXIT_FAILURE);
    }

    if (listen(listening_socket_fd, MAX_CLIENT_CONNECTIONS) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections requests on "listening socket"
    listen(listening_socket_fd, MAX_CLIENT_CONNECTIONS);
    inet_ntop(AF_INET, &(server_addr->sin_addr), IP_address, INET_ADDRSTRLEN);
    printf("Listening for incoming connection requests... \nIP Address: %s \nPort: %d\n\n", IP_address, port);

    return listening_socket_fd;
}

// Return SSL Context data structure, used to store
// configuration settings and parameters for SSL connections
SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Load certificate and private key into SSL Context object
void configure_context(SSL_CTX *ctx) {
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "ca.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "ca.key", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void initialize_proxy(int listening_port) {

    // Declare variables
    int listening_socket_fd;
    struct sockaddr_in server_addr;
    SSL_CTX *ctx;

    /* Ignore broken pipe signals */
    signal(SIGPIPE, SIG_IGN);

    // Prepare SSL Context object
    ctx = create_context(); // Get SSL Context to store TLS configuration parameters
    configure_context(ctx); // Load certificate and private key into context

    // Create listening socket using TCP
    listening_socket_fd = create_socket(listening_port, &server_addr);

    while(1) {
        struct sockaddr_in client_addr;
        unsigned int len = sizeof(client_addr);
        SSL *ssl;
        const char reply[] = "test\n";

        // Establish basic TCP connection with client (perform TCP handshake)
        printf("Prior to client connection\n");
        int client = accept(listening_socket_fd, (struct sockaddr*)&client_addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }
        printf("Successful client connection\n");

        // Set client connection to SSL (perform SSL handshake)
        ssl = SSL_new(ctx);                // Create SSL object
        SSL_set_fd(ssl, client);           // Link SSL object to accepted TCP socket
        if (SSL_accept(ssl) <= 0) {        // Perform SSL handshake
            printf("Unsuccessful client SSL handshake\n");
            ERR_print_errors_fp(stderr);
        } else {
            SSL_write(ssl, reply, strlen(reply));
        }

        // Close SSL connection and free data structure
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    // NOTE: Alec's code, may need to uncomment
    // int clientfd;
    // struct sockaddr_in peeraddr;
    // socklen_t peeraddr_len = sizeof(peeraddr);
    
    // SSL_CTX* ctx;
    // ssl_init(&ctx, "ca.crt", "ca.key");

    //clientfd = accept(servfd, (struct sockaddr *)&peeraddr, &peeraddr_len);

    // if (clientfd < 0){
    //     printf("accept()");
    //     exit(EXIT_FAILURE);
    // }

    //ssl_client_init(&client, clientfd, SSLMODE_SERVER);

    // while(1){
    //     //add port to list
    //}

    // Close socket
    close(listening_socket_fd);

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