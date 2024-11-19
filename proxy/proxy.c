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

#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>



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

    /* ALLOWS US TO REUSE SOCKETS*/
    int optval = 1;
    // Set the SO_REUSEADDR option to allow the socket to be reused
    if (setsockopt(listening_socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
        perror("setsockopt");
        close(listening_socket_fd);
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
void configure_context(SSL_CTX *ctx, const char* certificate, const char* key) {
    /* Set the key and cert */
    printf("HERE");
    if (SSL_CTX_use_certificate_file(ctx, certificate, SSL_FILETYPE_PEM) <= 0) {
        printf("HERE2");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    printf("HERE3");
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 ) {
        printf("HERE4");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}





void create_server_certificate(void) {
    // Create data structure for storing private key
    EVP_PKEY * pkey;
    pkey = EVP_PKEY_new();
    RSA * rsa;

    // Generate public/private key pair
    rsa = RSA_generate_key(
        2048,   /* number of bits for the key - 2048 is a sensible value */
        RSA_F4, /* exponent - RSA_F4 is defined as 0x10001L */
        NULL,   /* callback - can be NULL if we aren't displaying progress */
        NULL    /* callback argument - not needed in this case */
    );
    if(rsa == NULL) {
        printf("Failed to generate key for self-signed certificate. Exiting...\n");
        ERR_get_error();
        exit(EXIT_FAILURE);
    }

    // Assign key to data structure
    EVP_PKEY_assign_RSA(pkey, rsa);

    // Create x509 structure to represent certificate
    X509 * x509;
    x509 = X509_new();

    // Set certificate serial number to 1 (some HTTP servers refuse certificates with serial number 0)
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    
    // Set lifetime of certificate to 1 year
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    // Set certificate's public key to previously generate public key
    X509_set_pubkey(x509, pkey);

    // Get subject name to be used in self-signing the certificate
    // (the name of the issuer is the same as the name of the subject)
    X509_NAME * name;
    name = X509_get_subject_name(x509);

    // Provide country code ("C"), organization ("O") and common name ("CN")
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
                            (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
                            (unsigned char *)"Plano&Rolfe Inc.", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                            (unsigned char *)"localhost", -1, -1, 0);

    // Set the issuer name
    X509_set_issuer_name(x509, name);

    // Sign the certificate
    X509_sign(x509, pkey, EVP_sha1());

    // Write private key to disk as .pem file
    FILE * f;
    f = fopen("server_key.pem", "wb");
    PEM_write_PrivateKey(
        f,                  /* write the key to the file we've opened */
        pkey,               /* use key from earlier */
        EVP_des_ede3_cbc(), /* default cipher for encrypting the key on disk */
        "replace_me",       /* passphrase required for decrypting the key on disk */
        10,                 /* length of the passphrase string */
        NULL,               /* callback for requesting a password */
        NULL                /* data to pass to the callback */
    );
    fclose(f);


    // Write certificate to disk as .pem file
    // FILE * f;
    f = fopen("server_cert.pem", "wb");
    PEM_write_X509(
        f,   /* write the certificate to the file we've opened */
        x509 /* our certificate */
    );
    fclose(f);
}



void initialize_proxy(int listening_port) {

    // Declare variables
    int listening_socket_fd;
    struct sockaddr_in server_addr;
    SSL_CTX *ctx;

    // Ignore broken pipe signals 
    signal(SIGPIPE, SIG_IGN);

    // Create socket used for listening
    listening_socket_fd = create_socket(listening_port, &server_addr);

    char str_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(server_addr.sin_addr), str_addr, INET_ADDRSTRLEN);

    printf("Server Listening at address %.*s on port %d\n", INET_ADDRSTRLEN, str_addr, server_addr.sin_port);

    while(1) {
        /* Declare client address variables */
        struct sockaddr_in client_addr;
        unsigned int len = sizeof(client_addr);
        SSL *ssl;

        /* TODO variable reply */
        const char reply[] = "test\n";

        // Establish basic TCP connection with client (perform TCP handshake)
        printf("Prior to client connection\n");
        int client_socket = accept(listening_socket_fd, (struct sockaddr*)&client_addr, &len);
        if (client_socket < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        /* NEED TO READ HTTP GET FIRST BEFORE WE CAN DO ANYTHIGN*/
        // char buf[10000] = {0};
        // read(client_socket, buf, 10000);
        // printf("%.*s\n\n\n",100, buf);



        // Create server certificate and save to disk
        printf("Creating Certificate... \n");
        create_server_certificate();
        printf("Certificate created\n");

        // Prepare SSL Context object
        ctx = create_context();                                      // Get SSL Context to store TLS configuration parameters
        printf("Context created\n");
        /* TODO: I think there is somthing wrong with the vertificate files */
        configure_context(ctx, "server_cert.pem", "server_key.pem"); // Load certificate and private key into context
        //configure_context(ctx, "ca.crt", "ca.key"); // Load certificate and private key into context

        printf("Certificate loaded into context\n");

        // Set client connection to SSL (perform SSL handshake)
        printf("Creating new SSL object\n");
        ssl = SSL_new(ctx);                // Create SSL object
        printf("Calling SSL_set_fd\n");
        SSL_set_fd(ssl, client_socket);    // Link SSL object to accepted TCP socket
        printf("Done with SSL Stuff\n");
        if (SSL_accept(ssl) <= 0) {        // Perform SSL handshake
            printf("Unsuccessful client SSL handshake\n");
            ERR_print_errors_fp(stderr);
        } else {
            printf("OOOOOOOO");
            SSL_write(ssl, reply, strlen(reply));
        }
        printf("HEREHEREHERE");

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