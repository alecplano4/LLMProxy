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
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <fcntl.h>
#include <stdio.h>



// ----GLOBAL VARIABLES----------------------------------------------------------------------------
#define MAX_CLIENT_CONNECTIONS 10
#define HOST_NAME_LENGTH 100

X509 *create_signed_cert(SSL_CTX *root_ctx, const char *common_name);

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
    if (SSL_CTX_use_certificate_file(ctx, certificate, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

/* Given client connections request and a buffer, return
   the hostname from the connection request in the buffer*/ 
void extract_hostname(const char *request, char *hostname) {
    char *connect_ptr = strstr(request, "CONNECT ");
    if (connect_ptr) {
        // Move past "CONNECT "
        connect_ptr += 8;

        // Find the end of the hostname (up to the colon or space)
        char *hostname_end = strpbrk(connect_ptr, " :");
        if (hostname_end) {
            size_t hostname_len = hostname_end - connect_ptr;
            strncpy(hostname, connect_ptr, hostname_len);
            hostname[hostname_len] = '\0';  // Null-terminate the string
        } else {
            // No valid end found
            hostname[0] = '\0';
        }
    } else {
        // "CONNECT " not found
        hostname[0] = '\0';
    }
}


void create_server_certificate(const char *root_cert_file, const char *root_key_file, char* hostname, char* server_cert_file, char* server_key_file) {
    
    EVP_PKEY *root_key = NULL;
    X509 *root_cert = NULL;
    X509_REQ *csr = NULL;
    X509 *server_cert = NULL;

    /*---LOAD ROOT CERTIFICATE-----------------------------------------------*/

    // Load root certificate
    FILE *fp = fopen(root_cert_file, "r");
    if (!fp) {
        perror("Failed to open root certificate");
        return;
    }
    root_cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);

    // Load root private key
    fp = fopen(root_key_file, "r");
    if (!fp) {
        perror("Failed to open root private key");
        return;
    }
    root_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    printf("Successfully loaded root certificate\n");

    /*---GENERATE SERVER CERTIFICATE-----------------------------------------*/
    /* Certificates are generated using Certificate Signing Requests (CSR). 
    The steps are as follows:
    1. Generate new public/private key pair for the server certificate
    2. Create new CSR using server key
    3. Sign CSR using root certificate 
    4. Save */

    // 1. Generate public/private key pair for server certificate
    EVP_PKEY* server_key = EVP_PKEY_new();  // data structure for storing private key
    RSA* rsa = RSA_generate_key(
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
    EVP_PKEY_assign_RSA(server_key, rsa);     // Assign key to data structure
    printf("Successfully generated key for server certificate\n");

    // 2. Create a new Certificate Signing Request (CSR). Use server's private key
    //    in creation of CSR and sign using root certificate private key
    csr = X509_REQ_new();
    X509_REQ_set_version(csr, 1);  // Version 1
    X509_REQ_set_pubkey(csr, server_key);

    // Provide country code ("C"), organization ("O") and common name ("CN")
    printf("Adding fields to CSR\n");
    X509_NAME *name = X509_REQ_get_subject_name(csr);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"Example", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *) hostname, -1, -1, 0);

    // Add the server's private key to the CSR
    X509_REQ_sign(csr, server_key, EVP_sha256());

    // Create the server certificate
    server_cert = X509_new();
    X509_set_version(server_cert, 2);  // Version 3
    ASN1_INTEGER_set(X509_get_serialNumber(server_cert), 1);
    X509_gmtime_adj(X509_get_notBefore(server_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(server_cert), 31536000L);  // 1 year validity
    X509_set_subject_name(server_cert, X509_REQ_get_subject_name(csr));
    X509_set_issuer_name(server_cert, X509_get_subject_name(root_cert));  // Root is the issuer
    X509_set_pubkey(server_cert, server_key);

    // Sign the server certificate with the root private key
    X509_sign(server_cert, root_key, EVP_sha256());

    // Save the server certificate amd private key to a file
    strcpy(server_cert_file, hostname);
    strcpy(server_key_file, hostname);
    strcat(server_cert_file, ".crt");
    strcat(server_key_file, ".key");
    
    printf("File name of server certificate: %s\n", server_cert_file);
    printf("File name of server pirvate key: %s\n", server_key_file);

    fp = fopen(server_cert_file, "w");
    PEM_write_X509(fp, server_cert);
    fclose(fp);

    fp = fopen(server_key_file, "w");
    PEM_write_PrivateKey(fp, server_key, NULL, NULL, 0, NULL, NULL);
    fclose(fp);

    // Cleanup
    X509_free(root_cert);
    EVP_PKEY_free(root_key);
    EVP_PKEY_free(server_key);
    X509_REQ_free(csr);
    X509_free(server_cert);

    printf("Server certificate and private key generated and signed successfully.\n");

    // // Create x509 structure to represent server certificate
    // X509 * x509;
    // x509 = X509_new();

    // // Set certificate serial number to 1 (some HTTP servers refuse certificates with serial number 0)
    // ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    
    // // Set lifetime of certificate to 1 year
    // X509_gmtime_adj(X509_get_notBefore(x509), 0);
    // X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    // // Set certificate's public key to previously generated public key
    // X509_set_pubkey(x509, pkey);

    // // Get subject name to be used in self-signing the certificate
    // // (the name of the issuer is the same as the name of the subject)
    // X509_NAME * name;
    // name = X509_get_subject_name(x509);

    // // Provide country code ("C"), organization ("O") and common name ("CN")
    // X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
    //                         (unsigned char *)"US", -1, -1, 0);
    // X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
    //                         (unsigned char *)"Plano&Rolfe Inc.", -1, -1, 0);
    // X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
    //                         (unsigned char *)"localhost", -1, -1, 0);

    // // Set the issuer name
    // X509_set_issuer_name(x509, name);

    // // Sign the certificate
    // X509_sign(x509, pkey, EVP_sha1());

    // // Write private key to disk as .pem file
    // FILE * f;
    // f = fopen("server_key.pem", "wb");
    // PEM_write_PrivateKey(
    //     f,                  /* write the key to the file we've opened */
    //     pkey,               /* use key from earlier */
    //     EVP_des_ede3_cbc(), /* default cipher for encrypting the key on disk */
    //     "replace_me",       /* passphrase required for decrypting the key on disk */
    //     10,                 /* length of the passphrase string */
    //     NULL,               /* callback for requesting a password */
    //     NULL                /* data to pass to the callback */
    // );

    // // Write certificate to disk as .pem file
    // // FILE * f;
    // f = fopen("server_cert.pem", "wb");
    // PEM_write_X509(
    //     f,   /* write the certificate to the file we've opened */
    //     x509 /* our certificate */
    // );
}


void initialize_proxy(int listening_port) {

    const char *root_cert_file = "ca.crt";
    const char *root_key_file = "ca.key";
    char server_cert_file[HOST_NAME_LENGTH];
    char server_key_file[HOST_NAME_LENGTH];
    
    // Declare variables
    int listening_socket_fd;
    struct sockaddr_in server_addr;
    SSL_CTX *ctx;

    // Ignore broken pipe signals 
    signal(SIGPIPE, SIG_IGN);

    // Create socket and begin listening using TCP
    listening_socket_fd = create_socket(listening_port, &server_addr);

    while(1) {
        struct sockaddr_in client_addr;
        unsigned int len = sizeof(client_addr);
        SSL *ssl;
        const char reply[] = "test\n";

        // Establish basic TCP connection with client (perform TCP handshake)
        int client_socket = accept(listening_socket_fd, (struct sockaddr*)&client_addr, &len);
        if (client_socket < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }
        printf("Client TCP handshake successful\n");

        // Receive client data
        char request[200];
        char hostname[100];
        int bytes_received = recv(client_socket, request, sizeof(request)-1, 0);
        printf("Bytes received: %d\n", bytes_received);
        printf("Message: %s", request);
        extract_hostname(request, hostname);
        printf("Hostname: %s\n", hostname);

        // Client expects "Connection Established" response to CONNECT request.
        // Must be sent for client to initiate SSL handshake
        if (strstr(request, "CONNECT") == request) {
            // Respond with "HTTP/1.1 200 Connection Established"
            const char *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
            send(client_socket, response, strlen(response), 0);
            printf("Sent response to client:\n%s\n", response);

            // Here, you would establish a connection to the target server
            // and relay data between the client and server (not implemented here).

            // Create server certificate and save to disk
            create_server_certificate(root_cert_file, root_key_file, hostname, server_cert_file, server_key_file);
            printf("\n--------------------\nCERTIFICATE CREATED\n--------------------\n\n");

            // Prepare SSL Context object
            ctx = create_context();                                      // Get SSL Context to store TLS configuration parameters
            printf("Context created\n");
            configure_context(ctx, server_cert_file, server_key_file); // Load certificate and private key into context
            printf("Certificate loaded into context\n");

            // Set client connection to SSL (perform SSL handshake)
            ssl = SSL_new(ctx);                // Create SSL object
            SSL_set_fd(ssl, client_socket);    // Link SSL object to accepted TCP socket
            printf("SSL object created and linked to TCP socket\n");

            if (SSL_accept(ssl) <= 0) {        // Perform SSL handshake
                printf("Unsuccessful client SSL handshake\n");
                ERR_print_errors_fp(stderr);
            } else {
                printf("SSL handshake completed.\n");
            }

            // Receive message from client
            bytes_received = SSL_read(ssl, request, sizeof(request) - 1);
            if (bytes_received > 0) {
                request[bytes_received] = '\0'; // Null-terminate the received message
                printf("Received message from client: %s\n", request);
            } else {
                printf("SSL_read failed");
                exit(EXIT_FAILURE);
            }

            // Close SSL connection and free data structure
            SSL_shutdown(ssl);
            SSL_free(ssl);
        } else {
            fprintf(stderr, "Invalid request: Not a CONNECT request\n");
        }
    }
    close(listening_socket_fd);
}


// void initialize_proxy(int listening_port) {

//     // Declare files
//     const char *root_cert_file = "ca.crt";
//     const char *root_key_file = "ca.key";
//     const char *server_cert_file = "server.crt";
//     const char *server_key_file = "server.key";

//     // Declare variables
//     int listening_socket_fd;
//     struct sockaddr_in server_addr;
//     SSL_CTX *ctx;

//     // Ignore broken pipe signals 
//     signal(SIGPIPE, SIG_IGN);

//     // Prepare SSL Context object
//     ctx = create_context();                                      // Get SSL Context to store TLS configuration parameters
//     printf("Context created\n");
//     configure_context(ctx, "server_cert.pem", "server_key.pem"); // Load certificate and private key into context
//     //configure_context(ctx, "ca.crt", "ca.key"); // Load certificate and private key into context
//     // printf("Certificate loaded into context\n");
//     // ssl_init(&ctx, "server_cert.pem", "server_key.pem");

//     // Create root context (to generate signed certificates)
//     SSL_CTX *root_ctx = SSL_CTX_new(TLS_server_method());
//     if (!root_ctx) {
//         perror("SSL_CTX_new failed");
//         exit(1);
//     }

//     // Create socket used for listening
//     listening_socket_fd = create_socket(listening_port, &server_addr);

//     // int flags = fcntl(listening_socket_fd, F_GETFL, 0);
//     // fcntl(listening_socket_fd, F_SETFL, flags & ~O_NONBLOCK);

//     char str_addr[INET_ADDRSTRLEN];
//     inet_ntop(AF_INET, &(server_addr.sin_addr), str_addr, INET_ADDRSTRLEN);
//     printf("Server Listening at address %.*s on port %d\n", INET_ADDRSTRLEN, str_addr, server_addr.sin_port);

//     while(1) {
//         /* Declare client address variables */
//         struct sockaddr_in client_addr;
//         unsigned int len = sizeof(client_addr);
//         SSL *ssl;

//         /* TODO variable reply */
//         const char reply[] = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>Simple Web Page</title></head><body><h1>Hello, World!</h1></body></html>";

//         // Establish basic TCP connection with client (perform TCP handshake)
//         printf("Prior to client connection\n");
//         int client_socket = accept(listening_socket_fd, (struct sockaddr*)&client_addr, &len);
//         if (client_socket < 0) {
//             perror("Unable to accept");
//             exit(EXIT_FAILURE);
//         }

//         /* NEED TO READ HTTP GET FIRST BEFORE WE CAN DO ANYTHIGN*/
//         // char buf[10000] = {0};
//         // read(client_socket, buf, 10000);
//         // printf("%.*s\n\n\n",100, buf);



//         // Create server certificate and save to disk
//         printf("Creating Certificate... \n");
//         create_server_certificate(root_cert_file, root_key_file);
//         printf("Certificate created\n");

//         // // Prepare SSL Context object
//         // ctx = create_context();                                      // Get SSL Context to store TLS configuration parameters
//         // printf("Context created\n");
//         // /* TODO: I think there is somthing wrong with the vertificate files */
//         // configure_context(ctx, "server_cert.pem", "server_key.pem"); // Load certificate and private key into context
//         // //configure_context(ctx, "ca.crt", "ca.key"); // Load certificate and private key into context

//         // printf("Certificate loaded into context\n");

//         // Set client connection to SSL (perform SSL handshake)
//         printf("Creating new SSL object\n");
//         ssl = SSL_new(ctx);                // Create SSL object
//         printf("Calling SSL_set_fd\n");
//         SSL_set_fd(ssl, client_socket);    // Link SSL object to accepted TCP socket
//         printf("Done with SSL Stuff\n");

//         int ret  = SSL_accept(ssl);

//         X509 *new_cert = create_signed_cert(root_ctx, "www.example.com");

//         // Send the certificate to the client
//         SSL_write(ssl, new_cert, sizeof(new_cert));

//         if (ret <= 0) {        // Perform SSL handshake
//             int i = SSL_get_error(ssl,ret);
//             printf("Unsuccessful client SSL handshake %d\n", i);
//             ERR_print_errors_fp(stderr);
//         } else {
//             printf("OOOOOOOO");
//             SSL_write(ssl, reply, strlen(reply));
//         }
//         printf("HEREHEREHERE");

//         // Close SSL connection and free data structure
//         SSL_shutdown(ssl);
//         SSL_free(ssl);
//     }

//     // NOTE: Alec's code, may need to uncomment
//     // int clientfd;
//     // struct sockaddr_in peeraddr;
//     // socklen_t peeraddr_len = sizeof(peeraddr);
    
//     // SSL_CTX* ctx;
//     // ssl_init(&ctx, "ca.crt", "ca.key");

//     //clientfd = accept(servfd, (struct sockaddr *)&peeraddr, &peeraddr_len);

//     // if (clientfd < 0){
//     //     printf("accept()");
//     //     exit(EXIT_FAILURE);
//     // }

//     //ssl_client_init(&client, clientfd, SSLMODE_SERVER);

//     // while(1){
//     //     //add port to list
//     //}

//     // Close socket
//     close(listening_socket_fd);

// }


    //Assumption
    //ALEC: Assume getting an encrypted messgae
    //funciton will need string header, key from client to decrypte

// void proxy_connect_client(){

// }

// void ssl_init(SSL_CTX** ctx, const char *certfile, const char *keyfile){

//     SSL_library_init();
//     OpenSSL_add_all_algorithms();
//     SSL_load_error_strings();
//     #if OPENSSL_VERSION_MAJOR < 3
//     ERR_load_BIO_strings(); // deprecated since OpenSSL 3.0
//     #endif
//     ERR_load_crypto_strings();

//     /* create the SSL server context */
//     *ctx = SSL_CTX_new(TLS_method());
//     if (!ctx) {
//         printf("SSL_CTX_new()");
//         exit(EXIT_FAILURE);
//     }

//     /* Load certificate and private key files, and check consistency */
//     if (certfile && keyfile) {
//         if (SSL_CTX_use_certificate_file(*ctx, certfile,  SSL_FILETYPE_PEM) != 1)
//             printf("SSL_CTX_use_certificate_file failed");

//         if (SSL_CTX_use_PrivateKey_file(*ctx, keyfile, SSL_FILETYPE_PEM) != 1)
//             printf("SSL_CTX_use_PrivateKey_file failed");

//         /* Make sure the key and certificate file match. */
//         if (SSL_CTX_check_private_key(*ctx) != 1)
//             printf("SSL_CTX_check_private_key failed");
//         else
//             printf("certificate and private key loaded and verified\n");
//     }


//     /* Recommended to avoid SSLv2 & SSLv3 */
//     SSL_CTX_set_options(*ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
// }

// X509 *create_signed_cert(SSL_CTX *root_ctx, const char *common_name) {
//     EVP_PKEY *pkey = EVP_PKEY_new();
//     X509 *x509 = X509_new();
    
//     // Generate a new RSA key for the certificate
//     RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
//     EVP_PKEY_assign_RSA(pkey, rsa);

//     // Set certificate version (X.509 v3)
//     X509_set_version(x509, 2);
//     ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    
//     // Set the subject and issuer (subject is the CN)
//     X509_NAME *name = X509_get_subject_name(x509);
//     X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)common_name, -1, -1, 0);

//     // Set the public key
//     X509_set_pubkey(x509, pkey);

//     // Set the certificate's validity period
//     X509_gmtime_adj(X509_get_notBefore(x509), 0);
//     X509_gmtime_adj(X509_get_notAfter(x509), 3650 * 24 * 60 * 60); // Valid for 10 years

//     // Sign the certificate with the root CA's private key
//     if (SSL_CTX_use_certificate_file(root_ctx, ROOT_CERT, SSL_FILETYPE_PEM) <= 0) {
//         perror("SSL_CTX_use_certificate_file failed");
//         exit(1);
//     }

//     if (SSL_CTX_use_PrivateKey_file(root_ctx, ROOT_CERT, SSL_FILETYPE_PEM) <= 0) {
//         perror("SSL_CTX_use_PrivateKey_file failed");
//         exit(1);
//     }

//     if (X509_sign(x509, pkey, EVP_sha256()) == 0) {
//         perror("X509_sign failed");
//         exit(1);
//     }

//     return x509;
// }