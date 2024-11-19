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


// int create_server_certificate() {


//     /*------------------------------------*/
//         //FILE *root_cert_file = fopen("/Users/alecplano/Library/Application Support/Certificate Authority/Alec Plano’s CA/Alec Plano’s CA certificates.pem", "r");

//         FILE *root_cert_file = fopen("ca.crt", "r");
//         FILE *root_key_file = fopen("ca.key", "r");

//         if (!root_key_file) {
//             fprintf(stderr, "private key file.\n");
//             exit(EXIT_FAILURE);
//         }

//         if (!root_cert_file) {
//             fprintf(stderr, "Error opening root certificate\n");
//             exit(EXIT_FAILURE);
//         }

//         X509 *root_cert = PEM_read_X509(root_cert_file, NULL, NULL, NULL);
//         EVP_PKEY *root_key = PEM_read_PrivateKey(root_key_file, NULL, NULL, NULL);

//         fclose(root_cert_file);
//         fclose(root_key_file);

//         if (!root_key) {
//             fprintf(stderr, "Error reading private key.\n");
//             exit(EXIT_FAILURE);
//         }

//         if (!root_cert) {
//             fprintf(stderr, "Error reading root certificate\n");
//             exit(EXIT_FAILURE);
//         }




//     /*------------------------------------*/

//     // Generate RSA private key
//     EVP_PKEY *pkey = EVP_PKEY_new();
//     RSA *rsa = RSA_new();
//     BIGNUM *bn = BN_new();
//     int key_len = 2048;
//     BN_set_word(bn, 65537);
//     if (!bn || !RSA_generate_key_ex(rsa, key_len, bn, NULL)) {
//         printf("Error with RSA_generate_key_ex");
//         exit(EXIT_FAILURE);
//     }
//     EVP_PKEY_assign_RSA(pkey, rsa);

//     // Step 3: Create a new X.509 certificate
//     X509 *x509 = X509_new();
//     if (!x509) {
//         printf("Error with x509");
//         exit(EXIT_FAILURE);    }

//     // Set the version of the certificate (version 3)
//     if (X509_set_version(x509, 2) != 1) {
//         printf("Error with X509_set_version");
//         exit(EXIT_FAILURE);
//     }

//     // Step 4: Set the certificate's serial number
//     ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

//     // Step 5: Set the validity period of the certificate
//     ASN1_TIME_set(X509_get_notBefore(x509), time(NULL)); // current time
//     ASN1_TIME_set(X509_get_notAfter(x509), time(NULL) + 10 * 24 * 60 * 60); // 10 years

//     // Step 6: Set the subject name of the certificate (e.g., "localhost")
//     X509_NAME *name = X509_get_subject_name(x509);
//     X509_NAME_add_entry_by_txt(name, "C", 0, (unsigned char *)"US", -1, -1, 0);
//     X509_NAME_add_entry_by_txt(name, "ST", 0, (unsigned char *)"MA", -1, -1, 0);
//     X509_NAME_add_entry_by_txt(name, "L", 0, (unsigned char *)"BOS", -1, -1, 0);
//     X509_NAME_add_entry_by_txt(name, "O", 0, (unsigned char *)"Sam&Alec CO.", -1, -1, 0);
//     X509_NAME_add_entry_by_txt(name, "OU", 0, (unsigned char *)"My Org", -1, -1, 0);
//     X509_NAME_add_entry_by_txt(name, "CN", 0, (unsigned char *)"localhost", -1, -1, 0);

//     // Set the issuer name (for self-signed, the issuer is the same as the subject)
//     X509_set_issuer_name(x509, name);

//     // Step 7: Set the public key for the certificate
//     if (X509_set_pubkey(x509, pkey) != 1) {
//         printf("Error with X509_set_pubkey");
//         exit(EXIT_FAILURE);
//     }

//     // Step 8: Sign the certificate with the private key
//     if (X509_sign(x509, pkey, EVP_sha256()) <= 0) {
//         printf("Error with X509_sign");
//         exit(EXIT_FAILURE);
//     }

//     // Step 9: Write the private key to the PEM file
//     FILE *key_file = fopen("server_key.pem", "wb");
//     if (!key_file) {
//         perror("Unable to open file for writing private key");
//         return 1;
//     }
//     if (PEM_write_PrivateKey(key_file, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
//         perror("Error writing private key to file");
//         fclose(key_file);
//         return 1;
//     }
//     fclose(key_file);

//     // Step 10: Write the certificate to the PEM file
//     FILE *cert_file = fopen("server_cert.pem", "wb");
//     if (!cert_file) {
//         perror("Unable to open file for writing certificate");
//         return 1;
//     }
//     if (PEM_write_X509(cert_file, x509) != 1) {
//         perror("Error writing certificate to file");
//         fclose(cert_file);
//         return 1;
//     }
//     fclose(cert_file);

//     // Clean up
//     EVP_PKEY_free(pkey);
//     X509_free(x509);
//     BN_free(bn);

//     printf("Server private key and certificate successfully created.\n");
//     return 0;
// }


void create_server_certificate(void) {

/*------------------------------------*/
    FILE *root_cert_file = fopen("ca.crt", "r");
    FILE *root_key_file = fopen("ca.key", "r");

    if (!root_cert_file || !root_key_file) {
        fprintf(stderr, "Error opening root certificate or private key file.\n");
        exit(EXIT_FAILURE);
    }

    X509 *root_cert = PEM_read_X509(root_cert_file, NULL, NULL, NULL);
    EVP_PKEY *root_key = PEM_read_PrivateKey(root_key_file, NULL, NULL, NULL);

    fclose(root_cert_file);
    fclose(root_key_file);

    if (!root_cert || !root_key) {
        fprintf(stderr, "Error reading root certificate or private key.\n");
        exit(EXIT_FAILURE);
    }


/*------------------------------------*/


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
    //X509_set_issuer_name(x509, name);

    // Sign the certificate
    if (!X509_set_issuer_name(x509, X509_get_subject_name(root_cert))) {
        fprintf(stderr, "Error setting issuer name.\n");
        exit(EXIT_FAILURE);
    }
    X509_sign(x509, pkey, EVP_sha256());

    // Write private key to disk as .pem file
    FILE * f;
    f = fopen("server_key.pem", "wb");
    PEM_write_PrivateKey(
        f,                  /* write the key to the file we've opened */
        pkey,               /* use key from earlier */
        EVP_des_ede3_cbc(), /* default cipher for encrypting the key on disk */
        NULL,       /* passphrase required for decrypting the key on disk */
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
        const char reply[] = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>Simple Web Page</title></head><body><h1>Hello, World!</h1></body></html>";

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
        int ret  = SSL_accept(ssl);
        if (ret <= 0) {        // Perform SSL handshake
            int i = SSL_get_error(ssl,ret);
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