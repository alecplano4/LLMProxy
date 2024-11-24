//----HEADER---------------------------------------------------------------------------------------
// Date:        November 2024
// Script:      proxy.c
// Usage:       Implementation file for proxy
//*************************************************************************************************
#include "proxy.h"

#include <stdio.h>
#include <stdint.h>
#include <sys/_types/_fd_def.h>
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
#include <openssl/x509v3.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <fcntl.h>
#include <stdio.h>

#include <sys/types.h>
#include <netdb.h>



// ----GLOBAL VARIABLES----------------------------------------------------------------------------
#define MAX_CLIENT_CONNECTIONS 10
#define HOST_NAME_LENGTH 100
#define BUFSIZE 81920

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


// void create_server_certificate(const char *root_cert_file, const char *root_key_file, char* hostname, char* server_cert_file, char* server_key_file) {
    
//     EVP_PKEY *root_key = NULL;
//     X509 *root_cert = NULL;
//     X509_REQ *csr = NULL;
//     X509 *server_cert = NULL;

//     /*---LOAD ROOT CERTIFICATE-----------------------------------------------*/

//     // Load root certificate
//     FILE *fp = fopen(root_cert_file, "r");
//     if (!fp) {
//         perror("Failed to open root certificate");
//         return;
//     }
//     root_cert = PEM_read_X509(fp, NULL, NULL, NULL);
//     fclose(fp);

//     // Load root private key
//     fp = fopen(root_key_file, "r");
//     if (!fp) {
//         perror("Failed to open root private key");
//         return;
//     }
//     root_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
//     fclose(fp);
//     printf("Successfully loaded root certificate\n");

//     /*---GENERATE SERVER CERTIFICATE-----------------------------------------*/
//     /* Certificates are generated using Certificate Signing Requests (CSR). 
//     The steps are as follows:
//     1. Generate new public/private key pair for the server certificate
//     2. Create new CSR using server key
//     3. Sign CSR using root certificate 
//     4. Save */

//     // 1. Generate public/private key pair for server certificate
//     EVP_PKEY* server_key = EVP_PKEY_new();  // data structure for storing private key
//     RSA* rsa = RSA_generate_key(
//         2048,   /* number of bits for the key - 2048 is a sensible value */
//         RSA_F4, /* exponent - RSA_F4 is defined as 0x10001L */
//         NULL,   /* callback - can be NULL if we aren't displaying progress */
//         NULL    /* callback argument - not needed in this case */
//     );
//     if(rsa == NULL) {
//         printf("Failed to generate key for self-signed certificate. Exiting...\n");
//         ERR_get_error();
//         exit(EXIT_FAILURE);
//     }
//     EVP_PKEY_assign_RSA(server_key, rsa);     // Assign key to data structure
//     printf("Successfully generated key for server certificate\n");

//     // 2. Create a new Certificate Signing Request (CSR). Use server's private key
//     //    in creation of CSR and sign using root certificate private key
//     csr = X509_REQ_new();
//     X509_REQ_set_version(csr, 1);  // Version 1
//     X509_REQ_set_pubkey(csr, server_key);

//     // Provide country code ("C"), organization ("O") and common name ("CN")
//     printf("Adding fields to CSR\n");
//     X509_NAME *name = X509_REQ_get_subject_name(csr);
//     X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
//     X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"Example", -1, -1, 0);
//     X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *) hostname, -1, -1, 0);

//     // Add the server's private key to the CSR
//     X509_REQ_sign(csr, root_key, EVP_sha256());

//     // Create the server certificate
//     server_cert = X509_new();
//     X509_set_version(server_cert, 2);  // Version 3
//     ASN1_INTEGER_set(X509_get_serialNumber(server_cert), 1);
//     X509_gmtime_adj(X509_get_notBefore(server_cert), 0);
//     X509_gmtime_adj(X509_get_notAfter(server_cert), 31536000L);  // 1 year validity
//     X509_set_subject_name(server_cert, X509_REQ_get_subject_name(csr));
//     X509_set_issuer_name(server_cert, X509_get_subject_name(root_cert));  // Root is the issuer
//     X509_set_pubkey(server_cert, server_key);


//     // X509_EXTENSION *san_extension  = X509_EXTENSION_new();
//     // if (!X509_EXTENSION_set_object(san_extension, OBJ_nid2obj(NID_subject_alt_name))) {
//     //     fprintf(stderr, "Error setting SAN extension object\n");
//     //     return;
//     // }
//     // // SAN format: "DNS:hostname1,DNS:hostname2,IP:192.168.1.1"
//     // if (!X509_EXTENSION_set_data(san_extension, (unsigned char*)hostname)) {
//     //     fprintf(stderr, "Error setting SAN extension data\n");
//     //     return;
//     // }
//     // if (!X509_add_ext(server_cert, san_extension, -1)) {
//     //     fprintf(stderr, "Error adding SAN extension to server certificate\n");
//     //     return;
//     // }

//     // Sign the server certificate with the root private key
//     X509_sign(server_cert, root_key, EVP_sha256());

//     // Save the server certificate amd private key to a file
//     strcpy(server_cert_file, hostname);
//     strcpy(server_key_file, hostname);
//     strcat(server_cert_file, ".crt");
//     strcat(server_key_file, ".key");
    
//     printf("File name of server certificate: %s\n", server_cert_file);
//     printf("File name of server pirvate key: %s\n", server_key_file);


//     fp = fopen(server_cert_file, "w");
//     PEM_write_X509(fp, server_cert);
//     fclose(fp);

//     fp = fopen(server_key_file, "w");
//     PEM_write_PrivateKey(fp, server_key, NULL, NULL, 0, NULL, NULL);
//     fclose(fp);

//     // Cleanup
//     X509_free(root_cert);
//     EVP_PKEY_free(root_key);
//     EVP_PKEY_free(server_key);
//     X509_REQ_free(csr);
//     X509_free(server_cert);

//     printf("Server certificate and private key generated and signed successfully.\n");
// }

void create_server_certificate(const char* root_cert_file, const char* root_key_file, 
                               char* hostname, char* server_cert_file, char* server_key_file, 
                               const char* serial_number_file) {

    printf("Certificate Commands:\n");
    /*---1. CREATE SERVER SUBJECT -------------------------------------------*/
    // Curl relies on the Common Name (CN) in the subject field for domain validation.
    // Browsers rely on the SAN field for domain validation
    char subject[500];
    snprintf(subject, sizeof(subject), 
             "/C=US/ST=MA/L=Boston/O=Tufts/OU=GSE/CN=%s/emailAddress=it@example.com", 
             hostname);
    // printf("Subject: %s\n", subject);


    /*---2. CREATE PRIVATE KEY ----------------------------------------------*/
    // Create private key for server certificate    
    char cmd_create_private_key[500];
    snprintf(cmd_create_private_key, sizeof(cmd_create_private_key), 
             "openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out certificates/%s_key.pem > /dev/null 2>&1", hostname);
    printf("Private_Key Command: %s\n", cmd_create_private_key);
    system(cmd_create_private_key);
    snprintf(server_key_file, HOST_NAME_LENGTH, "certificates/%s_key.pem", hostname);

    /*---3. CREATE CERTIFICATE SIGNING REQUEST (CSR) ------------------------*/
    // The Certificate Signing Request relies on the OpenSSL configuration file. However, the default config file doesn't
    // include certificate parameters required by browsers, such as the Subject Alternate Name (SAN) (which needs to be
    // determined dynamically based on the requested host name), or the keyUsage field. To incorporate these, a custom openssl 
    // config file is created, which includes the default elements as well as the added elements. The custom config file is 
    // then referenced in the CSR creation command by the -config field.

    // 3.1: Create custom configuration file
    remove("openssl_custom.cnf");                            // Remove custom config file from prior CSR
    system("cp /etc/ssl/openssl.cnf openssl_custom.cnf");    // Copy default config file
    char cmd_create_custom_config_file[400];
    snprintf(cmd_create_custom_config_file, sizeof(cmd_create_custom_config_file), // Add needed fields to custom config file
             "echo \"\n[ v3_req ]\nbasicConstraints = CA:false\nkeyUsage = critical, digitalSignature, keyEncipherment\nextendedKeyUsage = serverAuth\nsubjectAltName = DNS:%s\" >> openssl_custom.cnf", 
             hostname);
    system(cmd_create_custom_config_file);

    // 3.2: Create Certificate Signing Request using custom config file  
    char cmd_create_CSR[500];
    snprintf(cmd_create_CSR, sizeof(cmd_create_CSR), 
             "openssl req -new -key certificates/%s_key.pem -out certificates/%s_csr.pem -subj %s -config openssl_custom.cnf", hostname, hostname, subject);
    printf("Create CSR: %s\n", cmd_create_CSR);
    system(cmd_create_CSR);

    /*---4. SIGN CSR WITH CERTIFICATE AUTHORITY ----------------------------*/
    char command_sign_CSR[500];
    snprintf(command_sign_CSR, sizeof(command_sign_CSR), 
             "openssl x509 -req -days 365 -in certificates/%s_csr.pem -CA %s -CAkey %s -CAcreateserial -out certificates/%s_cert.pem -extfile openssl_custom.cnf -extensions v3_req", 
             hostname, root_cert_file, root_key_file, hostname);
    printf("CA Sign CSR Command: %s\n", command_sign_CSR);
    system(command_sign_CSR);
    snprintf(server_cert_file, HOST_NAME_LENGTH, "certificates/%s_cert.pem", hostname);


    /*---PRIOR APPROACH------------------------------------------------------*/
    
    // EVP_PKEY *root_key = NULL;
    // X509 *root_cert = NULL;
    // X509_REQ *csr = NULL;
    // X509 *server_cert = NULL;

    // /*---LOAD ROOT CERTIFICATE-----------------------------------------------*/

    // // Load root certificate
    // FILE *fp = fopen(root_cert_file, "r");
    // if (!fp) {
    //     perror("Failed to open root certificate");
    //     return;
    // }
    // root_cert = PEM_read_X509(fp, NULL, NULL, NULL);
    // fclose(fp);

    // // Load root private key
    // fp = fopen(root_key_file, "r");
    // if (!fp) {
    //     perror("Failed to open root private key");
    //     return;
    // }
    // root_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    // fclose(fp);
    // printf("Successfully loaded root certificate\n");

    // /*---GENERATE SERVER CERTIFICATE-----------------------------------------*/
    // /* Certificates are generated using Certificate Signing Requests (CSR). 
    // The steps are as follows:
    // 1. Generate new public/private key pair for the server certificate
    // 2. Create new CSR using server key
    // 3. Sign CSR using root certificate 
    // 4. Save */

    // // 1. Generate public/private key pair for server certificate
    // EVP_PKEY* server_key = EVP_PKEY_new();  // data structure for storing private key
    // RSA* rsa = RSA_generate_key(
    //     2048,   /* number of bits for the key - 2048 is a sensible value */
    //     RSA_F4, /* exponent - RSA_F4 is defined as 0x10001L */
    //     NULL,   /* callback - can be NULL if we aren't displaying progress */
    //     NULL    /* callback argument - not needed in this case */
    // );
    // if(rsa == NULL) {
    //     printf("Failed to generate key for self-signed certificate. Exiting...\n");
    //     ERR_get_error();
    //     exit(EXIT_FAILURE);
    // }
    // EVP_PKEY_assign_RSA(server_key, rsa);     // Assign key to data structure
    // printf("Successfully generated key for server certificate\n");

    // // 2. Create a new Certificate Signing Request (CSR). Use server's private key
    // //    in creation of CSR and sign using root certificate private key
    // csr = X509_REQ_new();
    // X509_REQ_set_version(csr, 1);  // Version 1
    // X509_REQ_set_pubkey(csr, server_key);

    // // Provide country code ("C"), organization ("O") and common name ("CN")
    // printf("Adding fields to CSR\n");
    // X509_NAME *name = X509_REQ_get_subject_name(csr);
    // X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
    // X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"Example", -1, -1, 0);
    // X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *) hostname, -1, -1, 0);

    // // Add the server's private key to the CSR
    // X509_REQ_sign(csr, root_key, EVP_sha256());

    // // Create the server certificate. Important - serial number
    // // needs to be unique for each certificate. Store in local file and 
    // // incrmement for each certificate
    // printf("Creating server certificate\n");
    // server_cert = X509_new();
    // int serial_number = read_increment_save_serial_number(serial_number_file);
    // X509_set_version(server_cert, 2);  // Version 3
    // ASN1_INTEGER_set(X509_get_serialNumber(server_cert), serial_number);
    // X509_gmtime_adj(X509_get_notBefore(server_cert), 0);
    // X509_gmtime_adj(X509_get_notAfter(server_cert), 31536000L);  // 1 year validity
    // X509_set_subject_name(server_cert, X509_REQ_get_subject_name(csr));
    // X509_set_issuer_name(server_cert, X509_get_subject_name(root_cert));  // Root is the issuer
    // X509_set_pubkey(server_cert, server_key);

    // // Add Subject Alternative Name (SAN)
    // printf("Adding SAN field\n");
    // X509_EXTENSION *ext;
    // char san_buffer[256];
    // snprintf(san_buffer, sizeof(san_buffer), "DNS:%s", hostname);
    // ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san_buffer);
    // if (!ext) {
    //     fprintf(stderr, "Failed to create SAN extension\n");
    //     exit(EXIT_FAILURE);
    // }
    // X509_add_ext(server_cert, ext, -1);
    // X509_EXTENSION_free(ext);

    // // Add keyUsage extension (critical)
    // printf("Adding keyUsage extension\n");
    // ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, "critical,digitalSignature,keyEncipherment");
    // if (!ext) {
    //     fprintf(stderr, "Failed to create keyUsage extension\n");
    //     exit(EXIT_FAILURE);
    // }
    // X509_add_ext(server_cert, ext, -1);
    // X509_EXTENSION_free(ext);

    // // Add extendedKeyUsage extension
    // printf("Adding extendedkeyUsage extension\n");
    // ext = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "serverAuth");
    // if (!ext) {
    //     fprintf(stderr, "Failed to create extendedKeyUsage extension\n");
    //     exit(EXIT_FAILURE);
    // }
    // X509_add_ext(server_cert, ext, -1);
    // X509_EXTENSION_free(ext);

    // // SAN (Subject Alternative Name) field needed by browser
    // // X509_EXTENSION *san_extension  = X509_EXTENSION_new();
    // // if (!X509_EXTENSION_set_object(san_extension, OBJ_nid2obj(NID_subject_alt_name))) {
    // //     fprintf(stderr, "Error setting SAN extension object\n");
    // //     return;
    // // }
    // // // SAN format: "DNS:hostname1,DNS:hostname2,IP:192.168.1.1"
    // // if (!X509_EXTENSION_set_data(san_extension, (unsigned char*)hostname)) {
    // //     fprintf(stderr, "Error setting SAN extension data\n");
    // //     return;
    // // }
    // // if (!X509_add_ext(server_cert, san_extension, -1)) {
    // //     fprintf(stderr, "Error adding SAN extension to server certificate\n");
    // //     return;
    // // }

    // // Sign the server certificate with the root private key
    // X509_sign(server_cert, root_key, EVP_sha256());

    // // Save the server certificate amd private key to a file
    // strcpy(server_cert_file, hostname);
    // strcpy(server_key_file, hostname);
    // strcat(server_cert_file, ".crt");
    // strcat(server_key_file, ".key");
    
    // printf("File name of server certificate: %s\n", server_cert_file);
    // printf("File name of server pirvate key: %s\n", server_key_file);


    // fp = fopen(server_cert_file, "w");
    // PEM_write_X509(fp, server_cert);
    // fclose(fp);

    // fp = fopen(server_key_file, "w");
    // PEM_write_PrivateKey(fp, server_key, NULL, NULL, 0, NULL, NULL);
    // fclose(fp);

    // // Cleanup
    // X509_free(root_cert);
    // EVP_PKEY_free(root_key);
    // EVP_PKEY_free(server_key);
    // X509_REQ_free(csr);
    // X509_free(server_cert);

    // printf("Server certificate and private key generated and signed successfully.\n");
}

int read_increment_save_serial_number(const char *file_path) {
    FILE *file;
    int serial_number = 0;

    // Open the file for reading
    file = fopen(file_path, "r");
    if (!file) {
        perror("Failed to open file for reading");
        // If the file doesn't exist, assume starting at 1
        serial_number = 1;
    } else {
        // Read the serial number from the file
        if (fscanf(file, "%d", &serial_number) != 1) {
            perror("Failed to read serial number");
            serial_number = 1;  // Default value
        }
        fclose(file);
    }

    // Increment the serial number
    serial_number++;

    // Open the file for writing
    file = fopen(file_path, "w");
    if (!file) {
        perror("Failed to open file for writing");
        exit(EXIT_FAILURE);
    }

    // Write the updated serial number to the file
    fprintf(file, "%d\n", serial_number);
    fclose(file);

    printf("Updated serial number: %ld\n", serial_number);
    return serial_number;
}


void initialize_proxy_test(int listening_port) {

    const char *root_cert_file = "ca.crt";
    const char *root_key_file = "ca.key";
    const char *serial_number_file = "serial_number.txt";


    char server_cert_file[HOST_NAME_LENGTH] = {0};
    char server_key_file[HOST_NAME_LENGTH] = {0};

    
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

            // Create server certificate and save to disk
            create_server_certificate(root_cert_file, root_key_file, hostname, server_cert_file, server_key_file, serial_number_file);
            printf("\n--------------------\nCERTIFICATE CREATED\n--------------------\n\n");

            // Prepare SSL Context object
            ctx = create_context();                                    // Get SSL Context to store TLS configuration parameters
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




proxy_t* initialize_proxy(int listening_port) {
    proxy_t* new_proxy = malloc(sizeof(proxy_t));

    //new_proxy->client_read = true;
    new_proxy->listening_fd = create_socket(listening_port, &(new_proxy->proxy_addr));
    new_proxy->head = NULL;
    new_proxy->num_cs = 0;

    return new_proxy;
}


void run_proxy(int listening_port, bool tunnel_mode) {

    const char *root_cert_file = "ca.crt";
    const char *root_key_file = "ca.key";
    const char *serial_number_file = "serial_number.txt";


    proxy_t* p = initialize_proxy(listening_port);
    printf("DEBUG: Created Proxy object\n");

    fd_set read_fds;
    FD_ZERO(&read_fds);

    // struct timeval timeout;
    // timeout.tv_sec = 1;  // Seconds
    // timeout.tv_usec = 0; // Microseconds (500ms)

    while(1) {

        //TODO: create a set_fds function that loops through linked list and adds fds to sets
        //printf("NEW Select call");
        /* Always want to be listening for new connection*/
        FD_ZERO(&read_fds);
        proxy_create_fds(p, &read_fds);
        FD_SET(p->listening_fd, &read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        //usleep(100000);
        print_cs(p);


        int select_ret = select(FD_SETSIZE, &read_fds, NULL, NULL, NULL);

        /* error with select */
        if (select_ret == -1) {
            printf("ERROR: select with errno: %d\n", errno);
            exit(EXIT_FAILURE);
        }
        /* No data available on any file descriptors */
        else if (select_ret == 0) {
            printf("DEBUG: No data available due to timeout\n");
        }
        /* socket file descriptors ready for reading */
        else {
            /* Current implementation does not work concurently 
                it runs all instructions for a server at once*/
            if(FD_ISSET(STDIN_FILENO, &read_fds)){
                char buffer[1024];
                int bytes_read;

                // Read input from stdin
                bytes_read = read(STDIN_FILENO, buffer, sizeof(buffer) - 1);
                printf("%.*s\n", bytes_read, buffer);
                if(strncmp(buffer,"ls\n",3) == 0){
                    printf("here\n");
                    print_cs(p);
                }

            }
            if (FD_ISSET(p->listening_fd, &read_fds)) {
                if(tunnel_mode){
                    client_server_t* cs = malloc(sizeof(client_server_t));
                    cs->client_read = true;
                    cs->invalid = false;
                    /* Potential client local variables */
                    
                    cs->client_addr_len = sizeof(cs->client_addr);



                    cs->client_fd = accept(p->listening_fd,
                                        (struct sockaddr*)&(cs->client_addr),
                                        &(cs->client_addr_len));
                    uint8_t buf[10000];
                    int bytes_read = read(cs->client_fd, buf, 10000);
                    uint8_t header_copy_for_server[10000];
                    memcpy(header_copy_for_server, buf, bytes_read);

                    printf("parsing the header:\n");
                    cs->h = proxy_parse_header((char*)buf);

                    print_header_elems(cs->h);


                    printf("Connecting to server\n\n");
                    cs->server_fd = proxy_connect_server(cs->h);
                    printf("HEADER COPY FOR SERVER %d :\n%s---",bytes_read, header_copy_for_server);
                    int l = write(cs->server_fd, header_copy_for_server, bytes_read);

                    cs->data = malloc(bytes_read);
                    memcpy(cs->data, header_copy_for_server, bytes_read);
                    cs->data_len = bytes_read;
                    cs->client_read = false;

                    proxy_add_cs(p, cs);

                    // bzero(buf, 10000);
                    // int b = read(cs->server_fd, buf, 10000);
                    // printf("recieved messgae from server len = %d:\n", b);
                    // printf("%s\n", buf);
                    
                    // int c = read(server_fd, buf+b, 10000-b);
                    // printf("recieved messgae from server len = %d:\n", b);
                    // printf("%s\n", buf);


                    // char* server_resp_buf;
                    // int server_resp_buf_size;
                    // char* server_header;
                    // int server_header_size;
                    // proxy_read_server(NULL, server_fd,
                    //               &server_resp_buf, &server_resp_buf_size,
                    //               &server_header, &server_header_size, true);
                    // proxy_read_server(server_fd, &server_resp_buf, &server_resp_buf_size, &server_header, &server_header_size);
                    // printf("\nSERVER RESPONSE BUF \n%s", server_resp_buf);
                    // write(cs->client_fd, server_resp_buf, server_resp_buf_size);
                    // printf("relaying data back to client\n");
                    //write(cs->client_fd, buf, b);
                    

                }else{
                    printf("New Connection Inbound\n");
                    client_server_t* cs = malloc(sizeof(client_server_t));
                    cs->client_read = true;
                    cs->invalid = false;
                    cs->bytes_read = 0;
                    /* Potential client local variables */
                    
                    cs->client_addr_len = sizeof(cs->client_addr);

                    // struct sockaddr_in client_addr;
                    // unsigned int len = sizeof(client_addr);
                    // SSL *ssl;

                    char server_cert_file[HOST_NAME_LENGTH] = {0};
                    char server_key_file[HOST_NAME_LENGTH] = {0};
                    

                    cs->client_fd = accept(p->listening_fd, (struct sockaddr*)&(cs->client_addr), &(cs->client_addr_len));
                    if (cs->client_fd < 0) {
                        perror("Unable to accept");
                        exit(EXIT_FAILURE);
                    }
                    printf("Client TCP handshake successful\n");
                    // Receive client data
                    char request[BUFSIZE];
                    char hostname[100];
                    int bytes_received = recv(cs->client_fd, request, sizeof(request)-1, 0);
                    printf("Bytes received: %d\n", bytes_received);
                    printf("Message: %s\n", request);
                    extract_hostname(request, hostname);
                    printf("Hostname: %s\n", hostname);

                    // Client expects "Connection Established" response to CONNECT request.
                    // Must be sent for client to initiate SSL handshake
                    if (strstr(request, "CONNECT") == request) {
                        // Respond with "HTTP/1.1 200 Connection Established"
                        const char *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
                        send(cs->client_fd, response, strlen(response), 0);
                        printf("Sent response to client:\n%s\n", response);

                        // Create server certificate and save to disk
                        create_server_certificate(root_cert_file, root_key_file, hostname, server_cert_file, server_key_file, serial_number_file);
                        printf("\n--------------------\nCERTIFICATE CREATED\n--------------------\n\n");

                        // Prepare SSL Context object
                        cs->client_ctx = create_context();                                    // Get SSL Context to store TLS configuration parameters
                        printf("Context created\n");
                        configure_context(cs->client_ctx, server_cert_file, server_key_file); // Load certificate and private key into context
                        printf("Certificate loaded into context\n");

                        // Set client connection to SSL (perform SSL handshake)
                        cs->client_ssl = SSL_new(cs->client_ctx);      // Create SSL object
                        SSL_set_fd(cs->client_ssl, cs->client_fd);    // Link SSL object to accepted TCP socket
                        printf("SSL object created and linked to TCP socket\n");

                        if (SSL_accept(cs->client_ssl) <= 0) {        // Perform SSL handshake
                            printf("Unsuccessful client SSL handshake\n");
                            ERR_print_errors_fp(stderr);
                        } else {
                            printf("SSL handshake completed.\n");
                        }
                        /* DONE WITH SSL CONNECTION */
                        /* AT THIS POINT WE WANT TO GET INTO THE PARALLEL FACILOTATION */
                        /* RECIEVE NEXT MESSAGE */
                        bytes_received = SSL_read(cs->client_ssl, request, sizeof(request) - 1);
                        if (bytes_received > 0) {
                            request[bytes_received] = '\0'; // Null-terminate the received message
                            printf("Received message from client:\n %s\n\n", request);
                        } else {
                            printf("SSL_read failed");
                            exit(EXIT_FAILURE);
                        }

                        char request_copy[10000];
                        memcpy(request_copy, request, bytes_received);
                        header_elems* header = proxy_parse_header(request_copy);
                        print_header_elems(header);
                        printf("---------------\n");
                       


                        /* receive a message from the client*/
                        printf("FORWARDING MESSAGE TO SERVER: %s", request);
                        cs->server_ctx = SSL_CTX_new(TLS_client_method());
                        cs->server_fd = open_connection(hostname, 443);
                        if (cs->server_fd < 0) {
                            fprintf(stderr, "Unable to connect to server\n");
                            exit(EXIT_FAILURE);
                        }
                        cs->server_ssl = create_ssl_connection(cs->server_ctx, cs->server_fd);

                        if (SSL_write(cs->server_ssl, request, bytes_received) <= 0) {
                            printf("ERROR with ssl_write\n");
                            exit(EXIT_FAILURE);
                        }

                        char* server_data;
                        int server_data_size;
                        char* server_header;
                        int server_header_size;
                        // proxy_read_server(ssl_server, 0, &server_data, 
                        //                 &server_data_size, &server_header, 
                        //                 &server_header_size, false);

                        // printf("SERVER HEADER:\n");
                        // printf("%.*s", server_header_size, server_header);

                        int bytes;
                        char server_response[50000] = {0};
                        bytes = SSL_read(cs->server_ssl, server_response, sizeof(server_response) - 1);
                        printf("HEADER\n%s\n", server_response);


                        char server_response_copy[50000] = {0};
                        memcpy(server_response_copy, server_response, bytes);

                        header_elems* h = proxy_parse_header(server_response_copy);
                        print_header_elems(h);

                        cs->data_len = atoi(h->data_len);
                        cs->bytes_read+=bytes;

                        int header_size = strstr(server_response, "\r\n\r\n") - server_response + 4;
                        printf("HEADER SIZE = %d\n", header_size);
                        cs->data_len += header_size;


                        if (SSL_write(cs->client_ssl, server_response, bytes) <= 0) {
                            printf("ERROR with ssl_write\n");
                            exit(EXIT_FAILURE);
                        }

                        // bytes = SSL_read(cs->server_ssl, server_response, sizeof(server_response) - 1);
                        // printf("RESPONSE\n%s\n", server_response);
                        // if (SSL_write(cs->client_ssl, server_response, bytes) <= 0) {
                        //     printf("ERROR with ssl_write\n");
                        //     exit(EXIT_FAILURE);
                        // }
                        // printf("RESPONSE\n%s\n", server_response);




                        // Close SSL connection and free data structure
                        // SSL_shutdown(cs->server_ssl);
                        // SSL_free(cs->server_ssl);
                        // SSL_shutdown(cs->client_ssl);
                        // SSL_free(cs->client_ssl);


                        cs->client_read = false;
                        proxy_add_cs(p, cs);
                    } else {
                        fprintf(stderr, "Invalid request: Not a CONNECT request\n");
                    }
                }

                

            }
            //for all fds in the list add call relay
            client_server_t* cs = p->head;
            for(int i = 0; i<p->num_cs; i++){
                if(cs->client_read){
                    if(tunnel_mode){
                        if(FD_ISSET(cs->client_fd, &read_fds)){
                            printf("Client is ready to read\n");
                            char buf[1000] = {0};
                            int br = read(cs->client_fd, buf, 1000);
                            //printf("Read %d bytes from server:\n%s\n", br, buf);
                            if(br == 0){
                                printf("Clinet Closed Connection");
                                cs->invalid = true;
                            }
                            cs->client_read = false;
                        }
                    }else{
                        printf("READING FROM CLIENT");
                        int bytes;
                        char server_response[BUFSIZE] = {0};
                        bytes = SSL_read(cs->client_ssl, server_response, BUFSIZE);
                        //printf("RESPONSE\n%s\n", server_response);
                        if(bytes == 0){
                            printf("Clinet Closed Connection");
                            cs->invalid = true;
                        }
                        else if (SSL_write(cs->server_ssl, server_response, bytes) <= 0) {
                            printf("ERROR with ssl_write\n");
                            exit(EXIT_FAILURE);
                        }

                        cs->client_read = false;

                    }

                }else{
                    if(tunnel_mode){
                        if(FD_ISSET(cs->server_fd, &read_fds)){
                            printf("SERVER is ready to read\n");
                            char buf[1000] = {0};
                            int br = read(cs->server_fd, buf, 1000);
                            printf("Read %d bytes from server:\n%s\n", br, buf);
                            write(cs->client_fd, buf, br);
                            cs->client_read = true;
                        }   
                    }else{
                        if(FD_ISSET(cs->server_fd, &read_fds)){
                            printf("SERVER is ready to read\n");
                            char buf[BUFSIZE] = {0};
                            int br = SSL_read(cs->server_ssl, buf, BUFSIZE);
                            if(br == 0){
                                printf("Clinet Closed Connection");
                                cs->invalid = true;
                            }
                            else if (SSL_write(cs->client_ssl, buf, br) <= 0) {
                                printf("ERROR with ssl_write\n");
                                exit(EXIT_FAILURE);
                            }
                            cs->bytes_read+=br;

                            if(cs->bytes_read < cs->data_len){
                                cs->client_read = false; 
                            }else{
                                cs->client_read = true;
                            }
                            printf("Read %d bytes from server for %d out of %d:(client read = %d)\n", br, cs->bytes_read, cs->data_len, cs->client_read);

                        }   
                    }
                                        
                }
                cs = cs->next;
            
            }
        }
    }
    proxy_clean(p);
}

header_elems* proxy_parse_header(char* header)
{
    printf("PARSING HEADER\n");
    header_elems* h = (header_elems*)calloc(1,sizeof(header_elems));

    char* nl_delim = "\n";
    char* cr_delim = "\r";
    char* space_delim = " ";
    char* col_delim = ":";
    
    char* last;
    char* line = strtok_r(header, nl_delim, &last);
    printf("%s", line);
    while(strcmp(line, "\r") != 0){
        //printf("%s\n", line);
        char* inner_last;
        char* command = strtok_r(line, space_delim, &inner_last);
        //printf("%s\n", command);

        if(strcmp(command, "GET") == 0 || strcmp(command, "HEAD") == 0) {
            h->url = strtok_r(NULL, space_delim, &inner_last);
            char* http_v = strtok_r(NULL, cr_delim,&inner_last);
            //printf("HTTP_v = %s\n", http_v);

        }else if(strcmp(command, "Host:") == 0) {
            //printf("\n\nLINE: %s\n\n", command+6);
            h->host = strtok_r(NULL, cr_delim, &inner_last);
            if(strstr(h->host, ":") == NULL){
                h->port = "443";
            }else{
                char* host_port_delim = (strstr(h->host, ":"));
                *host_port_delim = '\0';
                h->port = host_port_delim+1;
                
            }
            //printf("HOST = %s\n", h->host);
            //printf("host len = %d\n",strlen(h->host));
            //printf("PORT = %s\n", h->port);

        }else if(strcmp(command, "Content-Length:") == 0 || 
                strcmp(command, "content-length:") == 0) {
            char* len = strtok_r(NULL, cr_delim, &inner_last);
            h->data_len = len;

        }else if(strcmp(command, "Cache-Control:") == 0) {
            char* eq = "=";
            strtok_r(NULL, eq, &inner_last);
            //Cache-Control: max-age=N
            char* max_age = strtok(NULL, cr_delim);
            h->max_age = max_age;

        }
        line = strtok_r(NULL, "\n", &last);
    }

    return h;
}

int proxy_connect_server(header_elems* header)
{
    int s_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s_fd == -1) {
        printf("ERROR: creating socket with erro: %d\n", errno);
        exit(EXIT_FAILURE);
    }

    struct addrinfo hints;
    struct addrinfo *result, *curr;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;



    int s = getaddrinfo(header->host, header->port, &hints, &result);
    if (s != 0) {
        printf("ERROR: getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }



    for (curr = result; curr != NULL; curr = curr->ai_next) {
        if (connect(s_fd, curr->ai_addr, curr->ai_addrlen) != -1)
            break;

    }

    freeaddrinfo(result);
    return s_fd;
}

void proxy_clean(proxy_t* p){
    close(p->listening_fd);
    client_server_t* cs = p->head;
    while(cs != NULL){
        client_server_t* next = cs->next;

        free(cs);
        cs = next;
    }
}


void proxy_read_server(int fd, char** buf, int* size, char** h_buf, int* h_size)
{
    /* read in first set of data */
    int buf_multiplier = 1;
    char* header_buf = malloc(BUFSIZE*buf_multiplier + 1);
    int bytes_read = read(fd, header_buf, BUFSIZE);
    printf("bytes read = %d into buffer %p\n", bytes_read, header_buf);
    //header_buf[bytes_read] = '\0';
    // char* eoh = NULL;
    // printf("%.*s\n",bytes_read,header_buf);
    // while((eoh = strstr(header_buf, "\r\n\r\n")) == NULL) {
    // printf("%.*s\n",bytes_read,header_buf);

    //     buf_multiplier++;

    //     header_buf = realloc(header_buf, BUFSIZE*buf_multiplier + 1);

    //     int more_bytes = read(fd, header_buf + bytes_read, BUFSIZE);
    //     if(more_bytes == 0){
    //         printf("read n");
    //         break;
    //     }

    //     bytes_read+=more_bytes;
    //     printf("%d\n",bytes_read);
    //     header_buf[bytes_read] = '\0';

    // }
    printf("here");

    // int header_size = (int)(eoh - header_buf)+4;


    *h_size = bytes_read;//header_size;
    // printf("sadf");
    *h_buf = header_buf;

    // char* header_copy = malloc(header_size + 1);
    // memcpy(header_copy, header_buf, header_size);
    // header_copy[header_size] = '\0';
    // printf("\n\n\n\nHeader COPY from server: %s\n", header_copy);

    // /* parse header to get data length*/
    // header_elems* h = proxy_parse_header(header_copy);
    // print_header_elems(h);
    // int data_size = atoi(h->data_len); //get data size from parsed header
    // free(h);
    // free(header_copy);
    // int data_read = bytes_read - header_size;
    // char* data_buf = malloc(data_size);

    // memcpy(data_buf, eoh+4, data_read);
    // int num_bytes_read = data_read;
    // num_bytes_read += read(fd, data_buf + num_bytes_read, data_size-num_bytes_read);
    // printf("SERVER DATA (data size: %d): %.*s",num_bytes_read,num_bytes_read,data_buf);
    // while (num_bytes_read != data_size) {
    //     num_bytes_read += read(fd, data_buf + num_bytes_read, data_size-num_bytes_read);
    //     printf("SERVER DATA: %.*s",num_bytes_read,data_buf);

    // }
    // printf("hereasdf\n");
    // *buf = data_buf;
    // *size = num_bytes_read;

}



SSL *create_ssl_connection(SSL_CTX *ctx, int sockfd) {
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        printf("FAILEING\n");
        ERR_print_errors_fp(stderr);
        abort();
    }
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) <= 0) {
        printf("FAILEING2\n");

        ERR_print_errors_fp(stderr);
        abort();
    }
    return ssl;
}

int open_connection(const char *hostname, int port) {
    struct hostent *host;
    struct sockaddr_in addr;
    int sockfd;

    host = gethostbyname(hostname);
    if (!host) {
        fprintf(stderr, "Could not resolve hostname\n");
        return -1;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Unable to create socket");
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr.s_addr, host->h_addr, host->h_length);

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Unable to connect");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

void print_header_elems(header_elems* h)
{
    printf("Printing header:\n");
    printf("URL: %s\n", h->url);
    printf("Host: %s\n", h->host);
    printf("Port: %s\n", h->port);
    printf("Max Age: %s\n", h->max_age);
    printf("Data Len: %s\n", h->data_len);

}

void proxy_add_cs(proxy_t* p, client_server_t* cs)
{
    client_server_t* next = p->head;
    p->head = cs;
    cs->next = next;
    p->num_cs++;
}

void proxy_create_fds(proxy_t* p, fd_set *read_fds)
{
    client_server_t* cs = p->head;
    for(int i = 0; i<p->num_cs; i++){
        client_server_t* next = cs->next;
        if(cs->invalid){
            proxy_remove_cs(p,cs);
        }
        else if(cs->client_read){
            //printf("adding cleint fd\n");
            FD_SET(cs->client_fd, read_fds);
        }else{
            //printf("adding server fd\n");

            FD_SET(cs->server_fd, read_fds);
        }
        cs = next;
    }
}


void proxy_remove_cs(proxy_t* p, client_server_t* cs)
{
    if(p->num_cs == 1){
        if(cs == p->head){
            p->head = cs->next;
            SSL_shutdown(cs->server_ssl);
            SSL_free(cs->server_ssl);
            SSL_shutdown(cs->client_ssl);
            SSL_free(cs->client_ssl);
            free(cs->h);
            free(cs->data);
            free(cs);
            p->num_cs--;
            return;
        }
    }else{
        if(cs == p->head){
            p->head = cs->next;
            SSL_shutdown(cs->server_ssl);
            SSL_free(cs->server_ssl);
            SSL_shutdown(cs->client_ssl);
            SSL_free(cs->client_ssl);
            free(cs->h);
            free(cs->data);
            free(cs);
            p->num_cs--;
            return;
        }


        client_server_t* prev = p->head;
        client_server_t* cur = p->head->next;
        while(cur!=NULL){
            if(cur == cs){
                prev->next = cur->next;
                SSL_shutdown(cs->server_ssl);
                SSL_free(cs->server_ssl);
                SSL_shutdown(cs->client_ssl);
                SSL_free(cs->client_ssl);
                free(cur->h);
                free(cur->data);
                free(cur);
                p->num_cs--;
                return;
            }
            cur = cur->next;
            prev = prev->next;
        }
    }

}

void print_cs(proxy_t* p){
    client_server_t* cs = p->head;
    client_server_t* next = cs;
    while(next != NULL) {
        printf("%d:%d -> ", next->client_fd, next->server_fd);
        next = next->next;
    }
    printf("(null)\n");
}