//----HEADER---------------------------------------------------------------------------------------
// Date:        November 2024
// Script:      proxy.c
// Usage:       Implementation file for proxy
//*************************************************************************************************
#include "proxy.h"

#include <stdio.h>
#include <stdint.h>
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

#include <sys/types.h>
#include <netdb.h>



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
    X509_REQ_sign(csr, root_key, EVP_sha256());

    // Create the server certificate
    server_cert = X509_new();
    X509_set_version(server_cert, 2);  // Version 3
    ASN1_INTEGER_set(X509_get_serialNumber(server_cert), 1);
    X509_gmtime_adj(X509_get_notBefore(server_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(server_cert), 31536000L);  // 1 year validity
    X509_set_subject_name(server_cert, X509_REQ_get_subject_name(csr));
    X509_set_issuer_name(server_cert, X509_get_subject_name(root_cert));  // Root is the issuer
    X509_set_pubkey(server_cert, server_key);


    X509_EXTENSION *san_extension  = X509_EXTENSION_new();
    if (!X509_EXTENSION_set_object(san_extension, OBJ_nid2obj(NID_subject_alt_name))) {
        fprintf(stderr, "Error setting SAN extension object\n");
        return;
    }
    // // SAN format: "DNS:hostname1,DNS:hostname2,IP:192.168.1.1"
    // if (!X509_EXTENSION_set_data(san_extension, (unsigned char*)hostname)) {
    //     fprintf(stderr, "Error setting SAN extension data\n");
    //     return;
    // }
    if (!X509_add_ext(server_cert, san_extension, -1)) {
        fprintf(stderr, "Error adding SAN extension to server certificate\n");
        return;
    }

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




proxy_t* intialize_proxy(int listening_port) {
    proxy_t* new_proxy = malloc(sizeof(proxy_t));

    //new_proxy->client_read = true;
    new_proxy->listening_fd = create_socket(listening_port, &(new_proxy->proxy_addr));
    new_proxy->head = NULL;

    return new_proxy;
}


void run_proxy(int listening_port, bool tunnel_mode) {
    
    proxy_t* p = intialize_proxy(listening_port);
    printf("DEBUG: Created Proxy object\n");

    fd_set read_fds; 
    FD_ZERO(&read_fds);

    while(1) {
        /* Potential client local variables */
        struct sockaddr_in client_addr;
        unsigned int sockaddr_len = sizeof(client_addr);

        //TODO: create a set_fds function that loops through linked list and adds fds to sets

        /* Always want to be listening for new connection*/
        FD_SET(p->listening_fd, &read_fds);

        int select_ret = select(FD_SETSIZE, &read_fds, NULL, NULL, NULL);

        /* error with select */
        if (select_ret == -1) {
            printf("ERROR: select with errno: %d\n", errno);
            exit(EXIT_FAILURE);
        }
        /* No data available on any file descriptors */
        else if (select_ret == 0) {
            #ifdef ALEC_DEBUG
            printf("DEBUG: No data available due to timeout\n");
            #endif
        }
        /* socket file descriptors ready for reading */
        else {
            /* Current implementation does not work concurently 
                it runs all instructions for a server at once*/
            if (FD_ISSET(p->listening_fd, &read_fds)) {
                int client_fd = accept(p->listening_fd,
                                       (struct sockaddr*)&(client_addr),
                                       &sockaddr_len);
                uint8_t buf[10000];
                int bytes_read = read(client_fd, buf, 10000);
                uint8_t header_copy_for_server[10000];
                memcpy(header_copy_for_server, buf, bytes_read);
                printf("Header Recieved from client:\n");
                printf("%s\n\n", header_copy_for_server);

                printf("parsing the header:\n");
                header_elems* h = proxy_parse_header((char*)buf);

                printf("HOST = %s\n\n\n",h->host);


                printf("Connecting to server\n\n");
                int server_fd = proxy_connect_server(h);
                int l = write(server_fd, header_copy_for_server, bytes_read);

                bzero(buf, 10000);
                int b = read(server_fd, buf, 10000);
                printf("recieved messgae from server len = %d:\n", b);
                printf("%s\n", buf);
                
                // int c = read(server_fd, buf+b, 10000-b);
                // printf("recieved messgae from server len = %d:\n", b);
                // printf("%s\n", buf);


                char* server_resp_buf;
                int server_resp_buf_size;
                char* server_header;
                int server_header_size;
                // proxy_read_server(server_fd,
                //               &server_resp_buf, &server_resp_buf_size,
                //               &server_header, &server_header_size);
                //write(client_fd, server_resp_buf, server_resp_buf_size);
                printf("relaying data back to client\n");
                write(client_fd, buf, b);


            }else{
                //for all fds in the list add call relay
            }
        }
    }
    proxy_clean(p);
}


header_elems* proxy_parse_header(char* header)
{
    header_elems* h = (header_elems*)calloc(1,sizeof(header_elems));

    char* nl_delim = "\n";
    char* cr_delim = "\r";
    char* space_delim = " ";
    char* col_delim = ":";

    h->max_age = NULL;

    char* command = strtok(header, space_delim);

    /* while there are commands */
    while(command != NULL){
        if(strcmp(command, "GET") == 0 || strcmp(command, "HEAD") == 0) {
            h->url = strtok(NULL, space_delim);
            printf("URL = %s\n", h->url);
            char* http_v = strtok(NULL, cr_delim);
            printf("HTTP_v = %s\n", http_v);

        }else if(strcmp(command, "\nHost") == 0) {

            h->host = strtok(NULL, cr_delim);
            h->host++;
            if(strstr(h->host, ":") == NULL){
                h->port = "80";
            }else{
                char* host_port_delim = (strstr(h->host, ":"));
                *host_port_delim = '\0';
                h->port = host_port_delim+1;
            }
            printf("HOST = %s\n", h->host);
            printf("PORT = %s\n", h->port);
        }else if(strcmp(command, "\nAccept") == 0) {
            char* a = strtok(NULL, cr_delim);

        }else if(strcmp(command, "\nProxy-Connection") == 0) {
            char* keep_alive = strtok(NULL, cr_delim);
            printf("BREKIGN while\n");
            break;
        }else if(strcmp(command, "\nContent-Length") == 0) {
            char* len = strtok(NULL, cr_delim);
            len++;
            h->data_len = len;

        }else if(strcmp(command, "\nCache-Control") == 0) {
            strtok(NULL, "=");
            //Cache-Control: max-age=N
            char* max_age = strtok(NULL, cr_delim);
            h->max_age = max_age;

        }else{
            strtok(NULL, cr_delim);
        }

        /* get the next command */
        command = strtok(NULL, col_delim);

    }
    printf("RETURNING\n");

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
    header_buf[bytes_read] = '\0';

    char* eoh = NULL;
    printf("HERE1");

    while((eoh = strstr(header_buf, "\r\n\r\n")) == NULL) {
        buf_multiplier++;
        header_buf = realloc(header_buf, BUFSIZE*buf_multiplier + 1);
        int more_bytes = read(fd, header_buf + bytes_read, BUFSIZE);

        bytes_read+=more_bytes;
        header_buf[bytes_read] = '\0';
    }

    int header_size = (int)(eoh - header_buf)+4;
    printf("HERE2");


    *h_size = header_size;
    *h_buf = header_buf;

    char* header_copy = malloc(header_size + 1);
    memcpy(header_copy, header_buf, header_size);
    header_copy[header_size] = '\0';
    //printf("Header COPY from server: %s\n", header_copy);

    /* parse header to get data length*/
    header_elems* h = proxy_parse_header(header_copy);
    int data_size = atoi(h->data_len); //get data size from parsed header
    free(h);
    free(header_copy);
    int data_read = bytes_read - header_size;
    char* data_buf = malloc(data_size);

    memcpy(data_buf, eoh+4, data_read);
    int num_bytes_read = data_read;
    num_bytes_read += read(fd, data_buf + num_bytes_read, data_size-num_bytes_read);
    while (num_bytes_read != data_size) {
        num_bytes_read += read(fd, data_buf + num_bytes_read, data_size-num_bytes_read);
    }
    printf("HERE3");

    *buf = data_buf;
    *size = num_bytes_read;

}