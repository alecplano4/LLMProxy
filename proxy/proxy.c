//----HEADER---------------------------------------------------------------------------------------
// Date:        November 2024
// Script:      proxy.c
// Usage:       Implementation file for proxy
//*************************************************************************************************
#include "proxy.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>
#include <openssl/err.h>
#include <netdb.h>



// ----GLOBAL VARIABLES----------------------------------------------------------------------------
#define MAX_CLIENT_CONNECTIONS 10
#define HOST_NAME_LENGTH 100
#define BUFSIZE 81920

X509 *create_signed_cert(SSL_CTX *root_ctx, const char *common_name);

#define TCP_DEBUG
#define SSL_DEBUG

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
SSL_CTX *create_context()
{
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
void configure_context(SSL_CTX *ctx, const char* certificate, const char* key)
{
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
void extract_hostname(const char *request, char *hostname)
{
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


void create_server_certificate(const char* root_cert_file, const char* root_key_file, 
                               char* hostname, char* server_cert_file, char* server_key_file) 
{

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

}

// Each certificate requires a unique serial number. Use file to store
// counter, incrementing for each serial number.
int read_increment_save_serial_number(const char *file_path)
{
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

    printf("Updated serial number: %d\n", serial_number);
    return serial_number;
}

// Given listening port, begin listening and
// return proxy data structure
proxy_t* initialize_proxy(int listening_port)
{
    proxy_t* new_proxy = malloc(sizeof(proxy_t));

    // Create socket and begin listening
    new_proxy->listening_fd = create_socket(listening_port, &(new_proxy->proxy_addr));
    new_proxy->head = NULL;
    new_proxy->num_cs = 0;

    return new_proxy;
}


void run_proxy(int listening_port, bool tunnel_mode)
{
    // Specify file path of root certificate and key for signing
    const char *root_cert_file = "ca.crt";
    const char *root_key_file = "ca.key";

    // Begin listening for connections and store proxy information in
    // proxy_t data structure
    proxy_t* p = initialize_proxy(listening_port);

    fd_set read_fds;
    FD_ZERO(&read_fds);

    struct timeval timeout;
    // timeout.tv_sec = 1;  // Seconds
    // timeout.tv_usec = 0; // Microseconds (500ms)

    while(1) {

        //TODO: create a set_fds function that loops through linked list and adds fds to sets
        //printf("NEW Select call");
        /* Always want to be listening for new connection*/
        proxy_remove_invalid(p);
        FD_ZERO(&read_fds);
        proxy_create_fds(p, &read_fds);
        proxy_set_timeout(p, &timeout);
        FD_SET(p->listening_fd, &read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        //usleep(100000);
        //print_cs(p);
        // printf("-----------------------NEW SELECT--------------------------\n");
        // printf("TIMEOUT= %ld\n", timeout.tv_sec);


        int select_ret = select(FD_SETSIZE, &read_fds, NULL, NULL, &timeout);

        /* error with select */
        if (select_ret == -1) {
            printf("ERROR: select with errno: %d\n", errno);
            exit(EXIT_FAILURE);
        }
        /* No data available on any file descriptors */
        else if (select_ret == 0) {
            printf("DEBUG: Invalidating old\n");
            invalidate_old(p);
        }
        /* socket file descriptors ready for reading */
        else {
            /* Current implementation does not work concurently 
                it runs all instructions for a server at once*/
            
            // Read input from stdin
            if(FD_ISSET(STDIN_FILENO, &read_fds)){
                char buffer[1024];
                int bytes_read;
                bytes_read = read(STDIN_FILENO, buffer, sizeof(buffer) - 1);
                printf("Input Command: %.*s\n", bytes_read, buffer);
                if(strncmp(buffer,"ls\n",3) == 0){
                    // print_cs(p);
                }if(strncmp(buffer,"exit\n",5) == 0){
                    break;
                }

            }

            // New client connection
            if (FD_ISSET(p->listening_fd, &read_fds)) {
                if(tunnel_mode){
                    client_server_t* cs = malloc(sizeof(client_server_t));
                    //cs->client_read = true;
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
                    (void)l;

                    cs->data = malloc(bytes_read);
                    memcpy(cs->data, header_copy_for_server, bytes_read);
                    cs->data_len = bytes_read;
                    //cs->client_read = false;

                    proxy_add_cs(p, cs);
                    
                }else{
                    #ifdef TCP_DEBUG
                    printf("New Connection Inbound\n");
                    #endif
                    client_server_t* cs = malloc(sizeof(client_server_t));
                    //cs->client_read = true;
                    cs->invalid = false;
                    cs->bytes_read = 0;
                    
                    cs->client_addr_len = sizeof(cs->client_addr);

                    char server_cert_file[HOST_NAME_LENGTH] = {0};
                    char server_key_file[HOST_NAME_LENGTH] = {0};
                    

                    cs->client_fd = accept(p->listening_fd, (struct sockaddr*)&(cs->client_addr), &(cs->client_addr_len));
                    if (cs->client_fd < 0) {
                        /* IF unsuccessful, set invalid and free resourses
                        KEEP PROGRAM GOING */
                        #ifdef TCP_DEBUG
                        printf("Unable to accept new connection\n");
                        #endif
                        cs->invalid = true;
                        continue;
                    }
                    #ifdef TCP_DEBUG
                    printf("Client TCP handshake successful\n");
                    #endif
                    // Receive client data
                    char request[BUFSIZE];
                    char hostname[100];
                    int bytes_received = recv(cs->client_fd, request, sizeof(request)-1, 0);

                    #ifdef TCP_DEBUG
                    printf("Bytes received: %d\n", bytes_received);
                    printf("Message: %s\n", request);
                    #endif
                    
                    extract_hostname(request, hostname);

                    #ifdef TCP_DEBUG
                    printf("Hostname: %s\n", hostname);
                    #endif

                    // Client expects "Connection Established" response to CONNECT request.
                    // Must be sent for client to initiate SSL handshake
                    if (strstr(request, "CONNECT") == request) {
                        // Respond with "HTTP/1.1 200 Connection Established"
                        const char *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
                        send(cs->client_fd, response, strlen(response), 0);
                        #ifdef SSL_DEBUG
                        printf("Sent response to client:\n%s\n", response);
                        #endif

                        // Create server certificate and save to disk
                        create_server_certificate(root_cert_file, root_key_file, hostname, server_cert_file, server_key_file);
                        #ifdef SSL_DEBUG
                        printf("\n--------------------\nCERTIFICATE CREATED\n--------------------\n\n");
                        #endif
                        // Prepare SSL Context object
                        cs->client_ctx = create_context();  
                        #ifdef SSL_DEBUG                                  // Get SSL Context to store TLS configuration parameters
                        printf("Context created\n");
                        #endif

                        configure_context(cs->client_ctx, server_cert_file, server_key_file); // Load certificate and private key into context
                        
                        #ifdef SSL_DEBUG
                        printf("Certificate loaded into context\n");
                        #endif

                        // Set client connection to SSL (perform SSL handshake)
                        cs->client_ssl = SSL_new(cs->client_ctx);     // Create SSL object
                        SSL_set_fd(cs->client_ssl, cs->client_fd);    // Link SSL object to accepted TCP socket
                        
                        #ifdef SSL_DEBUG
                        printf("SSL object created and linked to TCP socket\n");
                        #endif

                        if (SSL_accept(cs->client_ssl) <= 0) {        // Perform SSL handshake
                            printf("Unsuccessful client SSL handshake\n");
                            ERR_print_errors_fp(stderr);
                            cs->invalid = true;
                            continue;
                        } else {
                            printf("SSL handshake completed.\n");
                        }
                        /* DONE WITH SSL CONNECTION */
                        /* AT THIS POINT WE WANT TO GET INTO THE PARALLEL FACILOTATION */
                        /* RECIEVE NEXT MESSAGE */

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
                            //exit(EXIT_FAILURE);
                            cs->invalid = true;
                            proxy_add_cs(p, cs);
                            continue;
                        }
                        cs->server_ssl = create_ssl_connection(cs->server_ctx, cs->server_fd);
                        if(cs->server_ssl == NULL){
                            cs->invalid = true;
                        }
                        remove(server_cert_file);
                        remove(server_key_file);


                        (cs->timeout).tv_sec = 60;
                        gettimeofday(&(cs->last_update), NULL);
                        proxy_add_cs(p, cs);
                    } else {
                        #ifdef TCP_DEBUG
                        printf("Invalid request: Not a CONNECT request\n");
                        #endif
                        cs->invalid = true;
                        proxy_add_cs(p, cs);
                    }
                }
            }

            //for all fds in the list add call relay
            client_server_t* cs = p->head;
            for(int i = 0; i<p->num_cs; i++){
                client_server_t* next = cs->next;
                if(tunnel_mode){
                    if(FD_ISSET(cs->server_fd, &read_fds)){
                        printf("SERVER is ready to read\n");
                        char buf[1000] = {0};
                        int br = read(cs->server_fd, buf, 1000);
                        printf("Read %d bytes from server:\n%s\n", br, buf);
                        write(cs->client_fd, buf, br);
                        //cs->client_read = true;
                    } else  if(FD_ISSET(cs->client_fd, &read_fds)){
                        printf("Client is ready to read\n");
                        char buf[1000] = {0};
                        int br = read(cs->client_fd, buf, 1000);
                        //printf("Read %d bytes from server:\n%s\n", br, buf);
                        if(br == 0){
                            printf("Clinet Closed Connection");
                            cs->invalid = true;
                        }
                        //cs->client_read = false;
                    } 
                }else{
                    if(FD_ISSET(cs->client_fd, &read_fds)){
                        if(cs->invalid)
                            continue;
                        printf("READING FROM CLIENT(%d:%d)\n", cs->client_fd, cs->server_fd);
                        int bytes;
                        char server_response[BUFSIZE] = {0};
                        bytes = SSL_read(cs->client_ssl, server_response, BUFSIZE);
                        printf("Client to server(%d)\n%s\n",bytes, server_response);
                        if(bytes == 0){
                            printf("Clinet Closed Connection");
                            cs->invalid = true;
                            continue;;
                        }
                        else if (SSL_write(cs->server_ssl, server_response, bytes) <= 0) {
                            printf("ERROR with ssl_write\n");
                            //exit(EXIT_FAILURE);
                            cs->invalid = true;
                        }
                        (cs->timeout).tv_sec = 60;
                        gettimeofday(&(cs->last_update), NULL);

                        //cs->client_read = false;
                    }
                    if(FD_ISSET(cs->server_fd, &read_fds)){
                        if(cs->invalid)
                            continue;
                        printf("SERVER is ready to read(%d:%d)\n", cs->client_fd, cs->server_fd);
                        char buf[BUFSIZE] = {0};
                        int br = SSL_read(cs->server_ssl, buf, BUFSIZE);
                        printf("DATA: %.*s", br, buf);
                        if(br == 0){
                            printf("Clinet Closed Connection");
                            cs->invalid = true;
                            continue;
                        }

                        // TODO: INSERT LLM FUNCTIONALITY HERE

                        else if (SSL_write(cs->client_ssl, buf, br) <= 0) {
                            printf("ERROR with ssl_write\n");
                            //exit(EXIT_FAILURE);
                            cs->invalid = true;
                            //SSL_shutdown(cs->client_ssl);
                            continue;
                        }
                        cs->bytes_read+=br;
                        (cs->timeout).tv_sec = 60;
                        gettimeofday(&(cs->last_update), NULL);
                        printf("Read %d bytes from server for %d out of %d:\n", br, cs->bytes_read, cs->data_len);

                    }
                }
                                        
                cs = next;
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
            (void)http_v;
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

void proxy_clean(proxy_t* p)
{
    close(p->listening_fd);
    client_server_t* cs = p->head;
    while(cs != NULL){
        client_server_t* next = cs->next;

        free(cs);
        cs = next;
    }
}


SSL *create_ssl_connection(SSL_CTX *ctx, int sockfd)
{
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) <= 0) {
        #ifdef SSL_DEBUG
        printf("Failed to make SSL Connection\n");
        #endif
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = NULL;
    }
    return ssl;
}

int open_connection(const char *hostname, int port)
{
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
    while(cs!=NULL){
        client_server_t* next = cs->next;
        if(cs->invalid == false){
            FD_SET(cs->client_fd, read_fds);


            FD_SET(cs->server_fd, read_fds);
        }

        cs = next;
    }
}

void proxy_remove_invalid(proxy_t* p)
{
    printf("REMOVING INVALID ENTRIES\n");
    bool remove_first = false;
    client_server_t* prev = p->head;
    if(prev!= NULL){
        if(prev->invalid){
            remove_first = true;
        }
        client_server_t* curr = prev->next;
        while(curr!=NULL){
            //printf("AAAAAH\n");
            client_server_t* next = curr->next;
            if(curr->invalid){
                if(curr->server_ssl!=NULL){
                    //SSL_shutdown(curr->server_ssl);
                    SSL_free(curr->server_ssl);
                }
                if(curr->client_ssl!=NULL){
                    //SSL_shutdown(curr->client_ssl);
                    SSL_free(curr->client_ssl);
                }
                if(curr->h!=NULL){
                    free(curr->h);

                }
                if(curr->data != NULL){
                    free(curr->data);

                }
                if(curr->client_fd!=0){
                    close(curr->client_fd);

                }
                if(curr->server_fd!=0){
                    close(curr->server_fd);

                }
                free(curr);
                p->num_cs--;
                prev->next = next;
                curr = next;
            }else{
                prev = prev->next;
                curr = curr->next;
            }
            // print_cs(p);
        }
        if(remove_first){
            client_server_t* new_head = p->head->next;
            if(p->head->server_ssl!=NULL){
            //SSL_shutdown(p->head->server_ssl);
            SSL_free(p->head->server_ssl);
            }
            if(p->head->client_ssl!=NULL){
            //SSL_shutdown(p->head->client_ssl);
            SSL_free(p->head->client_ssl);
            }
            if(p->head->h!=NULL){
            free(p->head->h);

            }
            if(p->head->data != NULL){
            free(p->head->data);

            }
            if(p->head->client_fd!=0){
            close(p->head->client_fd);

            }
            if(p->head->server_fd!=0){
            close(p->head->server_fd);

            }
            free(p->head);
            p->num_cs--;
            p->head = new_head;
            // print_cs(p);
        }

    }
}


void print_cs(proxy_t* p)
{
    client_server_t* cs = p->head;
    client_server_t* next = cs;
    while(next != NULL) {
        printf("%d:%d(%d) -> ", next->client_fd, next->server_fd, next->invalid);
        next = next->next;
    }
    printf("(null)\n");
}

void proxy_set_timeout(proxy_t* p, struct timeval* timeout)
{
    timeout->tv_sec = 60;
    client_server_t* next = p->head;
    while(next != NULL) {
        struct timeval now;
        gettimeofday(&now, NULL);
        long diff = now.tv_sec-((next->last_update).tv_sec);
        // printf("DIFF %ld\n", diff);
        int new_timout = 60 - diff;
        if(new_timout<0){
            next->timeout.tv_sec = 0;
        }else{
            next->timeout.tv_sec = new_timout;
        }
        if (next->timeout.tv_sec < timeout->tv_sec ) {
            timeout->tv_sec = next->timeout.tv_sec;
        }
        next = next->next;
    }
}

void invalidate_old(proxy_t* p)
{
    client_server_t* next = p->head;
    while(next != NULL) {
        struct timeval now;
        gettimeofday(&now, NULL);
        long diff = now.tv_sec-((next->last_update).tv_sec);
        if (diff >= 60) {
            next->invalid = true;
        }
        next = next->next;
    }  
}