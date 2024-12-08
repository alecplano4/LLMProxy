//----HEADER---------------------------------------------------------------------------------------
// Date:        November 2024
// Script:      proxy.c
// Usage:       Implementation file for proxy
//*************************************************************************************************
#include "proxy.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <unistd.h>
#include <openssl/err.h>
#include <netdb.h>
#include <curl/curl.h>



// ----GLOBAL VARIABLES----------------------------------------------------------------------------
#define MAX_CLIENT_CONNECTIONS 10
#define HOST_NAME_LENGTH 100
#define BUFSIZE 81920

#define TCP_DEBUG
#define SSL_DEBUG
#define IMPORTANT_INFO

const char *url = "https://a061igc186.execute-api.us-east-1.amazonaws.com/dev";
const char *x_api_key = "x-api-key: comp112XKNZIOqcTzsCltN0ufGJjsYT3KyZEUHrDesQO2eR";

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

    return listening_socket_fd;
}

// Fix LLM response for HTML formatting (prior to sending to client)
void remove_non_html(char* input, char* output){
    // Remove incorrect backslashes
    char fixed_input[4096];
    int i = 4;
    int j = 0;
    while(*(input+i) != '\0'){
        if(*(input+i) == '\\'){
            if(*(input+i+1) == 'n'){
                i++;
            }
        }else{
            *(fixed_input+j) = *(input+i);
            j++;
        }
        i++;
    }
    *(fixed_input+j) = '\0';

    // Add HTTP header to output buffer
    int content_length = strlen(fixed_input);
    sprintf(output, "HTTP/1.1 200 OK\r\nContent-Type: text/html;\r\ncharset=UTF-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", content_length, fixed_input);
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

// Given client GET request for Wikipedia search, 
// extract the contents of the search from the request
void extract_wikipedia_search(char* server_response, char* search) {
    // Format: "/search-redirect.php?family=Wikipedia&language=en&search=<search word 1>+<search word 2>&language=en&go=Go"
    char *start, *end;

    // Find the first occurrence of '='
    start = strchr(server_response, '=');
    if (start != NULL) {
        // Find the second '='
        start = strchr(start + 1, '=');
        if (start != NULL) {
            start = strchr(start + 1, '=');
            // Find the third '='
            if (start != NULL) {
                start++;
                // Find the ampersand '&' (indicating the end of the search)
                end = strchr(start, '&');
                if (end != NULL) {
                    // Copy the substring between the 3rd '=' and the '&'
                    strncpy(search, start, end - start);
                    search[end - start] = '\0'; // Null-terminate the string
                    // Iterate over string to replace '+' character with space ' ' character
                    for(int i = 0; i < end - start; i++) {
                        if(*(search + i) == '+') {
                            search[i] = ' ';
                        }
                    }
                }
            }
        }
    }
    
}


/* Given client HTTP request, return True if request is GET request
   for Wikipedia search */
bool wikipedia_search(char* client_request) {
    // Wikipedia GET request substring extracted manually from observed
    // search request
    char wiki_search_substr[] = "=Wikipedia&language=en&search=";
    if(strstr(client_request, wiki_search_substr) != NULL) {
        return true;
    }
    return false;
}

void create_server_certificate(const char* root_cert_file, const char* root_key_file, 
                               char* hostname, char* server_cert_file, char* server_key_file) 
{

    // printf("Certificate Commands:\n");
    /*---1. CREATE SERVER SUBJECT -------------------------------------------*/
    // Curl relies on the Common Name (CN) in the subject field for domain validation.
    // Browsers rely on the SAN field for domain validation
    char subject[500];
    snprintf(subject, sizeof(subject), 
             "/C=US/ST=MA/L=Boston/O=Tufts/OU=GSE/CN=%s/emailAddress=it@example.com", 
             hostname);


    /*---2. CREATE PRIVATE KEY ----------------------------------------------*/
    // Create private key for server certificate    
    char cmd_create_private_key[500];
    snprintf(cmd_create_private_key, sizeof(cmd_create_private_key), 
             "openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out certificates/%s_key.pem > /dev/null 2>&1", hostname);

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

    system(cmd_create_CSR);

    /*---4. SIGN CSR WITH CERTIFICATE AUTHORITY ----------------------------*/
    char command_sign_CSR[500];
    snprintf(command_sign_CSR, sizeof(command_sign_CSR), 
             "openssl x509 -req -days 365 -in certificates/%s_csr.pem -CA %s -CAkey %s -CAcreateserial -out certificates/%s_cert.pem -extfile openssl_custom.cnf -extensions v3_req", 
             hostname, root_cert_file, root_key_file, hostname);

    system(command_sign_CSR);
    snprintf(server_cert_file, HOST_NAME_LENGTH, "certificates/%s_cert.pem", hostname);

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

header_elems* proxy_parse_header(char* header)
{
    header_elems* h = (header_elems*)calloc(1,sizeof(header_elems));

    char* nl_delim = "\n";
    char* cr_delim = "\r";
    char* space_delim = " ";
    
    char* last;
    char* line = strtok_r(header, nl_delim, &last);
    printf("%s", line);
    while(strcmp(line, "\r") != 0){
        char* inner_last;
        char* command = strtok_r(line, space_delim, &inner_last);

        if(strcmp(command, "GET") == 0 || strcmp(command, "HEAD") == 0) {
            h->url = strtok_r(NULL, space_delim, &inner_last);
            char* http_v = strtok_r(NULL, cr_delim,&inner_last);
            (void)http_v;

        }else if(strcmp(command, "Host:") == 0) {
            h->host = strtok_r(NULL, cr_delim, &inner_last);
            if(strstr(h->host, ":") == NULL){
                h->port = "443";
            }else{
                char* host_port_delim = (strstr(h->host, ":"));
                *host_port_delim = '\0';
                h->port = host_port_delim+1;
                
            }


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
    bool remove_first = false;
    client_server_t* prev = p->head;
    if(prev!= NULL){
        if(prev->invalid){
            remove_first = true;
        }
        client_server_t* curr = prev->next;
        while(curr!=NULL){
            client_server_t* next = curr->next;
            if(curr->invalid){
                if(curr->server_ssl!=NULL){
                    SSL_free(curr->server_ssl);
                }
                if(curr->client_ssl!=NULL){
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
        }
        if(remove_first){
            client_server_t* new_head = p->head->next;
            if(p->head->server_ssl!=NULL){
                SSL_free(p->head->server_ssl);
            }
            if(p->head->client_ssl!=NULL){
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

size_t write_callback(void *ptr, size_t size, size_t nmemb, char *data) {
    size_t total_size = size * nmemb; // Total size of received data
    strncat(data, ptr, total_size); // Append the received data to the buffer
    return total_size;
}

void llmproxy_request(char *model, char *system, char *query, char *response_body){
    CURL *curl;
    CURLcode res;


    char *request_fmt = "{\n"
                        "  \"model\": \"%s\",\n"
                        "  \"system\": \"%s\",\n"
                        "  \"query\": \"%s\",\n"
                        "  \"temperature\": %.2f,\n"
                        "  \"lastk\": %d,\n"
                        "  \"session_id\": \"%s\"\n"
                        "}";

    // JSON data to send in the POST request
    char request[4096];
    memset(request, 0, 4096);
    snprintf(request,
             sizeof(request),
             request_fmt,
             model,
             system,
             query,
             0.7,
             0,
             "GenericSession");


    printf("Initiating request: %s\n", request);

    // Initialize CURL
    curl = curl_easy_init();
    if (curl) {
        // Set the URL of the Proxy Agent server server
        curl_easy_setopt(curl, CURLOPT_URL, url);

        // Set the Content-Type to application/json
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        
        // Add x-api-key to header
        headers = curl_slist_append(headers, x_api_key);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);


        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // add request 
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);


        // Set the write callback function to capture response data
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

        // Set the buffer to write the response into
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_body);

        // Perform the POST request
        res = curl_easy_perform(curl);

        // Check if the request was successful
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        // Cleanup
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    } else {
        fprintf(stderr, "Failed to initialize CURL.\n");
    }
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

    struct timeval timeout = {0};


    while(1) {

        /* Always want to be listening for new connection*/
        proxy_remove_invalid(p);
        FD_ZERO(&read_fds);
        proxy_create_fds(p, &read_fds);
        proxy_set_timeout(p, &timeout);
        FD_SET(p->listening_fd, &read_fds);
        FD_SET(STDIN_FILENO, &read_fds);

        printf("-----------------------NEW SELECT--------------------------\n");
        printf("TIMEOUT= %ld\n", timeout.tv_sec);


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
            if(FD_ISSET(STDIN_FILENO, &read_fds)){
                char buffer[1024];
                bzero(buffer, 1024);
                int bytes_read;
                bytes_read = read(STDIN_FILENO, buffer, sizeof(buffer) - 1);
                
                if(strncmp(buffer,"ls\n",3) == 0){
                    print_cs(p);
                }else if(strncmp(buffer,"exit\n",5) == 0){
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
                    printf("New TCP Connection\n");
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

                        // Create server certificate and save to disk
                        create_server_certificate(root_cert_file, root_key_file, hostname, server_cert_file, server_key_file);
                        #ifdef SSL_DEBUG
                        printf("\n--------------------\nCERTIFICATE CREATED\n--------------------\n\n");
                        #endif
                        // Prepare SSL Context object
                        cs->client_ctx = create_context();  

                        configure_context(cs->client_ctx, server_cert_file, server_key_file); // Load certificate and private key into context

                        // Set client connection to SSL (perform SSL handshake)
                        cs->client_ssl = SSL_new(cs->client_ctx);     // Create SSL object
                        SSL_set_fd(cs->client_ssl, cs->client_fd);    // Link SSL object to accepted TCP socket

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
                        //header_elems* header = proxy_parse_header(request_copy);
                        //print_header_elems(header);
                       

                        /* receive a message from the client*/
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
                        char buf[1000] = {0};
                        int br = read(cs->server_fd, buf, 1000);
                        printf("Read %d bytes from Server:\n", br);
                        write(cs->client_fd, buf, br);
                        //cs->client_read = true;
                    } else  if(FD_ISSET(cs->client_fd, &read_fds)){
                        char buf[1000] = {0};
                        int br = read(cs->client_fd, buf, 1000);
                        printf("Read %d bytes from Client:\n", br);
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
                        //printf("READING FROM CLIENT(%d:%d)\n", cs->client_fd, cs->server_fd);
                        int bytes;
                        char server_response[BUFSIZE] = {0};
                        bytes = SSL_read(cs->client_ssl, server_response, BUFSIZE);
                        //printf("Client to server(%d)\n%s\n",bytes, server_response);
                        // If Wikipedia search, intercept request (and do not send to server)
                        if(bytes == 0){
                            printf("Client Closed Connection");
                            cs->invalid = true;
                            continue;;
                        } else {
                            if(wikipedia_search(server_response)) {
                                // Do something
                                char search[4096];
                                extract_wikipedia_search(server_response, search);
                                printf("\n---------WIKIPEDIA SEARCH---------\n");
                                char response_body[4096];
                                llmproxy_request("4o-mini", 
                                                 "For a given topic, give me the 3 most relevant wikipidia articles, please be certain the wikipedia articles match real articles. I would like this formated as an annoted bibliography, with the link to the wikipedia article and a very short, max 3 sentences, summary of the article. Ensure your response is formated in html.", 
                                                 search, response_body);

                                // Fix response in preparation for HTML helper function
                                char* beg = strstr(response_body,"```")+3;
                                char* end = strstr(beg, "```");
                                *end = '\0';
                                char* refine_responce = malloc(4096);
                                remove_non_html(beg, refine_responce);
                                //printf("Refined response: \n%s", refine_responce);
                                if (SSL_write(cs->client_ssl, refine_responce, strlen(refine_responce)) <= 0) {
                                    printf("ERROR with ssl_write\n");
                                    //exit(EXIT_FAILURE);
                                    cs->invalid = true;
                                    //SSL_shutdown(cs->client_ssl);
                                    free(refine_responce);
                                    continue;
                                }
                                //printf("Finished LLM write to client!\n----------\n\n");
                                free(refine_responce);

                                SSL_free(cs->server_ssl);
                                cs->server_ssl = NULL;                    
                                close(cs->server_fd);
                                cs->server_fd = 0;

                            } else if (SSL_write(cs->server_ssl, server_response, bytes) <= 0) {
                                printf("ERROR with ssl_write\n");
                                //exit(EXIT_FAILURE);
                                cs->invalid = true;
                            }
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
                        //printf("DATA: %.*s", br, buf);
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
                        //printf("Read %d bytes from server for %d out of %d:\n", br, cs->bytes_read, cs->data_len);

                    }
                }
                                        
                cs = next;
            }
        }
    }
    proxy_clean(p);
}