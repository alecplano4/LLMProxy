//----HEADER---------------------------------------------------------------------------------------
// Date:        November 2024
// Script:      proxy.h 
// Usage:       Header file for proxy
//*************************************************************************************************
#ifndef PROXY_H
#define PROXY_H

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <netinet/in.h> // Provides sockaddr_in struct

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>


#define BUFSIZE 100
// ----GLOBAL VARIABLES----------------------------------------------------------------------------

// ----STRUCT--------------------------------------------------------------------------------------

typedef struct header_elems {
    char* url;
    char* host;
    char* port;
    char* max_age;
    char* data_len;
} header_elems;

typedef struct client_server{
    bool client_read;

    int client_fd;
    struct sockaddr_in client_addr;
    unsigned int client_addr_len;

    header_elems* h;

    int server_fd;

    struct client_server* next;
} client_server_t;

typedef struct proxy {
    int listening_fd;
    struct sockaddr_in proxy_addr;

    client_server_t* head;
} proxy_t;


//----FUNCTIONS------------------------------------------------------------------------------------

proxy_t* initialize_proxy(int listening_port);
void proxy_clean(proxy_t* p);

// void run_proxy(int listening_port, bool tunnel_mode);

header_elems* proxy_parse_header(char* header);
void proxy_read_server(int fd, char** buf, int* size, char** h_buf, int* h_size);
int proxy_connect_server(header_elems* header);



int create_socket(int port, struct sockaddr_in* server_addr);
void initialize_proxy_test(int listening_port);
SSL_CTX *create_context(void);
void configure_context(SSL_CTX *ctx, const char* certificate, const char* key);
void proxy_server(void);
void ssl_init(SSL_CTX** ctx, const char *certfile, const char *keyfile);



SSL *create_ssl_connection(SSL_CTX *ctx, int sockfd);
int open_connection(const char *hostname, int port);




#endif
//-------------------------------------------------------------------------------------------------
