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
    SSL* client_ssl;
    SSL_CTX* client_ctx;
    struct sockaddr_in client_addr;
    unsigned int client_addr_len;
    header_elems* h;

    char* data;
    int data_len;

    int server_fd;
    SSL* server_ssl;
    SSL_CTX* server_ctx;
    int bytes_read;

    bool invalid;
    struct client_server* next;
} client_server_t;

typedef struct proxy {
    int listening_fd;
    struct sockaddr_in proxy_addr;

    int num_cs;
    client_server_t* head;
} proxy_t;


//----FUNCTIONS------------------------------------------------------------------------------------

proxy_t* initialize_proxy(int listening_port);
void proxy_clean(proxy_t* p);

void run_proxy(int listening_port, bool tunnel_mode);

header_elems* proxy_parse_header(char* header);
//void proxy_read_server(SSL* ssl, int fd, char** buf, int* size, char** h_buf, int* h_size, bool tunnel_mode);
int proxy_connect_server(header_elems* header);

void proxy_read_server(int fd, char** buf, int* size, char** h_buf, int* h_size);


int create_socket(int port, struct sockaddr_in* server_addr);
void initialize_proxy_test(int listening_port);
SSL_CTX *create_context(void);
void configure_context(SSL_CTX *ctx, const char* certificate, const char* key);
void proxy_server(void);
void ssl_init(SSL_CTX** ctx, const char *certfile, const char *keyfile);



SSL *create_ssl_connection(SSL_CTX *ctx, int sockfd);
int open_connection(const char *hostname, int port);

void print_header_elems(header_elems* h);

void proxy_add_cs(proxy_t* p, client_server_t* cs);

void proxy_create_fds(proxy_t* p, fd_set *read_fds);
void proxy_remove_cs(proxy_t* p, client_server_t* cs);

void print_cs(proxy_t* p);
int read_increment_save_serial_number(const char *file_path);

#endif
//-------------------------------------------------------------------------------------------------
