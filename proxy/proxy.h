//----HEADER---------------------------------------------------------------------------------------
// Date:        November 2024
// Script:      proxy.h 
// Usage:       Header file for proxy
//*************************************************************************************************
#ifndef PROXY_H
#define PROXY_H

#include <stdio.h>
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

//----FUNCTIONS------------------------------------------------------------------------------------
int create_socket(int port, struct sockaddr_in* server_addr);
void initialize_proxy(int listening_port);
SSL_CTX *create_context(void);
void configure_context(SSL_CTX *ctx, const char* certificate, const char* key);
void proxy_server(void);
void ssl_init(SSL_CTX** ctx, const char *certfile, const char *keyfile);

#endif
//-------------------------------------------------------------------------------------------------
