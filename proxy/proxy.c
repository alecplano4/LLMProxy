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


// ----GLOBAL VARIABLES----------------------------------------------------------------------------
#define MAX_CLIENT_CONNECTIONS 10

//----FUNCTIONS------------------------------------------------------------------------------------
// Given port number and pointer to address struct, create TCP socket,
// bind to port number, and return socket file descriptor and address struct
int create_socket(int port, struct sockaddr_in* server_addr)
{
    int listening_socket_fd;

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

    if (bind(listening_socket_fd, (struct sockaddr*) server_addr, sizeof(struct sockaddr_in)) < 0) {
        perror("Error binding listening socket");
        exit(EXIT_FAILURE);
    }

    if (listen(listening_socket_fd, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

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
void configure_context(SSL_CTX *ctx) {
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "ca.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "ca.key", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void initialize_proxy(int listening_port) {

    // Declare variables
    int listening_socket_fd;
    struct sockaddr_in server_addr;
    char IP_address[INET_ADDRSTRLEN];
    SSL_CTX *ctx;

    // Prepare SSL Context object
    ctx = create_context(); // Get SSL Context to store TLS configuration parameters
    configure_context(ctx); // Load certificate and private key into context

    // Create listening socket using TCP
    listening_socket_fd = create_socket(listening_port, &server_addr);

    // Listen for incoming connections requests on "listening socket"
    listen(listening_socket_fd, MAX_CLIENT_CONNECTIONS);
    inet_ntop(AF_INET, &(server_addr.sin_addr), IP_address, INET_ADDRSTRLEN);
    printf("Listening for incoming connection requests... \nIP Address: %s \nPort: %d\n\n", IP_address, listening_port);

    while(1) {
        struct sockaddr_in client_addr;
        unsigned int len = sizeof(client_addr);
        SSL *ssl;
        const char reply[] = "test\n";

        // Accept client connection
        int client = accept(listening_socket_fd, (struct sockaddr*)&client_addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        // Set client connection to SSL
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            SSL_write(ssl, reply, strlen(reply));
        }

        // Close SSL connection and free data structure
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    // Close socket
    close(listening_socket_fd);

}


    //Assumption
    //ALEC: Assume getting an encrypted messgae
    //funciton will need string header, key from client to decrypte

void proxy_server(){
    printf("Proxy Server\n");
    //Decrypte header from client
    //encrytp https request
    //send it to internet
    //recieve message back
    //unencrypt message

    long res = 1;
    int ret = 1;
    unsigned long ssl_err = 0;
    
    SSL_CTX* ctx = NULL;
    BIO *web = NULL, *out = NULL;
    SSL *ssl = NULL;
    
    do {
        
        /* Internal function that wraps the OpenSSL init's   */
        /* Cannot fail because no OpenSSL function fails ??? */
        init_openssl_library();
        
        /* https://www.openssl.org/docs/ssl/SSL_CTX_new.html */
        const SSL_METHOD* method = SSLv23_method();
        ssl_err = ERR_get_error();
        
        ASSERT(NULL != method);
        if(!(NULL != method))
        {
            print_error_string(ssl_err, "SSLv23_method");
            break; /* failed */
        }
        
        /* http://www.openssl.org/docs/ssl/ctx_new.html */
        ctx = SSL_CTX_new(method);
        /* ctx = SSL_CTX_new(TLSv1_method()); */
        ssl_err = ERR_get_error();
        
        ASSERT(ctx != NULL);
        if(!(ctx != NULL))
        {
            print_error_string(ssl_err, "SSL_CTX_new");
            break; /* failed */
        }
        
        /* https://www.openssl.org/docs/ssl/ctx_set_verify.html */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
        /* Cannot fail ??? */
        
        /* https://www.openssl.org/docs/ssl/ctx_set_verify.html */
        SSL_CTX_set_verify_depth(ctx, 5);
        /* Cannot fail ??? */
        
        /* Remove the most egregious. Because SSLv2 and SSLv3 have been      */
        /* removed, a TLSv1.0 handshake is used. The client accepts TLSv1.0  */
        /* and above. An added benefit of TLS 1.0 and above are TLS          */
        /* extensions like Server Name Indicatior (SNI).                     */
        const long flags = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
        long old_opts = SSL_CTX_set_options(ctx, flags);
        UNUSED(old_opts);
        
        /* http://www.openssl.org/docs/ssl/SSL_CTX_load_verify_locations.html */
        res = SSL_CTX_load_verify_locations(ctx, "random-org-chain.pem", NULL);
        ssl_err = ERR_get_error();
        
        ASSERT(1 == res);
        if(!(1 == res))
        {
            /* Non-fatal, but something else will probably break later */
            print_error_string(ssl_err, "SSL_CTX_load_verify_locations");
            /* break; */
        }
        
        /* https://www.openssl.org/docs/crypto/BIO_f_ssl.html */
        web = BIO_new_ssl_connect(ctx);
        ssl_err = ERR_get_error();
        
        ASSERT(web != NULL);
        if(!(web != NULL))
        {
            print_error_string(ssl_err, "BIO_new_ssl_connect");
            break; /* failed */
        }
        
        /* https://www.openssl.org/docs/crypto/BIO_s_connect.html */
        res = BIO_set_conn_hostname(web, HOST_NAME ":" HOST_PORT);
        ssl_err = ERR_get_error();
        
        ASSERT(1 == res);
        if(!(1 == res))
        {
            print_error_string(ssl_err, "BIO_set_conn_hostname");
            break; /* failed */
        }
        
        /* https://www.openssl.org/docs/crypto/BIO_f_ssl.html */
        /* This copies an internal pointer. No need to free.  */
        BIO_get_ssl(web, &ssl);
        ssl_err = ERR_get_error();
        
        ASSERT(ssl != NULL);
        if(!(ssl != NULL))
        {
            print_error_string(ssl_err, "BIO_get_ssl");
            break; /* failed */
        }
        
        /* https://www.openssl.org/docs/ssl/ssl.html#DEALING_WITH_PROTOCOL_CONTEXTS */
        /* https://www.openssl.org/docs/ssl/SSL_CTX_set_cipher_list.html            */
        res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
        ssl_err = ERR_get_error();
        
        ASSERT(1 == res);
        if(!(1 == res))
        {
            print_error_string(ssl_err, "SSL_set_cipher_list");
            break; /* failed */
        }

        /* No documentation. See the source code for tls.h and s_client.c */
        res = SSL_set_tlsext_host_name(ssl, HOST_NAME);
        ssl_err = ERR_get_error();
        
        ASSERT(1 == res);
        if(!(1 == res))
        {
            /* Non-fatal, but who knows what cert might be served by an SNI server  */
            /* (We know its the default site's cert in Apache and IIS...)           */
            print_error_string(ssl_err, "SSL_set_tlsext_host_name");
            /* break; */
        }
        
        /* https://www.openssl.org/docs/crypto/BIO_s_file.html */
        out = BIO_new_fp(stdout, BIO_NOCLOSE);
        ssl_err = ERR_get_error();
        
        ASSERT(NULL != out);
        if(!(NULL != out))
        {
            print_error_string(ssl_err, "BIO_new_fp");
            break; /* failed */
        }
        
        /* https://www.openssl.org/docs/crypto/BIO_s_connect.html */
        res = BIO_do_connect(web);
        ssl_err = ERR_get_error();
        
        ASSERT(1 == res);
        if(!(1 == res))
        {
            print_error_string(ssl_err, "BIO_do_connect");
            break; /* failed */
        }
        
        /* https://www.openssl.org/docs/crypto/BIO_f_ssl.html */
        res = BIO_do_handshake(web);
        ssl_err = ERR_get_error();
        
        ASSERT(1 == res);
        if(!(1 == res))
        {
            print_error_string(ssl_err, "BIO_do_handshake");
            break; /* failed */
        }
        
        /**************************************************************************************/
        /**************************************************************************************/
        /* You need to perform X509 verification here. There are two documents that provide   */
        /*   guidance on the gyrations. First is RFC 5280, and second is RFC 6125. Two other  */
        /*   documents of interest are:                                                       */
        /*     Baseline Certificate Requirements:                                             */
        /*       https://www.cabforum.org/Baseline_Requirements_V1_1_6.pdf                    */
        /*     Extended Validation Certificate Requirements:                                  */
        /*       https://www.cabforum.org/Guidelines_v1_4_3.pdf                               */
        /*                                                                                    */
        /* Here are the minimum steps you should perform:                                     */
        /*   1. Call SSL_get_peer_certificate and ensure the certificate is non-NULL. It      */
        /*      should never be NULL because Anonymous Diffie-Hellman (ADH) is not allowed.   */
        /*   2. Call SSL_get_verify_result and ensure it returns X509_V_OK. This return value */
        /*      depends upon your verify_callback if you provided one. If not, the library    */
        /*      default validation is fine (and you should not need to change it).            */
        /*   3. Verify either the CN or the SAN matches the host you attempted to connect to. */
        /*      Note Well (N.B.): OpenSSL prior to version 1.1.0 did *NOT* perform hostname   */
        /*      verification. If you are using OpenSSL 0.9.8 or 1.0.1, then you will need     */
        /*      to perform hostname verification yourself. The code to get you started on     */
        /*      hostname verification is provided in print_cn_name and print_san_name. Be     */
        /*      sure you are sensitive to ccTLDs (don't navively transform the hostname       */
        /*      string). http://publicsuffix.org/ might be helpful.                           */
        /*                                                                                    */
        /* If all three checks succeed, then you have a chance at a secure connection. But    */
        /*   its only a chance, and you should either pin your certificates (to remove DNS,   */
        /*   CA, and Web Hosters from the equation) or implement a Trust-On-First-Use (TOFU)  */
        /*   scheme like Perspectives or SSH. But before you TOFU, you still have to make     */
        /*   the customary checks to ensure the certifcate passes the sniff test.             */
        /*                                                                                    */
        /* Happy certificate validation hunting!                                              */
        /**************************************************************************************/
        /**************************************************************************************/
        
        
        /* Step 1: verify a server certifcate was presented during negotiation */
        /* https://www.openssl.org/docs/ssl/SSL_get_peer_certificate.html          */
        X509* cert = SSL_get_peer_certificate(ssl);
        if(cert) { X509_free(cert); } /* Free immediately */
        
        ASSERT(NULL != cert);
        if(NULL == cert)
        {
            /* Hack a code for print_error_string. */
            print_error_string(X509_V_ERR_APPLICATION_VERIFICATION, "SSL_get_peer_certificate");
            break; /* failed */
        }
        
        /* Step 2: verify the result of chain verifcation             */
        /* http://www.openssl.org/docs/ssl/SSL_get_verify_result.html */
        /* Error codes: http://www.openssl.org/docs/apps/verify.html  */
        res = SSL_get_verify_result(ssl);
        
        ASSERT(X509_V_OK == res);
        if(!(X509_V_OK == res))
        {
            /* Hack a code into print_error_string. */
            print_error_string((unsigned long)res, "SSL_get_verify_results");
            break; /* failed */
        }
        
        /* Step 3: hostname verifcation.   */
        /* An exercise left to the reader. */
        
        /**************************************************************************************/
        /**************************************************************************************/
        /* Now, we can finally start reading and writing to the BIO...                        */
        /**************************************************************************************/
        /**************************************************************************************/
        
        BIO_puts(web, "GET " HOST_RESOURCE " HTTP/1.1\r\nHost: " HOST_NAME "\r\nConnection: close\r\n\r\n");
        BIO_puts(out, "\nFetching: " HOST_RESOURCE "\n\n");
        
        int len = 0;
        do {
            char buff[1536] = {};
            
            /* https://www.openssl.org/docs/crypto/BIO_read.html */
            len = BIO_read(web, buff, sizeof(buff));
            
            if(len > 0)
                BIO_write(out, buff, len);
            
            /* BIO_should_retry returns TRUE unless there's an  */
            /* error. We expect an error when the server        */
            /* provides the response and closes the connection. */
            
        } while (len > 0 || BIO_should_retry(web));
        
        ret = 0;
        
    } while (0);
    
    if(out)
        BIO_free(out);
    
    if(web != NULL)
        BIO_free_all(web);
    
    if(NULL != ctx)
        SSL_CTX_free(ctx);
    
    return ret;

}

//-------------------------------------------------------------------------------------------------
