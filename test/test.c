
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <stdbool.h>

#include <openssl/err.h>

#include "../proxy/proxy.h"



int main(int argc, char* argv[]) {
    initialize_proxy_test(9105);
    printf("All tests Passed\n");
    return 0;
}
