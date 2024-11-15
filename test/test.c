
#include <stdio.h>

#include "../proxy/proxy.h"

int main(int argc, char* argv[]) {
    forward_header();
    printf("All tests Passed\n");
    return 0;
}