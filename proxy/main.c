//----HEADER---------------------------------------------------------------------------------------
// Date:        November 2024
// Script:      main.c 
// Usage:       ./proxy <port> 
//*************************************************************************************************
#include <stdio.h>
#include <stdlib.h>

#include "proxy.h"       

// ----GLOBAL VARIABLES----------------------------------------------------------------------------

//----FUNCTIONS------------------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    
    // Declare variables
    int listening_port;
    bool tunnel_mode = false; 

    // Get port number from argv
    if(argc != 2 && argc!=3) {
        printf("Usage: %s <port>\n", argv[0]);
        return -1;
    }
    listening_port = atoi(argv[1]);
    if(argc == 3){
        if(strcmp(argv[2],"-tunnel") == 0){
            printf("Using Tunnel Mode\n");
            tunnel_mode = true;
        }
    }

    run_proxy(listening_port, tunnel_mode);
}

//-------------------------------------------------------------------------------------------------