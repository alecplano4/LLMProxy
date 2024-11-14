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
    int LISTENING_PORT; 

    // Get port number from argv
    if(argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return -1;
    }
    LISTENING_PORT = atoi(argv[1]);

    // Initialize server
    initialize_proxy(LISTENING_PORT);
}

//-------------------------------------------------------------------------------------------------