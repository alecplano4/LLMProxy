//----HEADER---------------------------------------------------------------------------------------
// Date:        November 2024
// Script:      main.c 
// Usage:       ./proxy <port>
//*************************************************************************************************
#include <stdio.h>
#include <stdlib.h>

#include "client.h"       

// ----GLOBAL VARIABLES----------------------------------------------------------------------------

//----FUNCTIONS------------------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    
    // Declare variables
    int SERVER_PORT; 

    // Get port number from argv
    if(argc != 3) {
        printf("Usage: %s <port> <client_ID> \n", argv[0]);
        return -1;
    }
    SERVER_PORT = atoi(argv[1]);

    // Connect to server
    int client_socket = connect_to_server(SERVER_PORT);

    // Disconnect from server
    disconnect_from_server(client_socket);

    return 0;
}

//-------------------------------------------------------------------------------------------------