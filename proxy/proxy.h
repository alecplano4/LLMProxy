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



// ----GLOBAL VARIABLES----------------------------------------------------------------------------

// ----STRUCT--------------------------------------------------------------------------------------

//----FUNCTIONS------------------------------------------------------------------------------------
void initialize_proxy(int listening_port);

void proxy_server();

#endif
//-------------------------------------------------------------------------------------------------