/**********************************************************************
 *
 * Network Performance Test Utility (NWTEST)
 *
 * Copyright (c) Chris Jenkins 2019, 2020
 *
 * Licensed under the Universal Permissive License v 1.0 as shown
 * at http://oss.oracle.com/licenses/upl
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>
#include <signal.h>
#include <locale.h>
#if !defined(WINDOWS)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#else
#include "Ws2tcpip.h"
#endif

#include <nwtest.h>

/******************************************************************************
 * Data
 */

struct timeval pstart, pend;
struct rusage rstart, rend;

/******************************************************************************
 * Private functions
 */

static void
displaySizes(
    void
            )
{
    printf("sizeof( msghdr_t ) = %lu\n", sizeof( msghdr_t ) );
    printf("offsetof( msg_t, data ) = %lu\n", offsetof( msg_t, data ) );
    printf("sizeof( mconn_t ) = %lu\n", sizeof( mconn_t ) );
    printf("offsetof( mdata_t, datasz ) = %lu\n", offsetof( mdata_t, datasz ) );
    printf("offsetof( mdata_t, data ) = %lu\n", offsetof( mdata_t, data ) );
} // displaySizes

/******************************************************************************
 * Public functions
 */

/*
 * Process the help sub-command
 */

static int
cmdHelp(
    int    argc,
    char * argv[]
       )
{
    if (  argc != 1  )
        help( HELP );

    if (  ( strcmp( argv[0], "usage" ) == 0 ) ||
          ( strcmp( argv[0], "u" ) == 0 )  )
        help( USAGE );
    else
    if (  ( strcmp( argv[0], "general" ) == 0 ) ||
          ( strcmp( argv[0], "g" ) == 0 )  )
        help( GENERAL );
    else
    if (  ( strcmp( argv[0], "client" ) == 0 ) ||
          ( strcmp( argv[0], "c" ) == 0 )  )
        help( CLIENT );
    else
    if (  ( strcmp( argv[0], "server" ) == 0 ) ||
          ( strcmp( argv[0], "s" ) == 0 )  )
        help( SERVER );
    else
    if (  ( strcmp( argv[0], "metrics" ) == 0 ) ||
          ( strcmp( argv[0], "m" ) == 0 )  )
        help( METRICS );
    else
    if (  ( strcmp( argv[0], "full" ) == 0 ) ||
          ( strcmp( argv[0], "f" ) == 0 )  )
        help( FULL );
    else
        help( HELP );
    return HELP_EXIT;
} // cmdHelp

int
main(
    int    argc,
    char * argv[]
    )
{
    int ret = 0;

    setlocale( LC_ALL, "" );

    if (  argc < 2  )
        help( USAGE );

    setbuf( stdout, NULL );

    if (  ( strcmp( argv[1], "help" ) == 0 ) ||
          ( strcmp( argv[1], "h" ) == 0 )  )
        ret = cmdHelp( argc-2, &argv[2] );
    else
    if (  ( strcmp( argv[1], "server" ) == 0 ) ||
          ( strcmp( argv[1], "s" ) == 0 )  )
        ret = cmdServer( argc-2, &argv[2] );
    else
    if (  ( strcmp( argv[1], "client" ) == 0 ) ||
          ( strcmp( argv[1], "c" ) == 0 )  )
        ret = cmdClient( argc-2, &argv[2] );
    else
        help( USAGE );

    return ret;
} // main
