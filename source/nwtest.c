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
 * Global Data
 */

struct timeval pstart, pend;
struct rusage rstart, rend;

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
        help( HELP, 1 );

#if defined(ENABLE_DEBUG)
    if (  ( strcmp( argv[0], "debug" ) == 0 ) ||
          ( strcmp( argv[0], "d" ) == 0 )  )
        help( DEBUG, 0 );
    else
#endif /* ENABLE_DEBUG */
    if (  ( strcmp( argv[0], "info" ) == 0 ) ||
          ( strcmp( argv[0], "i" ) == 0 )  )
        help( INFO, 0 );
    else
    if (  ( strcmp( argv[0], "usage" ) == 0 ) ||
          ( strcmp( argv[0], "u" ) == 0 )  )
        help( USAGE, 0 );
    else
    if (  ( strcmp( argv[0], "general" ) == 0 ) ||
          ( strcmp( argv[0], "g" ) == 0 )  )
        help( GENERAL, 0 );
    else
    if (  ( strcmp( argv[0], "client" ) == 0 ) ||
          ( strcmp( argv[0], "c" ) == 0 )  )
        help( CLIENT, 0 );
    else
    if (  ( strcmp( argv[0], "server" ) == 0 ) ||
          ( strcmp( argv[0], "s" ) == 0 )  )
        help( SERVER, 0 );
    else
    if (  ( strcmp( argv[0], "metrics" ) == 0 ) ||
          ( strcmp( argv[0], "m" ) == 0 )  )
        help( METRICS, 0 );
    else
    if (  ( strcmp( argv[0], "full" ) == 0 ) ||
          ( strcmp( argv[0], "f" ) == 0 )  )
        help( FULL, 0 );
    else
        help( HELP, 0 );
    return HELP_EXIT;
} // cmdHelp

/*
 * Process the help sub-command
 */

static int
cmdInfo(
    int    argc,
    char * argv[]
       )
{
    int maxsendbuf, maxrecvbuf, ret;

    if (  argc != 0  )
        help( INFO, 1 );

    ret = getMaxSockBuf( &maxsendbuf, &maxrecvbuf );

    printf( "\n" );
    printf( "Version         : %s\n", VERSION );
    printf( "Platform        : %s\n",
#if defined(LINUX)
            "Linux"
#elif defined(SOLARIS)
            "Solaris"
#else
            "macOS"
#endif
          );
    printf( "Options         :%s%s%s%s%s%s",
#if defined(ALLOW_BUFFSIZE)
            " buffsize",
#else
            "",
#endif /* ALLOW_BUFFSIZE */
#if defined(ALLOW_NODELAY)
            " nodelay",
#else
            "",
#endif /* ALLOW_NODELAY */
#if defined(ALLOW_QUICKACK)
            " quickack",
#else
            "",
#endif /* ALLOW_QUICKACK */
#if defined(ALLOW_TCPECN)
            " tcpecn",
#else
            "",
#endif /* ALLOW_TCPECN */
#if defined(ENABLE_DEBUG)
            " debug",
#else
            "",
#endif /* ENABLE_DEBUG */
          "\n" );
#if defined(ALLOW_BUFFSIZE)
    if (  ret  )
    {
        printf( "Max send buffer : Unknown, limited to %'d bytes\n", DFLT_MAXSOCKBUF );
        printf( "Max recv buffer : Unknown, limited to %'d bytes\n", DFLT_MAXSOCKBUF );
    }
    else
    {
        printf( "Max send buffer : %'d bytes\n", maxsendbuf );
        printf( "Max recv buffer : %'d bytes\n", maxrecvbuf );
    }
#endif /* ALLOW_BUFFSIZE */
    printf( "\n" );

    return 0;
} // cmdInfo

int
main(
    int    argc,
    char * argv[]
    )
{
    int ret = 0;

    setlocale( LC_ALL, "" );

    if (  argc < 2  )
        help( USAGE, 1 );

    setbuf( stdout, NULL );

    if (  ( strcmp( argv[1], "help" ) == 0 ) ||
          ( strcmp( argv[1], "h" ) == 0 )  )
        ret = cmdHelp( argc-2, &argv[2] );
    else
    if (  ( strcmp( argv[1], "info" ) == 0 ) ||
          ( strcmp( argv[1], "i" ) == 0 )  )
        ret = cmdInfo( argc-2, &argv[2] );
    else
    if (  ( strcmp( argv[1], "server" ) == 0 ) ||
          ( strcmp( argv[1], "s" ) == 0 )  )
        ret = cmdServer( argc-2, &argv[2] );
    else
    if (  ( strcmp( argv[1], "client" ) == 0 ) ||
          ( strcmp( argv[1], "c" ) == 0 )  )
        ret = cmdClient( argc-2, &argv[2] );
    else
        help( USAGE, 1 );

    return ret;
} // main
