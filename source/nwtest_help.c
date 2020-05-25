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
#include <stddef.h>
#if !defined(WINDOWS)
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#else
#include "Ws2tcpip.h"
#endif

#include "nwtest.h"

static void
help_usage( void )
{
    printf(

"\nUsage:\n\n"

"    nwtest h[elp] { h[elp] | u[sage] | g[eneral] | c[lient] |\n"
"                    s[erver] | m[etrics] | f[ull] }\n\n"

"    nwtest s[erver] <port> [-4|-6] [-h[ost] <h>] [-m[sgsz] <m>]\n"
"                    [-c[onn] <c>] [-l[og] <logpath>]\n\n"

"    nwtest c[lient] <host> <port> [-s[rc] <srcaddr>] [-4|-6] [-a[sync]]\n"
"                    [-c[onn] <c>] [-d[ur] <d>] [-r[amp] <r>]\n"
"                    [-m[sgsz] <m>] [-l[og] <logpath>]\n"
#if defined(ALLOW_BUFFSIZE)
"                    [-sbsz <sbsz> | [[-srvsbsz <srvsbsz>] [-cltsbsz <cltsbsz>]]\n"
"                    [-rbsz <rbsz> | [[-srvrbsz <srvrbsz>] [-cltrbsz <cltrbsz>]]\n"
#endif /* ALLOW_BUFFSIZE */
#if defined(ALLOW_NODELAY) && defined(ALLOW_QUICKACK)
"                    [-n[odelay]] [-q[uickack]] [-b[rief]|-v[erbose]]\n\n"
#else
#if defined(ALLOW_NODELAY)
"                    [-n[odelay]] [-b[rief]|-v[erbose]]\n\n"
#else
#if defined(ALLOW_QUICKACK)
"                    [-q[uickack]] [-b[rief]|-v[erbose]]\n\n"
#else
"                    [-b[rief]|-v[erbose]]\n\n"
#endif /* ALLOW_QUICKACK */
#endif /* ALLOW_NODELAY */
#endif /* ALLOW_NODELAY && ALLOW_QUICKACK */

    );
} // help_usage

static void
help_help( void )
{
    printf(

"\n"
"nwtest h[elp] { u[sage] | g[eneral] | c[lient] | s[erver] | m[etrics] | f[ull] }\n\n"

"Display help on the specified topic.\n\n"

    );
} // help_help

static void
help_general( void )
{
    printf(

"\nThis program implements a network response time and throughput test.\n\n"

"The program can be run as either a client or a server. The client opens one\n"
"or more connections to a server and exchanges messages of a given size with\n"
"the server for a given period of time. At the end of the test period, various\n"
"performance metrics are displayed.\n\n"

"The test can run in two modes. In synchronous (request/response) mode, each\n"
"connection has a single thread in both the client and the server. Once the\n"
"connection is established the client sends a message to the server and waits\n"
"for a response. As soon as the server receives a message it sends it straight\n"
"back to the client. This sequence is repeated until the test ends.\n\n"

"In asynchronous (streaming) mode, each connection has two threads in both the\n"
"client and the server. Once the connection is established the client sends a\n"
"continuous stream of messages to the server and the server simultaneously\n"
"sends a continuous stream of messages to the client.\n\n"

"The size of the messages exchanged, the duration of the test measurement phase,\n"
"the amount of load ramp-up and ramp-down time and the number of connections\n"
"(and hence threads) are all configurable.\n\n"

"The defaults for the various configurable parameters have been carefully chosen\n"
"such that using the defaults will generally give a meaningful result. The main\n"
"parameters that you might vary in normal usage are the message size and the\n"
"number of connections.\n\n"

    );
} // help_general

static void
help_client( int brief )
{
    printf(

"\n"
"nwtest c[lient] <host> <port> [-s[rc] <srcaddr>] [-4|-6] [-a[sync]]\n"
"                [-c[onn] <c>] [-d[ur] <d>] [-r[amp] <r>]\n"
"                [-m[sgsz] <m>] [-l[og] <logpath>]\n"
#if defined(ALLOW_BUFFSIZE)
"                [-sbsz <sbsz> | [[-srvsbsz <srvsbsz>] [-cltsbsz <cltsbsz>]]\n"
"                [-rbsz <rbsz> | [[-srvrbsz <srvrbsz>] [-cltrbsz <cltrbsz>]]\n"
#endif /* ALLOW_BUFFSIZE */
#if defined(ALLOW_NODELAY) && defined(ALLOW_QUICKACK)
"                [-n[odelay]] [-q[uickack]] [-b[rief]|-v[erbose]]\n\n"
#else
#if defined(ALLOW_NODELAY) 
"                [-n[odelay]] [-b[rief]|-v[erbose]]\n\n"
#else
#if defined(ALLOW_QUICKACK) 
"                [-q[uickack]] [-b[rief]|-v[erbose]]\n\n"
#else
"                [-b[rief]|-v[erbose]]\n\n"
#endif /* ALLOW_QUICKACK */
#endif /* ALLOW_NODELAY */
#endif /* ALLOW_NODELAY && ALLOW_QUICKACK */
    );

    if (   ! brief  )
    {
    printf(

"Run as a client connecting to a server at host <host> and port <port>. The\n"
"host can be specified as either a host name or an IP address (IPv4 or IPv6).\n"
"If a hostname is specified then you can use the '-4' or '-6' options to limit\n"
"communication to IPv4 or IPv6.\n\n"

"Normally the OS will determine the local source IP address (interface) to use\n"
"for the outgoing connection, but this can be overridden by specifying an\n"
"explicit local address using the '-src' option. This value must be an IP\n"
"address, not a hostname, and it must correspond to the address of an\n"
"interface on the local system. If <host> has been specified using an IP\n"
"address then the address type (IPv4 or IPv6) for <srcaddr> must be the same\n"
"as that of <host>. Furthermore, if the allowed connection type has been\n"
"restricted by way of '-4' or '-6' then the value of <srcaddr> must be of\n"
"the selected type.\n\n"

"By default the test is performed in request/response (synchronous) mode but\n"
"if '-async' is specified the test is performed in streaming mode.\n\n"

"The measurement part of the test will run for <d> seconds with a ramp-up/down\n"
"of <r> seconds. %d <= <d> <= %d with a default of %d and %d <= <r> <= %d\n"
"with a default of %d.\n\n"

"The message size used for the test is specified by <m> where %'d <= <m> <=\n"
"%'d with a default of %'d. This size represents the size of the user\n"
"data; it excludes network protocol overheads (ethernet, IPv4/6 etc.). The\n"
"size may be specified using a suffix of 'k' to repesent KB (%'d bytes) or\n"
"'m' to represent MB (%'d bytes).\n\n"

"The number of concurrent connections used is specified by <c> where %d <= <c>\n"
"<= %d with a default of %d.\n\n"

"Normally all output goes to stdout/stderr, but if '-log' is specified then\n"
"after initial argument parsing any subsequent messages will be written only\n"
"to <logpath> with microsecond resolution timestamps. A <logpath> of '-'\n"
"equates to 'stdout' and '--' equates to 'stderr'.\n\n"

#if defined(ALLOW_BUFFSIZE)
"Normally the OS will allocate the sizes for the socket send and receive\n"
"buffers, and these sizes will be reported in the connection messages. If\n"
"you want to use specific values for the socket send and receive buffer\n"
"sizes then you can do so using '-sbsz' (sets size for send buffer on both\n"
"client and server), '-rbsz' (sets size for the receive buffer on both client\n"
"and server), '-srvsbsz' (sets size for send buffer on server), '-srvrbsz'\n"
"(sets size for receive buffer on server), '-cltsbsz' (sets size for send\n"
"buffer on client) and '-cltrbsz' (sets size for receive buffer on client).\n"
"These values are specified in bytes and each must be between %'d and\n"
"%'d. Also, the total of the sizes must be <= %'d. These sizes may\n"
"be specified using a suffix of 'k' to repesent KB (%'d bytes) or 'm' to\n"
"represent MB (%'d bytes).\n\n"
#endif /* ALLOW_BUFFSIZE */

#if defined(ALLOW_NODELAY)
"If '-nodelay' is specified then the TCP_NODELAY option is enabled on all\n"
"sockets used for data transfer in both the client and the server.\n\n"
#endif /*  ALLOW_NODELAY */

#if defined(ALLOW_QUICKACK)
#if defined(LINUX)
"If '-quickack' is specified then the TCP_QUICKACK option is enabled on\n"
#else /* macOS */
"If '-quickack' is specified then the TCP_SENDMOREACKS option is enabled on\n"
#endif /* macOS */
"all sockets used for data transfer in both the client and the server.\n\n"
#endif /*  ALLOW_QUICKACK */

"Normally only aggregate performance metrics are displayed, but if '-verbose'\n"
"is specified then per connection metrics are also displayed. If '-brief' is\n"
"specified then just key metrics are displayed on a single line.\n\n"

, MIN_DURATION, MAX_DURATION, DFLT_DURATION,
  MIN_RAMP, MAX_RAMP, DFLT_RAMP,
  MIN_MSG_SIZE, MAX_MSG_SIZE, DFLT_CLT_MSG_SIZE,
  1024, 1048576,
  MIN_CLT_CONN, MAX_CLT_CONN, DFLT_CLT_CONN
#if defined(ALLOW_BUFFSIZE)
  ,MIN_BSZ, MAX_BSZ, getMaxSockBuf(), 1024, 1048576
#endif /* ALLOW_BUFFSIZE */
    );

    }

} // help_client

static void
help_server( int brief )
{
    printf(

"\n"
"nwtest s[erver] <port> [-4|-6] [-h[ost] <h>] [-m[sgsz] <m>]\n"
"                       [-c[onn] <c>] [-l[og] <logpath>]\n\n"

    );

    if (  ! brief  )
    {
    printf(

"Run as a server on local port <port>. If a specific host is specified (<h>)\n"
"then bind to the address(es) for that host, otherwise bind to INADDR[6]_ANY.\n"
"The host can be specified as a hostname or an IP address (IPv4 or IPv6);\n"
"the address specified must be an address for an interface on the local system.\n"
"If a hostname is specified then you can use the '-4' or '-6' options to limit\n"
"communication to IPv4 or IPv6.\n\n"

"The maximum message size, in bytes, that the server will accept is specified\n"
"by <m> where %'d <= <m> <= %'d. Connections requesting a message size\n"
"larger than this will be rejected. The default is %'d. This size\n"
"represents the size of the user data; it excludes network protocol overheads\n"
"(ethernet, IPv4/6 etc.). The size may be specified using a suffix of 'k' to\n"
"repesent KB (%'d bytes) or 'm' to represent MB (%'d bytes).\n\n"

"The maximum number of concurrent connections that the server will allow is set\n"
"using <c> where %d <= <c> <= %d. Connections that exceed this number will\n"
"be rejected. The default is %d.\n\n"

"Normally all output goes to stdout/stderr, but if '-log' is specified then\n"
"after initial argument parsing any subsequent messages will be written only\n"
"to <logpath> with microsecond resolution timestamps. A <logpath> of '-'\n"
"equates to 'stdout' and '--' equates to 'stderr'.\n\n"

, MIN_MSG_SIZE, MAX_MSG_SIZE, DFLT_SRV_MSG_SIZE, 1024, 1048576,
  MIN_SRV_CONN, MAX_SRV_CONN, DFLT_SRV_CONN
    );

    }
} // help_server

static void
help_metrics( void )
{
    printf(

"\n"

"For each connection successfully established, the client and server will\n"
"report the TCP MSS (maxseg) value and the size of the socket send and\n"
"receive buffers (sndbsz anb rcvbsz).\n\n"

"The metrics measured and reported by this program for each test mode are\n"
"as follows; all references to 'data' and 'throughput' refer to application\n"
"data excluding network overheads.\n\n"

"All modes\n"
"---------\n\n"

"Elapsed time       - The wall clock elapsed time for the measurement part\n"
"                     of the test (excludes ramp up/down time).\n\n"

"User CPU time      - The amount of user CPU time consumed during the\n"
"                     elapsed time.\n\n"

"System CPU time    - The amount of system CPU time consumed during the\n"
"                     elapsed time.\n\n"

"Total CPU time     - User time plus system time.\n\n"

"Process CPU usage  - The average CPU usage for the nwtest process during\n"
"                     the elapsed time, expressed as a percentage of one\n"
"                     CPU core.\n\n"

"System CPU usage   - The average CPU usage for the nwtest process during\n"
"                     the elapsed time, expressed as a percentage of total\n"
"                     available system CPU resources.\n\n"

"Sync (request/response) mode\n"
"----------------------------\n\n"

"Total messages     - The total number of data messages sent during the\n"
"                     measurement period. The number of received messages\n"
"                     is the same.\n\n"

"Total data         - The total number of bytes sent during the measurement\n"
"                     period. The number of received bytes is the same.\n\n"

"Avg measure time   - The average measurement time across all threads (µs).\n\n"

"Start variance     - The maximum difference between the start times of all\n"
"                     the threads (µs). Only displayed if connections > 1.\n\n"

"Run variance       - The maximum difference between the measurement times of\n"
"                     all the threads (µs). Only displayed if connections > 1.\n\n"

"Throughput         - The send throughput, aggregated across all connections,\n"
"                     during the measurement period (bytes/second).\n\n"

"Minimum R/T        - The lowest round trip time across all connections during\n"
"                     the measurement period (µs).\n\n"

"Average R/T        - The average round trip time across all connections during\n"
"                     the measurement period (µs).\n\n"

"Maximum R/T        - The highest round trip time across all connections during\n"
"                     the measurement period (µs).\n\n"

"In brief mode the output consists of a single line as follows:\n\n"

"info: results S,<nconn>,<throughput>,<minrt>,<avgrt>,<maxrt>,<proccpu>,<syscpu>\n\n"

"Async (streaming) mode\n"
"----------------------\n\n"

"Total msg sent     - The total number of messages sent during the measurement\n"
"                     period.\n\n"

"Total msg rcvd     - The total number of messages received during the\n"
"                     measurement period.\n\n"

"Total data sent    - The total number of bytes sent during the measurement\n"
"                     period.\n\n"

"Total data rcvd    - The total number of bytes received during the measurement\n"
"                     period.\n\n"

"Avg measure time   - The average measurement time across all threads (µs).\n\n"

"Start variance     - The maximum difference between the start times of all\n"
"                     the threads (µs).\n\n"

"Run variance       - The maximum difference between the measurement times of\n"
"                     all the threads (µs).\n\n"

"Send throughput    - The send throughput, aggregated across all connections,\n"
"                     during the measurement period (bytes/second).\n\n"

"Recv throughput    - The receive throughput, aggregated across all connections,\n"
"                     during the measurement period (bytes/second).\n\n"

"Average throughput - The average of the send and receive throughputs.\n\n"

"In brief mode the output consists of a single line as follows:\n\n"

"info: results A,<nconn>,<sendthroughput>,<recvthroughput>,<proccpu>,<syscpu>\n\n"

"Network overheads\n"
"-----------------\n\n"

"The message size that you specify defines the size of the 'application data'\n"
"in each message sent or received. The actual amount of data for each message\n"
"will be larger than this due to various network and protocol related overheads.\n\n"

"For IPv4/TCP, there is at least 28 bytes of overhead per message and in unusual\n"
"cases this may be as much as 36 bytes. In addition the TCPv4 header is another\n"
"24 bytes. In most cases, for this program, the IPv4 packet size will be <message\n"
"size> + 52 bytes.\n\n"

"For IPv6/TCP, there is at least 72 bytes of overhead per message and in unusual\n"
"cases this may be more due to additional header fields (each is 8 bytes). In\n"
"most cases, for this program, the IPv6 packet size will be <message size> + 72\n"
"bytes.\n\n"

"For Ethernet the standard Maximum Transmission Unit (MTU) is 1500 bytes. Each\n"
"IP packet will be sent as a sequence of one or more Ethernet frames. Each frame\n"
"has some overhead; normally this is 38 bytes but if 802.1q VLANs are being used\n"
"it will be 42 bytes.\n\n"

"For WiFi the standard Maximum Transmission Unit (MTU) is 1500 bytes. Each IP\n"
"packet will be sent as a sequence of one or more WiFi frames. Each frame has\n"
"some overhead; normally this is 36 bytes but it may be as much as 44 bytes.\n\n"

"To give this some context, with the default test message size of 1024 bytes the\n"
"IPv4 packet size will be 1076 bytes and the IPv6 packet size will be 1096 bytes.\n"
"Both will therefore fit into a single Ethernet/WiFi frame. The associated\n"
"Ethernet frame will be 1114 bytes for IPv4 and 1134 bytes for IPv6.\n\n"

"With a 1 Gbit/s Ethernet network, the maximum theoretical throughput will be\n"
"112,208 frames/s for IPv4 and 110,229 frames/s for IPv6. This translates to\n"
"a theoretical maximum application data rate of 109.5 Mbyte/s for IPv4 and\n"
"107.6 Mbyte/s for IPv6.\n\n"

    );
} // help_metrics

static void
help_full( void )
{
    help_general();
    help_usage();
    help_help();
    help_server( 0 );
    help_client( 0 );
    help_metrics();
} // help_full

void
help( help_t topic, int brief )
{
    printf( "\nVersion %s\n", VERSION );

    switch (  topic  )
    {
        case USAGE:
            help_usage();
            break;
        case HELP:
            help_help();
            break;
        case GENERAL:
            help_general();
            break;
        case SERVER:
            help_server( brief );
            break;
        case CLIENT:
            help_client( brief );
            break;
        case METRICS:
            help_metrics();
            break;
        case FULL:
            help_full();
            break;
        default:
            help_usage();
            break;
    }

    exit( 100 );
} // help

