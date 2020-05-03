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

#if ! defined(_NWTEST_H)
#define _NWTEST_H

#include <pthread.h>
#include <sys/resource.h>

/******************************************************************************
 * Macros and constants.
 */

/*
 * Configuration things. These can be changed (with care).
 */
#define  PROGNAME          "NWTEST"
#define  VERSION           "1.7"

#define  ALLOW_NODELAY     1
#define  ALLOW_BUFFSIZE    1
#define  MAX_MSG_SIZE      1048576
#define  DFLT_CLT_MSG_SIZE 1024
#define  DFLT_SRV_MSG_SIZE MAX_MSG_SIZE
#define  MIN_SRV_CONN      2
#define  MAX_SRV_CONN      128
#define  DFLT_SRV_CONN     32
#define  MIN_CLT_CONN      1
#define  MAX_CLT_CONN      64
#define  DFLT_CLT_CONN     1
#define  MIN_DURATION      10
#define  MAX_DURATION      300
#define  DFLT_DURATION     30
#define  MIN_RAMP          0
#define  MAX_RAMP          30
#define  DFLT_RAMP         10
#define  MIN_BSZ           (8 * 1024)
#define  MAX_BSZ           (8 * 1024 * 1024)
#define  DFLT_MAXSOCKBUF   (8 * 1024 * 1024)

/*
 * Other stuff (do not change).
 */

#define  LOG_STDOUT        "-"
#define  LOG_STDERR        "--"
#define  HELP_EXIT         100
#define  INTR_EXIT         127
#define  KB_MULT           1024L
#define  MB_MULT           (KB_MULT * KB_MULT)
#define  NODELAY_OFF       0
#define  NODELAY_ON        1
#define  MAX_MSG_WAIT      10
#define  MIN_PORT          1024
#define  MAX_PORT          65535
#define  MIN_MSG_SIZE      (int)offsetof(mdata_t,data)
#define  SECRET            0x4e775465L
#define  MSG_ANY           0
#define  MSG_CONN          1
#define  MSG_CONN_ACK      2
#define  MSG_HSHAKE        3
#define  MSG_HSHAKE_ACK    4
#define  MSG_STOP          5
#define  MSG_STOP_ACK      6
#define  MSG_DISC          7
#define  MSG_DISC_ACK      8
#define  MSG_DATA          9
#define  MSG_DATA_ACK      10

#define  HTON8( x )        (x)
#define  NTOH8( x )        (x)
#define  HTON16( x )       htons(x)
#define  NTOH16( x )       ntohs(x)
#define  HTON32( x )       htonl(x)
#define  NTOH32( x )       ntohl(x)
#define  HTON64( x )       htonll(x)
#define  NTOH64( x )       ntohll(x)

/******************************************************************************
 * Types
 */

typedef enum { USAGE, HELP, GENERAL, SERVER, CLIENT, METRICS, FULL } help_t;
typedef enum { DEFUNCT, RUNNING, RAMP, MEASURE, END, STOP, FINISHED } tstate_t;
typedef enum { SENDER, RECEIVER } ttype_t;
typedef enum { ANY, SYNC, ASYNC } tmode_t;
typedef enum { TSERVER, TCLIENT } cs_t;

typedef char sint8;
typedef unsigned char uint8;
typedef short sint16;
typedef unsigned short uint16;
typedef int sint32;
typedef unsigned int uint32;
typedef long sint64;
typedef unsigned long uint64;

typedef struct s_msghdr msghdr_t;
typedef struct s_genmsg msg_t;
typedef struct s_connmsg mconn_t;
typedef struct s_connackmsg mconnack_t;
typedef struct s_hshakemsg mhshake_t;
typedef struct s_hshakeackmsg mhshakeack_t;
typedef struct s_stopmsg mstop_t;
typedef struct s_stopackmsg mstopack_t;
typedef struct s_discmsg mdisc_t;
typedef struct s_discackmsg mdiscack_t;
typedef struct s_datamsg mdata_t;
typedef struct s_dataackmsg mdataack_t;
typedef struct s_thread thread_t;
typedef struct s_conn conn_t;
typedef struct s_context context_t;

struct s_msghdr
{
    uint32      msglen;
    uint32      secret;
    uint32      ts;
    uint32      seqno;
    uint8       msgtype;
}; // s_msghdr

struct s_genmsg
{
    msghdr_t    hdr;
    uint8       data[];
}; // s_genmsg

struct s_connmsg
{
    msghdr_t    hdr;
    uint8       async;
    uint8       nodelay;
    uint8       filler;
    uint32      msgsz;
    uint32      sbsz;
    uint32      rbsz;
    uint64      srcats;
}; // s_connmsg

struct s_connackmsg
{
    msghdr_t    hdr;
    uint8       filler[3];
    uint64      srcats;
}; // s_connackmsg

struct s_hshakemsg
{
    msghdr_t    hdr;
}; // s_hshakemsg

struct s_hshakeackmsg
{
    msghdr_t    hdr;
}; // s_hshakeackmsg

struct s_stopmsg
{
    msghdr_t    hdr;
}; // s_stopmsg

struct s_stopackmsg
{
    msghdr_t    hdr;
}; // s_stopackmsg

struct s_discmsg
{
    msghdr_t    hdr;
}; // s_discmsg

struct s_discackmsg
{
    msghdr_t    hdr;
}; // s_discackmsg

struct s_datamsg
{
    msghdr_t    hdr;
    uint8       filler[3];
    uint32      datasz;
    uint8       data[];
}; // s_datamsg

struct s_dataackmsg
{
    msghdr_t    hdr;
    uint8       filler[3];
    uint32      datasz;
    uint8       data[];
}; // s_dataackmsg

struct s_thread
{
    thread_t        * next;
    thread_t        * prev;
    conn_t          * conn;
    int               tno;
    pthread_t         tid;
    long              retcode;
    ttype_t           type;
    volatile tstate_t state;
    long              startts;
    long              stopts;
    long              msent;
    long              mrcvd;
    long              bsent;
    long              brcvd;
    long              minrt;
    long              maxrt;
    long              totrt;
    msg_t           * sndbuff;
    msg_t           * rcvbuff;
}; // s_thread

struct s_conn
{
    context_t       * ctxt;
    struct sockaddr * peer;
    socklen_t         lpeer;
    int               v6peer;
    int               connid;
    int               msgsz;
    int               nodelay;
    volatile int      busy;
    volatile int      ready;
    long              startts;
    long              stopts;
    long              tpsent;
    long              tprcvd;
    long              tbsent;
    long              tbrcvd;
    volatile int      rwsock;
    char            * error;
    thread_t        * sender;
    thread_t        * receiver;
}; // s_conn

struct s_context
{
    FILE            * log;
    pthread_mutex_t   loglock;
    uint64            tbase;
    cs_t              cs;
    tmode_t           mode;
    char            * host;
    int               port;
    char            * src;
    int               msgsz;
    int               maxmsgsz;
    int               maxdatasz;
    int               ramp;
    int               dur;
    int               brief;
    int               verbose;
    int               v4only;
    int               v6only;
    int               nodelay;
    int               nconn;
    int               maxsockbuf;
    int               sbsz;
    int               rbsz;
    char            * error;
    int               debug;
    int               naddr;
    int               nv4addr;
    int               nv6addr;
    struct addrinfo * v4addr;
    struct addrinfo * v6addr;
    struct addrinfo * srcaddr;
    int             * lsocks;
    int               maxsocket;
    fd_set            lfds;
    thread_t        * runqhead;
    thread_t        * runqtail;
    conn_t          * conn[];
}; // s_context

/******************************************************************************
 * Global data
 */

extern struct timeval pstart, pend;
extern struct rusage rstart, rend;

/******************************************************************************
 * Functions
 */

void help( help_t topic );

void msgFree( thread_t * thread, msg_t ** msg);

void threadFree( conn_t * conn, thread_t ** thread );

void connFree( context_t * ctxt, conn_t ** conn );

void contextFree( context_t ** ctxt );

msg_t * msgAlloc( thread_t * thread, int mtype );

thread_t * threadAlloc( conn_t  * conn, ttype_t type, int tno );

conn_t * connAlloc( context_t * ctxt, int connid );

context_t * contextAlloc( cs_t cs, tmode_t mode, char * host, int port, 
                          char * src, int msgsz, int ramp, int dur, int verbose,
                          int brief, int nconn, int v4only, int v6only, int sbsz,
                          int rbsz, FILE * log, int debug );

struct addrinfo * copyAddrInfo( struct addrinfo * addr );

void usSleep( unsigned int us );

int waitforThread( thread_t * thread, tstate_t state, long touts );

char * tStateStr( tstate_t state );

char * msgTypeStr( int mtype );

int valueConvert( char * val, long * lval );

int getMaxSockBuf( void );

#if ! defined(MACOS)
void FD_COPY( fd_set * orig, fd_set * copy );
uint64 htonll( uint64 hval );
uint64 ntohll( uint64 nval );
#endif /* MACOS */

#if defined(SOLARIS) || defined(WINDOWS)
char * strsep( char **stringp, const char *delim );
#endif /* SOLARIS || WINDOWS */

int logLock( context_t * ctxt );

int logLockTry( context_t * ctxt );

int logUnlock( context_t * ctxt );

int sendMsg( context_t * ctxt, int sock, msg_t * msg, char ** errmsg );

int recvMsg( context_t * ctxt, int sock, msg_t * msg, int maxsz, char ** errmsg );

void dequeueThread( context_t * ctxt, thread_t ** thread );

void enqueueThread( context_t * ctxt, thread_t * thread );

int sigReceived( void );

void sigClear( void );

int stopReceived( void );

int handleSignals( void );

int isInteger( int ssigned, char * val );

uint64 getTS( uint64 tbase );

int printTS( FILE * f );

int logMsg( FILE * f, char * fmt, ... );

FILE * getStdOut( context_t * ctxt );

FILE * getStdErr( context_t * ctxt );

int printMsg( context_t * ctxt, int lock, char * fmt, ... );

int printErr( context_t * ctxt, int lock, char * fmt, ... );

uint64 maxUint64( uint64 val1, ... );

int validMsgType( int mtype );

int getMsgSize( context_t * ctxt, int mtype );

int getMaxDataSize( context_t * ctxt );

int getMaxMsgSize( context_t * ctxt );

int isIPv4Address( char * s );

int isIPv6Address( char * s );

int isIPAddress( char * s );

int hostToAddr( char * hostname, char * servname, int v4, int v6,
                int listen, struct addrinfo ** v4addr, struct addrinfo ** v6addr );

int cmdServer( int argc, char * argv[] );

int cmdClient( int argc, char * argv[] );

void printIPv4address( FILE * f, struct sockaddr * addr4, int full );

void printIPv6address( FILE * f, struct sockaddr * addr6, int full );

void printIPaddress( FILE * f, struct sockaddr * addr, socklen_t laddr, int full );

int getConnection( context_t * ctxt );

#endif /* _NWTEST_H */
