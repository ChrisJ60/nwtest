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
#include <string.h>
#include <stddef.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/select.h>
#if !defined(WINDOWS)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <netdb.h>
#else
#include "Ws2tcpip.h"
#endif

#include <nwtest.h>

/******************************************************************************
 * Data
 */

static volatile int signalReceived = 0;

/******************************************************************************
 * Private functions
 */

/*
 * Signal handler
 */

static void
signalHandler(
    int signo
             )
{
    signalReceived = signo;
} // signalHandler

/******************************************************************************
 * Public functions
 */

/*
 * Convert a string to a value; allows K/k and M/m suffixes.
 */

int
valueConvert(
             char * val,
             long * lval
            )
{
    int l;
    char * p;
    long multiplier = 1, lv;

    if (  ( val == NULL ) || ( lval == NULL )  )
        return 1;

    l = strlen( val );
    if ( l < 1  )
        return 1;

    p = val + l - 1;
    switch (  *p  )
    {
        case 'K':
        case 'k':
            multiplier = KB_MULT;
            *p = '\0';
            l -= 1;
            break;

        case 'M':
        case 'm':
            multiplier = MB_MULT;
            *p = '\0';
            l -= 1;
            break;
    }
    if ( l < 1  )
        return 1;

    lv = strtol( val, &p, 10 );
    if (  *p  )
        return 1;

    *lval = (lv * multiplier);
    return 0;
} // valueConvert

/*
 * Determine the maximum allowed combined size for socket buffers.
 */

int
getMaxSockBuf(
    void
             )
{
#if defined( MACOS )
    int maxsockbuf = 0;
    size_t lmaxsockbuf = sizeof( maxsockbuf );

    errno = 0;
    if (  sysctlbyname( "kern.ipc.maxsockbuf", &maxsockbuf, &lmaxsockbuf, NULL, (size_t)0 ) ||
          ( lmaxsockbuf != sizeof( maxsockbuf ) )  )
        maxsockbuf = DFLT_MAXSOCKBUF;

    return maxsockbuf;
#else /* ! MACOS */
    return DFLT_MAXSOCKBUF;
#endif /* ! MACOS */
} // getMaxSockBuf

/*
 * Sleep for a specific number of micro seconds
 */

void
usSleep(
    unsigned int us
       )
{
    struct timespec ts = { us / 1000000, (us % 1000000) * 1000 };

    nanosleep( &ts, NULL );
} // usSleep

/*
 * Wait for a thread to be in a specified state.
 */

int
waitforThread(
    thread_t * thread,
    tstate_t   state,
    long       touts
             )
{
    time_t now = 0, end = 1;

    if (  (thread == NULL) || (touts < 0)  )
        return -1;

     if (  touts  )
     {
         now = time( NULL );
         end = now + touts;
     }
     while (  (thread->state != state) && (thread->state != DEFUNCT) && (now <= end)  )
     {
         usSleep( 100 );
         if (  touts  )
             now = time( NULL );
     }

     return ( ( thread->state != state ) && ( thread->state != DEFUNCT) );
} // waitforThread

/*
 * Lock the context's log mutex.
 */

int
logLock(
    context_t * ctxt
       )
{
    if (  ctxt == NULL  )
        return -1;

    return pthread_mutex_lock( &(ctxt->loglock)  );
} // logLock

/*
 * Lock the context's log mutex if possible.
 */

int
logLockTry(
    context_t * ctxt
          )
{
    if (  ctxt == NULL  )
        return -1;

    return pthread_mutex_trylock( &(ctxt->loglock)  );
} // logLock

/*
 * Unlock the context's log mutex.
 */

int
logUnlock(
    context_t * ctxt
         )
{
    int ret;

    if (  ctxt == NULL  )
        return -1;

    ret = pthread_mutex_unlock( &(ctxt->loglock)  );

    if (  (ret == 0) || (ret == EPERM)  )
        return 0;
    else
        return ret;
} // logUnlock

/*
 * Remove a thread from the context's run queue
 */

void
dequeueThread(
    context_t * ctxt,
    thread_t ** thread
             )
{
    thread_t * tmp = NULL;

    if (  (ctxt != NULL) && (thread != NULL) && (*thread != NULL) &&
          (ctxt->runqhead != NULL) && (ctxt->runqtail != NULL)  )
    {
            if (  (*thread == ctxt->runqhead) &&
                  (*thread == ctxt->runqtail)  )
            {
                (*thread)->next = (*thread)->prev = NULL;
                *thread = ctxt->runqhead = ctxt->runqtail = NULL;
            }
            else
            if (  *thread == ctxt->runqhead  )
            {
                *thread = ctxt->runqhead->next;
                ctxt->runqhead->next = ctxt->runqhead->prev = NULL;
                ctxt->runqhead = *thread;
            }
            else
            if (  *thread == ctxt->runqtail  )
            {
                ctxt->runqtail = ctxt->runqtail->prev;
                ctxt->runqtail->next = NULL;
                (*thread)->next = (*thread)->prev = NULL;
                *thread = NULL;
            }
            else
            {
                tmp = *thread;
                tmp->prev->next = tmp->next;
                tmp->next->prev = tmp->prev;
                (*thread) = tmp->next;
                tmp->next = tmp->prev = NULL;
            }
    }
} // dequeueThread

/*
 * Add a thread to the context's run queue
 */

void
enqueueThread(
    context_t * ctxt,
    thread_t  * thread
             )
{
    if (  (ctxt != NULL) && (thread != NULL)  )
    {
        if (  ctxt->runqhead == NULL  )
        {
            thread->next = thread->prev = NULL;
            ctxt->runqhead = ctxt->runqtail = thread;
        }
        else
        {
            thread->prev = ctxt->runqtail;
            thread->next = NULL;
            ctxt->runqtail->next = thread;
            ctxt->runqtail = thread;
        }
    }
} // enqueueThread

/*
 * Returns a string corresponding to a thread state.
 */

char *
tStateStr(
    tstate_t state
         )
{
    char * ret = NULL;

    switch (  state  )
    {
        case DEFUNCT:
            ret = "DEFUNCT";
            break;
        case RUNNING:
            ret = "RUNNING";
            break;
        case RAMP:
            ret = "RAMP";
            break;
        case MEASURE:
            ret = "MEASURE";
            break;
        case END:
            ret = "END";
            break;
        case STOP:
            ret = "STOP";
            break;
        case FINISHED:
            ret = "FINISHED";
            break;
        default:
            ret = "<INVALID>";
            break;
    }

    return ret;
} // tStateStr

/*
 * Returns a string corresponding to amessage tyupe.
 */

char *
msgTypeStr(
    int mtype
          )
{
    char * ret = NULL;

    switch (  mtype  )
    {
        case MSG_CONN:
            ret = "MSG_CONN";
            break;
        case MSG_CONN_ACK:
            ret = "MSG_CONN_ACK";
            break;
        case MSG_HSHAKE:
            ret = "MSG_HSHAKE";
            break;
        case MSG_HSHAKE_ACK:
            ret = "MSG_HSHAKE_ACK";
            break;
        case MSG_STOP:
            ret = "MSG_STOP";
            break;
        case MSG_STOP_ACK:
            ret = "MSG_STOP_ACK";
            break;
        case MSG_DISC:
            ret = "MSG_DISC";
            break;
        case MSG_DISC_ACK:
            ret = "MSG_DISC_ACK";
            break;
        case MSG_DATA:
            ret = "MSG_DATA";
            break;
        case MSG_DATA_ACK:
            ret = "MSG_DATA_ACK";
            break;
        default:
            ret = "<INVALID>";
            break;
    }

    return ret;
} // msgTypeStr

/*
 * Check if a message type is valid.
 */

int
validMsgType(
    int mtype
            )
{
    switch (  mtype  )
    {
        case MSG_CONN:
        case MSG_CONN_ACK:
        case MSG_HSHAKE:
        case MSG_HSHAKE_ACK:
        case MSG_STOP:
        case MSG_STOP_ACK:
        case MSG_DISC:
        case MSG_DISC_ACK:
        case MSG_DATA:
        case MSG_DATA_ACK:
            return 1;
            break;
        default:
            return 0;
            break;
    }
} // validMsgType

/*
 * Return the amount of memory needed for a specific message type.
 */

int
getMsgSize(
    context_t * ctxt,
    int         mtype
    )
{
    if (  ctxt == NULL  )
        return 0;

    switch ( mtype )
    {
        case MSG_ANY:
            return ctxt->maxmsgsz;
            break;
        case MSG_CONN:
            return sizeof( mconn_t );
            break;
        case MSG_CONN_ACK:
            return sizeof( mconnack_t );
            break;
        case MSG_HSHAKE:
            return sizeof( mhshake_t );
            break;
        case MSG_HSHAKE_ACK:
            return sizeof( mhshakeack_t );
            break;
        case MSG_STOP:
            return sizeof( mstop_t );
            break;
        case MSG_STOP_ACK:
            return sizeof( mstopack_t );
            break;
        case MSG_DISC:
            return sizeof( mdisc_t );
            break;
        case MSG_DISC_ACK:
            return sizeof( mdiscack_t );
            break;
        case MSG_DATA:
            return ctxt->msgsz;
            break;
        case MSG_DATA_ACK:
            return ctxt->msgsz;
            break;
        default:
            return 0;
            break;
    }
} // getMsgSize

/*
 * Clear the 'signal received' flag
 */

void
sigClear(
    void
        )
{
    signalReceived = 0;
} // sigClear

/*
 * Return the most recently recived signal (if any)
 */

int 
sigReceived(
    void
           )
{
    return signalReceived;
} // sigReceived

/*
 * Has a 'stop' interrupt been received?
 */

int
stopReceived(
    void
            )
{
    int ret;

    switch (  sigReceived()  )
    {
        case SIGHUP:
        case SIGTERM:
        case SIGINT:
            ret = 1;
            break;
        default:
            ret = 0;
            break;
    }

    return ret;
} // stopReceived

/*
 * Setup signal handling
 */

int
handleSignals(
    void
             )
{
    struct sigaction sa;

    memset( (void *)&sa, 0, sizeof(struct sigaction) );
    sa.sa_handler = signalHandler;

    if (  sigaction( SIGINT, &sa, NULL )  )
        return 1;
    if (  sigaction( SIGHUP, &sa, NULL )  )
        return 1;
    if (  sigaction( SIGTERM, &sa, NULL )  )
        return 1;
    if (  sigaction( SIGUSR1, &sa, NULL )  )
        return 1;
    if (  sigaction( SIGUSR2, &sa, NULL )  )
        return 1;
    sa.sa_handler = SIG_IGN;
    if (  sigaction( SIGPIPE, &sa, NULL )  )
        return 1;

    return 0;
} // handleSignals

/*
 * Find and allocate a free connection in the connection array.
 */

int
getConnection(
    context_t * ctxt
             )
{
    int connid;

    if (  ctxt == NULL  )
        return -1;

    for ( connid = 0; connid < ctxt->nconn; connid++ )
        if (  ! ctxt->conn[connid]->busy  )
        {
            ctxt->conn[connid]->busy = 1;
            return connid;
        }

    return -1;
} // getConnection

#if ! defined(MACOS)
/*
 * Equivalent of BSF FD_COPY function.
 */

void
FD_COPY(
    fd_set * orig,
    fd_set * copy 
       )
{
    memcpy( (void *)copy, (void *)orig, sizeof( fd_set ) );
} // FD_COPY

/*
 * Equivalent of htonl for 64-bit values.
 */

uint64
htonll(
    uint64 hval
      )
{
    register int i = 0;
    uint64 nval = 0;
    uint8 * r = ( uint8 * )&hval;
    uint8 * w = ( ( uint8 * )&nval ) + sizeof( uint64 ) - 1;
    for ( i = 0; i < sizeof( uint32 ); i++ )
        *w-- = *r++;
    
    return nval;
} // htonll

/*
 * Equivalent of ntohl for 64-bit values.
 */

uint64
ntohll(
    uint64 nval
      )
{
    register int i = 0;
    uint64 hval = 0;
    uint8 * r = ( uint8 * )&nval;
    uint8 * w = ( ( uint8 * )&hval ) + sizeof( uint64 ) - 1;
    for ( i = 0; i < sizeof( uint32 ); i++) 
        *w-- = *r++;
    
    return hval;
} // ntohll
#endif /* MACOS */

/*
 * Return the current time as a microsecod offset from another timestamp.
 */

uint64
getTS(
    uint64 tbase
     )
{
    struct timeval tv;

    if (  gettimeofday( &tv, NULL )  )
        return 0;

    return ( tv.tv_sec * 1000000 ) + tv.tv_usec - tbase;
} // getTS

/*
 * Print a timestamp, in the format YYYY-MM-DD HH-MM-SS, to a file.
 */

int
printTS(
    FILE * f
       )
{
    struct tm now;
    struct timeval tv;
    int ret = 0;

    if (  f != NULL  )
    {
        gettimeofday( &tv, NULL );
        if (  localtime_r( &(tv.tv_sec), &now ) != NULL  )
            ret = fprintf( f, "%4.4d-%2.2d-%2.2d %2.2d-%2.2d-%2.2d.%6.6d",
                           1900+now.tm_year, 1+now.tm_mon, now.tm_mday,
                           now.tm_hour, now.tm_min, now.tm_sec, tv.tv_usec );
    }

    return ret;
}

/*
 * Log a message, preceeded by a timestamp, to a file.
 */

int
logMsg(
    FILE * f,
    char * fmt,
    ...
      )
{
    int ret = 0;
    va_list ap;

    if (  ( f != NULL ) && ( fmt != NULL )  )
    {
        va_start( ap, fmt );
        ret += printTS( f );
        ret += fprintf( f, " " );
        ret += vfprintf( f, fmt, ap );
        va_end( ap );
    }

    return ret;
} // logMsg

/*
 * Return the file to use for stdout.
 */

FILE *
getStdOut(
    context_t * ctxt
         )
{
    if (  (ctxt == NULL) || (ctxt->log == NULL)  )
        return stdout;
    else
        return ctxt->log;
} // getStdOut

/*
 * Return the file to use for stderr.
 */

FILE *
getStdErr(
    context_t * ctxt
         )
{
    if (  (ctxt == NULL) || (ctxt->log == NULL)  )
        return stderr;
    else
        return ctxt->log;
} // getStdErr

/*
 * Print a message to either stdout or the log file.
 */

int 
printMsg(
    context_t * ctxt,
    int         lock,
    char      * fmt,
    ...
        )
{
    int ret = 0;
    va_list ap;

    if (  ( ctxt != NULL ) && ( fmt != NULL )  )
    {
        if (  lock  )
            logLock( ctxt );
        va_start( ap, fmt );
        if (  ctxt->log == NULL  )
            ret += vfprintf( stdout, fmt, ap );
        else
        {
            ret += printTS( ctxt->log );
            ret += fprintf( ctxt->log, " : " );
            ret += vfprintf( ctxt->log, fmt, ap );
        }
        va_end( ap );
        if (  lock  )
            logUnlock( ctxt );
    }

    return ret;
} // printMsg

/*
 * Print a message to either stderr or the log file.
 */

int 
printErr(
    context_t * ctxt,
    int         lock,
    char      * fmt,
    ...
         )
{
    int ret = 0;
    va_list ap;

    if (  ( ctxt != NULL ) && ( fmt != NULL )  )
    {
        if (  lock  )
            logLock( ctxt );
        va_start( ap, fmt );
        if (  ctxt->log == NULL  )
            ret += vfprintf( stderr, fmt, ap );
        else
        {
            ret += printTS( ctxt->log );
            ret += fprintf( ctxt->log, " : " );
            ret += vfprintf( ctxt->log, fmt, ap );
        }
        va_end( ap );
        if (  lock  )
            logUnlock( ctxt );
    }

    return ret;
} // printErr

/*
 * Return the maximum of a list of uint64 values terminated by a 0 value.
 */

uint64
maxUint64(
    uint64 val1,
    ...
         )
{
    va_list ap;
    uint64 i, max = 0;

    va_start( ap, val1 );
    for (  i = val1; i > 0; i = va_arg( ap, uint64 )  )
    {
        if (  i > max  )
            max = i;
    }    
    va_end( ap );

    return max;
} // maxUint64

/*
 * Check if a string is a valid integer
 */
int
isInteger(
    int ssigned,
    char * val
          )
{
    char * endptr = NULL;
    char * pval = val;
    long lval;

    while (  isspace( *pval )  )
        pval += 1;

    if (  ! ssigned  )
    {
        if (  (*pval == '\0') || (*pval == '+') || (*pval == '-')  )
            return 0;
    }
    else
    {
        if (  (*pval == '+') || (*pval == '-')  )
        {
            if (  *(pval+1) == '\0'  )
                return 0;
         }
         else
         if (  *pval == '\0'  )
             return 0;
    }

    errno = 0;
    lval = strtol( val, &endptr, 10 );
    if (  errno || ( (endptr != NULL) && (*endptr != '\0') )  )
        return 0;

    return 1;
} // isInteger

/*
 * Get the maximum data size for a data / data ack message based on the configuration.
 */

int
getMaxDataSize(
    context_t * ctxt
              )
{
    if (  ctxt == NULL  )
        return 0;

    return ctxt->msgsz - offsetof( mdata_t, data );
} // getMaxDataSize

/*
 * Get the maximum possible message size based on the configuration.
 */

int
getMaxMsgSize(
    context_t * ctxt
             )
{
    uint64 maxsz;

    if (  ctxt == NULL  )
        return 0;

    maxsz = maxUint64( 
                (uint64)getMsgSize( ctxt, MSG_CONN ),
                (uint64)getMsgSize( ctxt, MSG_CONN_ACK ),
                (uint64)getMsgSize( ctxt, MSG_HSHAKE ),
                (uint64)getMsgSize( ctxt, MSG_HSHAKE_ACK ),
                (uint64)getMsgSize( ctxt, MSG_STOP ),
                (uint64)getMsgSize( ctxt, MSG_STOP_ACK ),
                (uint64)getMsgSize( ctxt, MSG_DISC ),
                (uint64)getMsgSize( ctxt, MSG_DISC_ACK ),
                (uint64)ctxt->msgsz,
                0
                     );

    return (int)maxsz;
} // getMaxMsgSize

/*
 * Free a message.
 */

void
msgFree(
    thread_t *  thread,
    msg_t    ** msg
       )
{
    if (  msg == NULL  )
    {
        if (  (thread != NULL) &&
              (thread->conn != NULL) &&
              (thread->conn->ctxt != NULL)  )
            thread->conn->ctxt->error = "internal: invalid message pointer";
        return;
    }

    if (  *msg == NULL  )
        return;

    free( (void *)(*msg) );
    *msg = NULL;
} // msgFree

/*
 * Free a thread
 */

void
threadFree(
    conn_t    * conn,
    thread_t ** thread
          )
{
    if (  thread == NULL  )
    {
        if (  (conn != NULL) &&
              (conn->ctxt != NULL)  )
            conn->ctxt->error = "internal: invalid thread pointer";
        return;
    }

    if (  *thread == NULL  )
        return;

    if (  (*thread)->sndbuff != NULL  )
        msgFree( *thread, &((*thread)->sndbuff) );
    if (  (*thread)->rcvbuff != NULL  )
        msgFree( *thread, &((*thread)->rcvbuff) );
    (*thread)->conn = NULL;

    free( (void *)(*thread) );
    *thread = NULL;
} // threadFree

/*
 * Free a connection.
 */

void
connFree(
    context_t * ctxt,
    conn_t   ** conn
        )
{
    if (  conn == NULL  )
    {
        if (  ctxt != NULL  )
            ctxt->error = "internal: invalid connection pointer";
        return;
    }

    if (  *conn == NULL  )
        return;

    if (  (*conn)->sender != NULL  )
        threadFree( *conn, &((*conn)->sender) );
    if (  (*conn)->receiver != NULL  )
        threadFree( *conn, &((*conn)->receiver) );
    if (  (*conn)->peer != NULL  )
        free(  (void *)((*conn)->peer)  );
    (*conn)->ctxt = NULL;

    free( (void *)(*conn) );
    *conn = NULL;
} // connFree

/*
 * Free a context and all of its children.
 */

void
contextFree(
    context_t ** ctxt
           )
{
    int i;

    if (  (ctxt == NULL) || (*ctxt == NULL)  )
        return;

    for (i = 0; i < (*ctxt)->nconn; i++)
        connFree( *ctxt, &((*ctxt)->conn[i]) );

    if (  (*ctxt)->v4addr != NULL  )
        freeaddrinfo( (*ctxt)->v4addr );
    if (  (*ctxt)->v6addr != NULL  )
        freeaddrinfo( (*ctxt)->v6addr );

    if (  (*ctxt)->log != NULL  )
        fclose( (*ctxt)->log );

    free( (void *)(*ctxt) );
    *ctxt = NULL;
} // contextFree

/*
 * Allocate a message
 */

msg_t *
msgAlloc(
    thread_t  * thread,
    int         mtype
        )
{
    msg_t * m = NULL;
    int sz;

    if (  (thread == NULL) ||
          (thread->conn == NULL) ||
          (thread->conn->ctxt == NULL) )
        return m;

    sz = getMsgSize( thread->conn->ctxt, mtype );
    if (  sz <= 0  )
    {
        thread->conn->ctxt->error = "internal: invalid message type";
        return m;
    }

    m = (msg_t *)calloc( 1, sz );
    if (  m == NULL  )
    {
        thread->conn->ctxt->error = "internal: memory allocation failed (message)";
        return m;
    }

    m->hdr.msglen = HTON32( sz );
    m->hdr.secret = HTON32( SECRET );
    m->hdr.msgtype = HTON8( mtype );

    // Message type specific initialisation
    switch ( mtype )
    {
        case MSG_CONN:
            {
                mconn_t * mconn = (mconn_t *)m;
                mconn->async = HTON8( thread->conn->ctxt->mode == ASYNC );
                mconn->nodelay = HTON8( thread->conn->ctxt->nodelay );
                mconn->msgsz = HTON32( (uint32)thread->conn->ctxt->msgsz );
            }
            break;
        case MSG_DATA:
            {
                mdata_t * mdata = (mdata_t *)m;
                mdata->datasz = HTON32( sz - offsetof( mdata_t, data ) );
            }
            break;
        case MSG_DATA_ACK:
            {
                mdataack_t * mdataack = (mdataack_t *)m;
                mdataack->datasz = HTON32( sz - offsetof( mdataack_t, data ) );
            }
            break;
        default:
            break;
    }

    return m;
} // msgAlloc

/*
 * Allocate a thread and its receive buffer.
 */

thread_t *
threadAlloc(
    conn_t  * conn,
    ttype_t   type,
    int       tno
           )
{
    thread_t * t = NULL;

    if (  (conn == NULL) ||
          (conn->ctxt == NULL) )
        return t;

    t = (thread_t *)calloc( 1, sizeof(thread_t) );
    if (  t == NULL  )
    {
        conn->ctxt->error = "internal: memory allocation failed (thread)";
        return t;
    }

    t->conn = conn;
    t->type = type;
    t->tno = tno;
    t->state = DEFUNCT;
    t->rcvbuff = msgAlloc( t, MSG_ANY );
    if (  t->rcvbuff == NULL  )
    {
        conn->ctxt->error = "internal: memory allocation failed (thread buffer)";
        free( (void *)t );
        t = NULL;
    }

    return t;
} // threadAlloc

/*
 * Allocate a connection and its send and receive threads.
 */

conn_t *
connAlloc(
    context_t * ctxt,
    int         connid
         )
{
    conn_t * c = NULL;

    if (  ctxt == NULL  )
        return c;

    c = (conn_t *)calloc( 1, sizeof(conn_t) );
    if (  c == NULL  )
    {
        ctxt->error = "internal: memory allocation failed (connection)";
        return c;
    }

    c->ctxt = ctxt;
    c->connid = connid;
    c->msgsz = ctxt->msgsz;
    c->peer = (struct sockaddr *)calloc( 1, sizeof( struct sockaddr_in6 ) );
    if (  c->peer == NULL  )
    {
        free( (void *)c );
        c = NULL;
    }
    else
    {
        c->sender = threadAlloc( c, SENDER, 0 );
        if (  c->sender == NULL  )
        {
            free( (void *)(c->peer) );
            free( (void *)c );
            c = NULL;
        }
        else
        {
            c->receiver = threadAlloc( c, RECEIVER, 1 );
            if (  c->receiver == NULL  )
            {
                threadFree( c, &(c->sender) );
                free( (void *)(c->peer) );
                free( (void *)c );
                c = NULL;
            }
        }
    }
    
    return c;
} // connAlloc

/*
 * Allocate and initialise a context
 */
context_t *
contextAlloc(
    cs_t     cs,
    tmode_t  mode,
    char   * host,
    int      port,
    char   * src,
    int      msgsz,
    int      ramp,
    int      dur,
    int      verbose,
    int      brief,
    int      nconn,
    int      v4only,
    int      v6only,
    int      sbsz,
    int      rbsz,
    FILE   * log,
    int      debug
            )
{
    context_t * c = NULL;
    int i;

    c = (context_t *)calloc( 1, offsetof( context_t, conn ) + ( nconn * sizeof( conn_t * ) ) );
    if (  c == NULL  )
        return c;

    c->cs = cs;
    c->mode = mode;
    c->host = host;
    c->port = port;
    c->src = src;
    c->msgsz = msgsz;
    c->ramp = ramp;
    c->dur = dur;
    c->verbose = verbose;
    c->brief = brief;
    c->nconn = nconn;
    c->v4only = v4only;
    c->v6only = v6only;
    c->nodelay = NODELAY_OFF;
    c->sbsz = sbsz;
    c->rbsz = rbsz;
    c->log = log;
    c->debug = debug;
    c->tbase = getTS( 0 );
    c->maxmsgsz = MAX_MSG_SIZE;
    c->maxdatasz = getMaxDataSize( c );
    c->maxsockbuf = getMaxSockBuf();
    FD_ZERO( &c->lfds );

    for (i = 0; i < nconn; i++)
    {
        c->conn[i] = connAlloc( c, i );
        if (  c->conn[i] == NULL  )
        {
            contextFree( &c );
            break;
        }
    }

    if (  (c != NULL) && pthread_mutex_init( &(c->loglock), NULL )  )
        contextFree( &c );

    return c;
} // contextAlloc

