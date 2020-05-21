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
#include <pthread.h>
#include <errno.h>
#if !defined(WINDOWS)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/tcp.h>
#include <netdb.h>
#else
#include "Ws2tcpip.h"
#endif

#include <nwtest.h>

/******************************************************************************
 * Data
 */

/******************************************************************************
 * Private functions
 */

/*
 * Parse the arguments to the client sub-command
 */

static int
parseArgsClient(
    int          argc,
    char       * argv[],
    context_t ** ctxt
               )
{
static char buff[256];
    int               argno = 0;
    char            * host = NULL;
    char            * src = NULL;
    char            * ports = NULL;
    char            * logpath = NULL;
    FILE            * log = NULL;
    int               port = 0;
    int               msgsz = 0;
    int               nconn = 0;
    int               v4only = 0;
    int               v6only = 0;
    int               async = 0;
    int               dur = 0;
    int               nodelay = 0;
    int               bsz = 0;
    int               sbsz = 0;
    int               rbsz = 0;
    int               verbose = 0;
    int               brief = 0;
    int               ramp = -1;
    int               debug = 0;
    int               maxsockbuf = 0;
    long              tmp;
    int               sock;
    struct addrinfo * addr = NULL;

    if (  ctxt == NULL  )
    {
        fprintf( stderr, "error: internal error - NULL context\n" );
        return 1;
    }
    *ctxt = NULL;

    if (  argc < 2  )
        help( CLIENT, 1 );

    host = argv[argno++];
    if (  *host == '\0'  )
        help( CLIENT, 1 );

    if (  ! isInteger( 0, argv[argno] )  )
        help( CLIENT, 1 );
    ports = argv[argno++];
    port = atoi( ports );
    if (  (port < MIN_PORT) || (port > MAX_PORT)  )
        help( CLIENT, 0 );

    while (  argno < argc )
    {
        if (  strcmp( argv[argno], "-debug" ) == 0  )
        {
            debug = 1;
        }
#if defined(ALLOW_NODELAY)
        else
        if (  ( strcmp( argv[argno], "-nodelay" ) == 0 ) ||
              ( strcmp( argv[argno], "-n" ) == 0 )  )
        {
            if (  nodelay > 0  )
                help( CLIENT, 1 );
            nodelay = 1;
        }
#endif /* ALLOW_NODELAY */
        else
        if (  ( strcmp( argv[argno], "-async" ) == 0 ) ||
              ( strcmp( argv[argno], "-a" ) == 0 )  )
        {
            if (  async > 0  )
                help( CLIENT, 1 );
            async = 1;
        }
        else
        if (  ( strcmp( argv[argno], "-verbose" ) == 0 ) ||
              ( strcmp( argv[argno], "-v" ) == 0 )  )
        {
            if (  verbose || brief  )
                help( CLIENT, 1 );
            verbose = 1;
        }
        else
        if (  ( strcmp( argv[argno], "-brief" ) == 0 ) ||
              ( strcmp( argv[argno], "-b" ) == 0 )  )
        {
            if (  verbose || brief  )
                help( CLIENT, 1 );
            brief = 1;
        }
        else
        if (  strcmp( argv[argno], "-4" ) == 0  )
        {
            if (  v4only || v6only  )
                help( CLIENT, 1 );
            v4only = 1;
        }
        else
        if (  strcmp( argv[argno], "-6" ) == 0  )
        {
            if (  v4only || v6only  )
                help( CLIENT, 1 );
            v6only = 1;
        }
        else
        if (  ( strcmp( argv[argno], "-src" ) == 0 ) ||
              ( strcmp( argv[argno], "-s" ) == 0 )  )
        {
            if (  src != NULL  )
                help( CLIENT, 0 );
            if (  ++argno >= argc  )
                help( CLIENT, 1 );
            src = argv[argno];
            if (  ! isIPAddress( src )  )
                help( CLIENT, 1 );
        }
        else
        if (  strcmp( argv[argno], "-bsz" ) == 0  )
        {
            if (  bsz || sbsz || rbsz  )
                help( CLIENT, 1 );
            if (  ++argno >= argc  )
                help( CLIENT, 1 );
            if (  valueConvert( argv[argno], &tmp )  )
                help( CLIENT, 0 );
            if (  ( tmp < MIN_BSZ ) ||
                  ( tmp > MAX_BSZ )  )
                help( CLIENT, 0 );
            bsz = (int)tmp;
        }
        else
        if (  strcmp( argv[argno], "-sbsz" ) == 0  )
        {
            if (  bsz || sbsz  )
                help( CLIENT, 0 );
            if (  ++argno >= argc  )
                help( CLIENT, 1 );
            if (  valueConvert( argv[argno], &tmp )  )
                help( CLIENT, 0 );
            if (  ( tmp < MIN_BSZ ) ||
                  ( tmp > MAX_BSZ )  )
                help( CLIENT, 0 );
            sbsz = (int)tmp;
        }
        else
        if (  strcmp( argv[argno], "-rbsz" ) == 0  )
        {
            if (  bsz || rbsz  )
                help( CLIENT, 1 );
            if (  ++argno >= argc  )
                help( CLIENT, 1 );
            if (  valueConvert( argv[argno], &tmp )  )
                help( CLIENT, 0 );
            if (  ( tmp < MIN_BSZ ) ||
                  ( tmp > MAX_BSZ )  )
                help( CLIENT, 0 );
            rbsz = (int)tmp;
        }
        else
        if (  ( strcmp( argv[argno], "-dur" ) == 0 ) ||
              ( strcmp( argv[argno], "-d" ) == 0 )  )
        {
            if (  dur > 0  )
                help( CLIENT, 1 );
            if (  ++argno >= argc  )
                help( CLIENT, 1 );
            if (  ! isInteger( 0, argv[argno] )  )
                help( CLIENT, 0 );
            dur = atoi( argv[argno] );
            if (  ( dur < MIN_DURATION ) ||
                  ( dur > MAX_DURATION )  )
                help( CLIENT, 0 );
        }
        else
        if (  ( strcmp( argv[argno], "-ramp" ) == 0 ) ||
              ( strcmp( argv[argno], "-r" ) == 0 )  )
        {
            if (  ramp >= 0  )
                help( CLIENT, 1 );
            if (  ++argno >= argc  )
                help( CLIENT, 1 );
            if (  ! isInteger( 0, argv[argno] )  )
                help( CLIENT, 0 );
            ramp = atoi( argv[argno] );
            if (  ( ramp < MIN_RAMP ) ||
                  ( ramp > MAX_RAMP )  )
                help( CLIENT, 0 );
        }
        else
        if (  ( strcmp( argv[argno], "-msgsz" ) == 0 ) ||
              ( strcmp( argv[argno], "-m" ) == 0 )  )
        {
            if (  msgsz != 0  )
                help( CLIENT, 1 );
            if (  ++argno >= argc  )
                help( CLIENT, 1 );
            if (  valueConvert( argv[argno], &tmp )  )
                help( CLIENT, 0 );
            if (  ( tmp < MIN_MSG_SIZE ) ||
                  ( tmp > MAX_MSG_SIZE )  )
                help( CLIENT, 0 );
            msgsz = (int)tmp;
        }
        else
        if (  ( strcmp( argv[argno], "-conn" ) == 0 ) ||
              ( strcmp( argv[argno], "-c" ) == 0 )  )
        {
            if (  nconn != 0  )
                help( CLIENT, 1 );
            if (  ++argno >= argc  )
                help( CLIENT, 1 );
            if (  ! isInteger( 0, argv[argno] )  )
                help( CLIENT, 0 );
            nconn = atoi( argv[argno] );
            if (  ( nconn < MIN_CLT_CONN ) ||
                  ( nconn > MAX_CLT_CONN )  )
                help( CLIENT, 0 );
        }
        else
        if (  ( strcmp( argv[argno], "-log" ) == 0 ) ||
              ( strcmp( argv[argno], "-l" ) == 0 )  )
        {
            if (  logpath != NULL  )
                help( CLIENT, 1 );
            if (  ++argno >= argc  )
                help( CLIENT, 1 );
            logpath = argv[argno];
            if (  logpath[0] == '\0'  )
                help( CLIENT, 1 );
            if (  strcmp( logpath, LOG_STDOUT ) == 0  )
                log = stdout;
            else
            if (  strcmp( logpath, LOG_STDERR ) == 0  )
                log = stderr;
            else
                log = fopen( logpath, "w" );
            if (  log == NULL  )
            {
                fprintf( stderr, "error: unable to open '%s' for writing\n", logpath );
                return 2;
            }
            setbuf( log, NULL );
        }
        else
            help( CLIENT, 1 );
        argno += 1;
    }

    // Sanity checks
    if (  bsz  )
        sbsz = rbsz = bsz;
    if (  sbsz || rbsz  )
    {
        maxsockbuf = getMaxSockBuf();
        if (  ( sbsz > maxsockbuf ) ||
              ( rbsz > maxsockbuf ) ||
              ( ( sbsz + rbsz ) > maxsockbuf )  )
            help( CLIENT, 0 );
    }
    if (  src != NULL  )
    {
        if (  ( v4only && ! isIPv4Address( src ) ) ||
              ( v6only && ! isIPv6Address( src ) )  )
            help( CLIENT, 1 );
        if (  ( isIPv4Address( host ) && ! isIPv4Address( src ) ) ||
              ( isIPv6Address( host ) && ! isIPv6Address( src ) )  )
            help( CLIENT, 0 );
        if (  isIPv4Address( src )  )
            v4only = 1;
        else
        if (  isIPv6Address( src )  )
            v6only = 1;
    }

    // Initialise context fields
    if (  msgsz == 0  )
        msgsz = DFLT_CLT_MSG_SIZE;
    if (  nconn == 0  )
        nconn = DFLT_CLT_CONN;
    if (  ramp < 0  )
        ramp = DFLT_RAMP;
    if (  dur<= 0  )
        dur = DFLT_DURATION;

    *ctxt = contextAlloc( TCLIENT, async?ASYNC:SYNC, host, port, src, msgsz, ramp, dur, 
                          verbose, brief, nconn, v4only, v6only, sbsz, rbsz, log, debug );
    if (  *ctxt == NULL  )
    {
        fprintf( stderr, "error: memory allocation failed (context)\n" );
        return 3;
    }
#if defined(ALLOW_NODELAY)
    if (  nodelay  )
        (*ctxt)->nodelay = NODELAY_ON;
#endif /* ALLOW_NODELAY */

    // Validate 'src' if specified
    if (  src != NULL  )
    {
        if (  hostToAddr( src, NULL, v4only, v6only, 0, 
                          &((*ctxt)->v4addr),  &((*ctxt)->v6addr) )  )
        {
            fprintf( stderr, "error: invalid src '%s'\n", src );
            return 4;
        }
        if (  v4only  )
            addr = (*ctxt)->srcaddr = (*ctxt)->v4addr;
        else
            addr = (*ctxt)->srcaddr = (*ctxt)->v6addr;
        sock = socket( addr->ai_family, addr->ai_socktype, addr->ai_protocol );
        if (  sock < 0  )
        {
            fprintf( stderr, "error: invalid src '%s'\n", src );
            return 5;
        }
        if (  bind( sock, addr->ai_addr, addr->ai_addrlen )  )
        {
            close( sock );
            fprintf( stderr, "error: bind() failed for address '" );
            printIPv4address( stderr, addr->ai_addr, 1 );
            fprintf( stderr, "'\n" );
            return 6;
        }
        close( sock );
        (*ctxt)->srcaddr = addr;
    }

    if (  stopReceived()  )
        return INTR_EXIT;

    if (  v4only == v6only  )
        v4only = v6only = 1;
    (*ctxt)->v4addr = NULL;
    (*ctxt)->v6addr = NULL;

    if (  hostToAddr( host, ports, v4only, v6only, 0, 
                      &((*ctxt)->v4addr),  &((*ctxt)->v6addr) )  )
    {
        fprintf( stderr, "error: invalid host '%s'\n", host );
        return 5;
    }

    if (  stopReceived()  )
        return INTR_EXIT;

    // Count target addresses refer to the local system
    addr = (*ctxt)->v4addr;
    while (  addr != NULL  )
    {
        addr = addr->ai_next;
        (*ctxt)->naddr += 1;
        (*ctxt)->nv4addr += 1;
    }

    addr = (*ctxt)->v6addr;
    while (  addr != NULL  )
    {
        addr = addr->ai_next;
        (*ctxt)->naddr += 1;
        (*ctxt)->nv6addr += 1;
    }

    if (  stopReceived()  )
        return INTR_EXIT;

    (*ctxt)->tbase = getTS( 0 );

    return 0;
} // parseArgsClient

/*
 * Checks if all threads have azero return code.
 */

static int
allThreadsOK(
    context_t * ctxt
            )
{
    int connid;
    int ok = 1;

    if (  ctxt == NULL  )
        return 0;

    for ( connid = 0; connid < ctxt->nconn; connid++ )
    {
        if (  (ctxt->conn[connid]->sender == NULL) ||
              (ctxt->conn[connid]->receiver == NULL)  )
        {
            ok = 0;
            break;
        }
        if (  (ctxt->conn[connid]->sender->retcode != 0) ||
              (ctxt->conn[connid]->receiver->retcode != 0)  )
        {
            ok = 0;
            break;
        }
        if (  (ctxt->conn[connid]->sender->startts <= 0) ||
              (ctxt->conn[connid]->sender->stopts <= ctxt->conn[connid]->sender->startts)  )
        {
            ok = 0;
            break;
        }
        if (  (ctxt->mode == ASYNC) &&
              ( (ctxt->conn[connid]->receiver->startts <= 0) ||
                (ctxt->conn[connid]->receiver->stopts <= ctxt->conn[connid]->receiver->startts) )  )
        {
            ok = 0;
            break;
        }
    }

    return ok;
} // allThreadsOK

/*
 * Client 'receive message' function.
 */

static int
cltRecvMsg(
    context_t * ctxt,
    int         sr,
    int         connid,
    int         tno,
    int         sock,
    msg_t     * msg,
    int         maxsz,
    int         reqmtype,
    uint32      reqseqno
          )
{
    int ret = 0;
    char * errmsg = NULL;

    // Receive the client message and validate it.
    ret = recvMsg( ctxt, sock, msg, maxsz, &errmsg );
    if (  ret  )
    {
        if (  ret > 0  )
        {
            printErr( ctxt, 1, "error: %cthread %d/%d failed to receive message: %d/%s\n",
                      sr, connid, tno, ret, errmsg );
            return 4;
        }
        else
        {
            printErr( ctxt, 1, "error: %cthread %d/%d lost connection to server\n", sr, connid, tno );
            return -1;
        }
    }
    if (  ( (reqmtype == MSG_ANY) && ! validMsgType( msg->hdr.msgtype ) ) ||
          ( (reqmtype != MSG_ANY) && (msg->hdr.msgtype != reqmtype) )  )
    {
        printErr( ctxt, 1, "error: %cthread %d/%d expecting %s, received %s\n",
                  sr, connid, tno, msgTypeStr( reqmtype ), msgTypeStr( (int)msg->hdr.msgtype ) );
        return 5;
    }
    if (  msg->hdr.seqno != reqseqno  )
    {
        printErr( ctxt, 1, "error: %cthread %d/%d expecting seqno %u, received ud\n",
                  sr, connid, tno, reqseqno, msg->hdr.seqno );
        return 6;
    }

    if (  ( ctxt->debug ) && ( msg->hdr.msgtype != MSG_DATA ) && ( msg->hdr.msgtype != MSG_DATA_ACK )  )
        printErr( ctxt, 1, "DEBUG: %cthread %d/%d received %s\n",
                  sr, connid, tno, msgTypeStr( (int)msg->hdr.msgtype ) );

    return 0;
} // cltRecvMsg

/*
 * Receiver thread. Async mode only.
 */

static void * 
receiverThread(
    void * arg
              )
{
    thread_t   * thread = NULL;
    conn_t     * conn = NULL;
    context_t  * ctxt = NULL;
    void       * retval = NULL;
    char       * errmsg = NULL;
    int          ret;
    int          msgsz;
    int          datasz;
    int          done = 0;
    int          connid;
    int          tno;
    uint32       rseqno = 0;
    mdata_t    * mdata = NULL;
    mdisc_t    * mdisc = NULL;

    if (  arg == NULL  )
    {
        retval = (void *)1;
        goto fini;
    }
    thread = (thread_t *)arg;
    tno = thread->tno;
    if (  thread->conn == NULL  )
    {
        retval = (void *)2;
        goto fini;
    }

    conn = thread->conn;
    connid = conn->connid;
    if (  conn->ctxt == NULL  )
    {
        retval = (void *)3;
        goto fini;
    }
    ctxt = conn->ctxt;
    msgsz = ctxt->msgsz;
    datasz = msgsz - offsetof( mdata_t, data );
    mdata = (mdata_t *)thread->rcvbuff;

    if (  ctxt->debug  )
        printErr( ctxt, 1, "DEBUG: receiver thread %d/%d started\n", connid, tno );

    if (  thread->state == STOP  )
    {
        retval = (void *)INTR_EXIT;
        goto fini;
    }

    // Setup timer
    if (  thread->state == MEASURE  )
        thread->startts = getTS( 0 );

    //  Main message exchange loop
    do {
        // Receive a data message
        ret = cltRecvMsg( ctxt, 'R',  connid, tno, conn->rwsock, thread->rcvbuff, msgsz,
                          MSG_ANY, rseqno++ );
        if (  ret   )
            ret = ret + 10;
        else
        if (  mdata->hdr.msgtype == MSG_DISC  )
        {
            if (  thread->startts && ! thread->stopts  )
                thread->stopts = getTS( 0 );;
            done = 1;
        }
        else
        if (  mdata->hdr.msgtype != MSG_DATA  )
        {
            printErr( ctxt, 1, "error: Rthread %d/%d invalid message type %s\n",
                      connid, tno, msgTypeStr( (int)mdata->hdr.msgtype ) );
            ret = 4;
        }
        else
        if (  (msgsz != mdata->hdr.msglen) || (datasz != mdata->datasz)  )
        {
            printErr( ctxt, 1, "error: Rthread %d/%d invalid data size %d/%d\n",
                      connid, tno, (int)mdata->hdr.msglen,
                      (int)mdata->datasz );
            ret = 5;
        }

        // Timing stuff
        if (  thread->state == STOP  )
        {
            if (  thread->startts && ! thread->stopts  )
                thread->stopts = getTS( 0 );
            ret = INTR_EXIT;
            done = 1;
        }
        else
        if (  thread->state == END  )
        {
            if (  thread->startts && ! thread->stopts  )
                thread->stopts = getTS( 0 );
        }
        else
        if (  thread->state == MEASURE  )
        {
            if (  ! thread->startts  )
                thread->startts = getTS( 0 );
            // accrue stats
            thread->mrcvd++;
            thread->brcvd += msgsz;
        }
        else
        if (  thread->state == RAMP  )
        {
            if (  thread->startts && ! thread->stopts  )
                thread->stopts = getTS( 0 );
        }

    } while (  (ret == 0) && ! done  );

    if (  ret  )
        retval = (void *)((unsigned long)ret);

fini:
    if (  ctxt->debug  )
        printErr( ctxt, 1, "DEBUG: receiver thread %d/%d terminated(%ld)\n", connid, tno, (long)retval );
    if (  thread != NULL  )
        thread->state = FINISHED;
    return retval;
} // receiverThread

/*
 * Sender/Control thread.
 */

static void * 
senderThread(
    void * arg
            )
{
    thread_t   * thread = NULL;
    thread_t   * rthread = NULL;
    conn_t     * conn = NULL;
    context_t  * ctxt = NULL;
    void       * retval = NULL;
    char       * errmsg = NULL;
    int          ret;
    int          msgsz;
    int          datasz;
    int          async = 0;
    int          measuring = 0;
    int          done = 0;
    int          connid;
    int          tno;
    uint32       sbsz = 0;
    uint32       rbsz = 0;
    uint32       sseqno = 0;
    uint32       rseqno = 0;
    uint64       csrcats;
    uint64       ssrcats;
    uint64       rtb;
    uint64       rte;
    mconn_t    * mconn = NULL;
    mdisc_t    * mdisc = NULL;
    mdata_t    * mdata = NULL;
    mconnack_t * mconnack = NULL;
    mdiscack_t * mdiscack = NULL;
    mdataack_t * mdataack = NULL;

    if (  arg == NULL  )
    {
        retval = (void *)1;
        goto fini;
    }
    thread = (thread_t *)arg;
    tno = thread->tno;
    if (  thread->conn == NULL  )
    {
        retval = (void *)2;
        goto fini;
    }

    conn = thread->conn;
    connid = conn->connid;
    if (  conn->ctxt == NULL  )
    {
        retval = (void *)3;
        goto fini;
    }
    ctxt = conn->ctxt;
    msgsz = ctxt->msgsz;
    datasz = msgsz - offsetof( mdata_t, data );
    async = ( ctxt->mode == ASYNC );
    sbsz = (uint32)ctxt->sbsz;
    rbsz = (uint32)ctxt->rbsz;
    mconn = (mconn_t *)msgAlloc( thread, MSG_CONN );
    if (  mconn == NULL  )
    {
        printErr( ctxt, 1, "error: Sthread %d/%d unable to allocate MSG_CONN\n", connid, tno );
        retval = (void *)7;
        goto fini;
    }
    mdisc = (mdisc_t *)msgAlloc( thread, MSG_DISC );
    if (  mdisc == NULL  )
    {
        printErr( ctxt, 1, "error: Sthread %d/%d unable to allocate MSG_DISC\n", connid, tno );
        retval = (void *)8;
        goto fini;
    }
    mdata = (mdata_t *)msgAlloc( thread, MSG_DATA );
    if (  mdata == NULL  )
    {
        printErr( ctxt, 1, "error: Sthread %d/%d unable to allocate MSG_DATA\n", connid, tno );
        retval = (void *)9;
        goto fini;
    }
    mconnack = (mconnack_t *)thread->rcvbuff;
    mdataack = (mdataack_t *)thread->rcvbuff;
    mdiscack = (mdiscack_t *)thread->rcvbuff;

    // Send the connection message
    if (  ctxt->debug  )
        printErr( ctxt, 1, "DEBUG: Sthread %d/%d sending MSG_CONN\n", connid, tno );
    mconn->hdr.seqno = HTON32( sseqno );
    sseqno++;
    mconn->async = HTON8( async );
    mconn->sbsz = HTON32( sbsz );
    mconn->rbsz = HTON32( rbsz );
    csrcats = getTS( 0 );
    mconn->srcats = HTON64( csrcats );
    ret = sendMsg( ctxt, conn->rwsock, (msg_t *)mconn, &errmsg );
    if (  ret < 0  )
    {
        printErr( ctxt, 1, "error: Sthread %d/%d lost connection to server\n", connid, tno );
        retval = (void *)90;
        goto fini;
    }
    else
    if (  ret > 0  )
    {
        printErr( ctxt, 1, "error: Sthread %d/%d failed to send connect message: %d/%s\n",
                  connid, tno, ret, errmsg );
        retval = (void *)((unsigned long)(ret+10));
        goto fini;
    }
    if (  thread->state == STOP  )
    {
        retval = (void *)INTR_EXIT;
        goto fini;
    }

    // Receive the connection ack message and validate it.
    ret = cltRecvMsg( ctxt, 'S', conn->connid, thread->tno, conn->rwsock, thread->rcvbuff, sizeof( mconnack_t ),
                      MSG_CONN_ACK, rseqno++ );
    if (  ret  )
    {
        retval = (void *)((unsigned long)(ret+10));
        goto fini;
    }
    if (  thread->state == STOP  )
    {
        retval = (void *)INTR_EXIT;
        goto fini;
    }

    ssrcats =  mconnack->srcats;
    if (  ctxt->debug  )
        printErr( ctxt, 1, "DEBUG: csrcats = %lu, ssrcats = %lu\n", csrcats, ssrcats );

    if (  async  )
    {
        // Create and start the receiver thread.
        if (  ctxt->ramp > 0  )
            conn->receiver->state = RAMP;
        else
            conn->receiver->state = MEASURE;
        ret = pthread_create( &(conn->receiver->tid), NULL, receiverThread, (void *)conn->receiver );
        if (  ret  )
        {
            conn->receiver->state = DEFUNCT;
            printErr( ctxt, 1, "error: pthread_create() failed for receiver with error %d\n", ret );
            retval = (void *)11;
            goto fini;
        }
        else
        {
            enqueueThread( ctxt, conn->receiver );
            rthread = conn->receiver;
        }
    }
    if (  thread->state == STOP  )
    {
        retval = (void *)INTR_EXIT;
        goto fini;
    }

    // Setup timer
    if (  thread->state == MEASURE  )
    {
        measuring = 1;
        thread->startts = getTS( 0 );
    }

    //  Main message exchange loop
    do {
        // Send a data message
        mdata->hdr.seqno = HTON32( sseqno );
        sseqno++;
        mdata->datasz = HTON32( datasz );
        if (  measuring && ! async  )
           rtb = getTS( 0 );
        ret = sendMsg( ctxt, conn->rwsock, (msg_t *)mdata, &errmsg );
        if (  ret < 0  )
        {
            printErr( ctxt, 1, "error: Sthread %d/%d lost connection to server\n", connid, tno );
            retval = (void *)90;
            goto fini;
        }
        else
        if (  ret > 0  )
        {
            printErr( ctxt, 1, "error: Sthread %d/%d failed to send data message: %d/%s\n",
                      conn->connid, thread->tno, ret, errmsg );
            ret = ret + 10;
        }

        if (  measuring  ) // accrue stats
        {
            if (  ! thread->startts  )
                thread->startts = getTS( 0 );
            thread->msent++;
            thread->bsent += msgsz;
        }

        if (  (ret == 0) && ! async  )
        {
            // Receive a data ack message
            ret = cltRecvMsg( ctxt, 'S', conn->connid, thread->tno, conn->rwsock, thread->rcvbuff, msgsz,
                              MSG_DATA_ACK, rseqno++ );
            if (  measuring  )  // accrue stats
            {
                rte = getTS( 0 ) - rtb;
                thread->totrt += rte;
                if (  rte > thread->maxrt  )
                    thread->maxrt = rte;
                if (  rte < thread->minrt  )
                    thread->minrt = rte;
                thread->mrcvd++;
                thread->brcvd += msgsz;
            }
            if (  ret   )
                ret = ret + 10;
            else
            if (  (msgsz != mdataack->hdr.msglen) || (datasz != mdataack->datasz)  )
            {
                printErr( ctxt, 1, "error: Sthread %d/%d invalid data size %d/%d\n",
                          conn->connid, thread->tno, (int)mdataack->hdr.msglen,
                          (int)mdataack->datasz );
                ret = 9;
            }
        }

        if (  ( thread->state == STOP ) || ( thread->state == END )  )
        {
            if (  thread->startts && ! thread->stopts  )
                thread->stopts = getTS( 0 );
            measuring = 0;
            done = 1;
        }
        else
        if (  thread->state == RAMP  )
        {
            measuring = 0;
            if (  thread->startts && ! thread->stopts  )
            {
                thread->stopts = getTS( 0 );
            }
        }
        else
        if (  thread->state == MEASURE  )
        {
            measuring = 1;
        }

    } while (  (ret == 0) && ! done  );

    if (  ret  )
    {
        retval = (void *)((unsigned long)ret);
        goto fini;
    }

    // Send the disconnection message
    if (  ctxt->debug  )
        printErr( ctxt, 1, "DEBUG: Sthread %d/%d sending MSG_DISC\n", connid, tno );
    mdisc->hdr.seqno = HTON32( sseqno );
    sseqno++;
    ret = sendMsg( ctxt, conn->rwsock, (msg_t *)mdisc, &errmsg );
    if (  ret < 0  )
    {
        printErr( ctxt, 1, "error: Sthread %d/%d lost connection to server\n", connid, tno );
        retval = (void *)90;
        goto fini;
    }
    else
    if (  ret > 0  )
    {
        printErr( ctxt, 1, "error: Sthread %d/%d failed to send disconnect message: %d/%s\n",
                  conn->connid, thread->tno, ret, errmsg );
        retval = (void *)((unsigned long)(ret+10));
        goto fini;
    }

    // Wait for receiver thread to stop
    if (  async && ( rthread != NULL )  )
    {
        if (  waitforThread( rthread, FINISHED, 1000 )  )
        {
            printErr( ctxt, 1, "error: Sthread %d/%d failed to stop receiver (%s)\n", 
                      connid, tno, tStateStr( rthread->state ) );
            rthread->state = STOP;
            retval = (void *)90;
            goto fini;
        }
        rthread = NULL;
    }

    // Receive the disconnection ack message and validate it.
    ret = cltRecvMsg( ctxt, 'S', conn->connid, thread->tno, conn->rwsock, thread->rcvbuff, sizeof( mdiscack_t ),
                      MSG_DISC_ACK, rseqno++ );
    if (  ret  )
    {
        retval = (void *)((unsigned long)(ret+10));
        goto fini;
    }

    printMsg( ctxt, 1, "info: disconnected (conn = %d)\n", connid );

fini:
    if (  ctxt->debug  )
        printMsg( ctxt, 1, "DEBUG: sender thread %d/%d terminated (%ld)\n",
                  connid, tno, (long)retval );

    if (  async && (rthread != NULL)  )
    {
        rthread->state = STOP;
        waitforThread( rthread, FINISHED, 1000 );
    }
    if (  mconn != NULL  )
        msgFree( thread, (msg_t **)&mconn );
    if (  mdisc != NULL  )
        msgFree( thread, (msg_t **)&mdisc );
    if (  mdata != NULL  )
        msgFree( thread, (msg_t **)&mdata );
    if (  conn->rwsock >= 0  )
    {
        shutdown( conn->rwsock, SHUT_RDWR );
        close( conn->rwsock );
        if (  conn != NULL  )
            conn->rwsock = -1;
    }
    if (  thread != NULL  )
        thread->state = FINISHED;
    return retval;
} // senderThread

/*
 * Connects to the host. If retaddr is NULL, tries addresses in sequence until success
 * and returns the one that succeeded otherwise only tried the one passed in *retaddr.
 */

static int
clientConnect(
    context_t        * ctxt,
    struct addrinfo ** conaddr,
    struct addrinfo  * srcaddr
             )
{
    struct addrinfo * addr = NULL;
    int sock = -1, ret = 0;

    if (  ctxt == NULL  )
        return sock;

    if (  (conaddr != NULL) && (*conaddr != NULL)  )
    {
        sock = socket( (*conaddr)->ai_family, (*conaddr)->ai_socktype, (*conaddr)->ai_protocol );
        if (  sock >= 0  )
        {
            if (  ctxt->debug  )
            {
                logLock( ctxt );
                printErr( ctxt, 0, "DEBUG: connecting to '" );
                printIPaddress( getStdErr(ctxt), (*conaddr)->ai_addr, (*conaddr)->ai_addrlen, 1 );
                fprintf( getStdErr( ctxt ), "'" );
                if (  srcaddr != NULL  )
                {
                    fprintf( getStdErr( ctxt ), " from '" );
                    printIPaddress( getStdErr(ctxt), srcaddr->ai_addr, srcaddr->ai_addrlen, 1 );
                    fprintf( getStdErr( ctxt ), "'" );
                }
                fprintf( getStdErr( ctxt ), "\n" );
                logUnlock( ctxt );
            }
            if (  srcaddr != NULL  )
            {
                errno = 0;
                if (  bind( sock, srcaddr->ai_addr, srcaddr->ai_addrlen )  )
                {
                    if (  ctxt->debug  )
                    {
                        logLock( ctxt );
                        printErr( ctxt, 0, "DEBUG: bind() failed for address '" );
                        printIPaddress( getStdErr( ctxt), srcaddr->ai_addr, srcaddr->ai_addrlen, 1 );
                        fprintf( getStdErr( ctxt), "'\n" );
                        logUnlock( ctxt );
                    }
                    close( sock );
                    sock = -1;
                    ret = 1;
                }
            }
            if (  ret == 0  )
            {
                errno = 0;
                ret = connect( sock, (*conaddr)->ai_addr, (*conaddr)->ai_addrlen );
                if (   ret  )
                {
                    if (  ctxt->debug  )
                        printErr( ctxt, 1, "DEBUG: connection failed\n" );
                    close( sock );
                    sock = -1;
                }
                else
                if (  ctxt->debug  )
                    printErr( ctxt, 1, "DEBUG: connection successful (%d)\n", sock );
            }
        }
        return sock;
    }

    if (  conaddr != NULL  )
        *conaddr = NULL;

    // first try IPv6 addresses
    if (  ! ctxt->v4only  )
    {
        addr = ctxt->v6addr;
        while (  addr != NULL  )
        {
            if (  sock >= 0  )
                close( sock );
            ret = 0;
            sock = socket( addr->ai_family, addr->ai_socktype, addr->ai_protocol );
            if (  sock >= 0  )
            {
                if (  ctxt->debug  )
                {
                    logLock( ctxt );
                    printErr( ctxt, 0, "DEBUG: attempting connection to '" );
                    printIPaddress( getStdErr(ctxt), addr->ai_addr, addr->ai_addrlen, 1 );
                    fprintf( getStdErr( ctxt ), "'" );
                    if (  srcaddr != NULL  )
                    {
                        fprintf( getStdErr( ctxt ), " from '" );
                        printIPaddress( getStdErr(ctxt), srcaddr->ai_addr, srcaddr->ai_addrlen, 1 );
                        fprintf( getStdErr( ctxt ), "'" );
                    }
                    fprintf( getStdErr( ctxt ), "\n" );
                    logUnlock( ctxt );
                }
                if (  srcaddr != NULL  )
                {
                    errno = 0;
                    if (  bind( sock, srcaddr->ai_addr, srcaddr->ai_addrlen )  )
                    {
                        if (  ctxt->debug  )
                        {
                            logLock( ctxt );
                            printErr( ctxt, 0, "DEBUG: bind() failed for address '" );
                            printIPaddress( getStdErr( ctxt), srcaddr->ai_addr, srcaddr->ai_addrlen, 1 );
                            fprintf( getStdErr( ctxt), "'\n" );
                            logUnlock( ctxt );
                        }
                        close( sock );
                        sock = -1;
                        ret = 1;
                    }
                }
                if (  ret == 0  )
                {
                    errno = 0;
                    ret = connect( sock, addr->ai_addr, addr->ai_addrlen );
                    if (  ! ret  )
                    {
                        if (  ctxt->debug  )
                            printErr( ctxt, 1, "DEBUG: connection successful (%d)\n", sock );
                        if (  conaddr != NULL  )
                            *conaddr = addr;
                        return sock;
                    }
                    else
                    if (  ctxt->debug  )
                        printErr( ctxt, 1, "DEBUG: connection failed\n" );
                }
            }
            addr = addr->ai_next;
        }
    }

    // now try IPv4 addresses
    if (  ! ctxt->v6only  )
    {
        addr = ctxt->v4addr;
        while (  addr != NULL  )
        {
            if (  sock >= 0  )
                close( sock );
            ret = 0;
            sock = socket( addr->ai_family, addr->ai_socktype, addr->ai_protocol );
            if (  sock >= 0  )
            {
                if (  ctxt->debug  )
                {
                    logLock( ctxt );
                    printErr( ctxt, 0, "DEBUG: attempting connection to '" );
                    printIPaddress( getStdErr(ctxt), addr->ai_addr, addr->ai_addrlen, 1 );
                    fprintf( getStdErr( ctxt ), "'" );
                    if (  srcaddr != NULL  )
                    {
                        fprintf( getStdErr( ctxt ), " from '" );
                        printIPaddress( getStdErr(ctxt), srcaddr->ai_addr, srcaddr->ai_addrlen, 1 );
                        fprintf( getStdErr( ctxt ), "'" );
                    }
                    fprintf( getStdErr( ctxt ), "\n" );
                    logUnlock( ctxt );
                }
                if (  srcaddr != NULL  )
                {
                    errno = 0;
                    if (  bind( sock, srcaddr->ai_addr, srcaddr->ai_addrlen )  )
                    {
                        if (  ctxt->debug  )
                        {
                            logLock( ctxt );
                            printErr( ctxt, 0, "DEBUG: bind() failed for address '" );
                            printIPaddress( getStdErr( ctxt), srcaddr->ai_addr, srcaddr->ai_addrlen, 1 );
                            fprintf( getStdErr( ctxt), "'\n" );
                            logUnlock( ctxt );
                        }
                        close( sock );
                        sock = -1;
                        ret = 1;
                    }
                }
                if (  ret == 0  )
                {
                    errno = 0;
                    ret = connect( sock, addr->ai_addr, addr->ai_addrlen );
                    if (  ! ret  )
                    {
                        if (  ctxt->debug  )
                            printErr( ctxt, 1, "DEBUG: connection successful (%d)\n", sock );
                        if (  conaddr != NULL  )
                            *conaddr = addr;
                        return sock;
                    }
                    else
                    if (  ctxt->debug  )
                        printErr( ctxt, 1, "DEBUG: connection failed\n" );
                }
            }
            addr = addr->ai_next;
        }
    }

    if (  sock >= 0  )
        close( sock );

    return -1;
} // clientConnect

/*
 * Checks the run queue for terminated therads and cleans them up.
 */
static void
threadReaper(
    context_t * ctxt
            )
{
    thread_t * thread = NULL;
    conn_t * conn = NULL;
    int connid, tno;
    void * retval;
    int ret;

    if (  ctxt == NULL  )
        return; // something is badly wrong!

    // Mark any terminated threads as DEFUNCT and dequeue
    thread = ctxt->runqhead;
    while (  thread != NULL  )
    {
        conn = thread->conn;
        tno = thread->tno;
        if (  conn == NULL  )
            connid = -1;
        else
            connid = conn->connid;
        // if (  (thread->state == FINISHED) || pthread_kill(thread->tid,0)  )
        if (  ( thread->state == FINISHED ) || 
              ( ( thread->state != DEFUNCT ) && pthread_kill(thread->tid,0) )  )
        {
            if (  ctxt->debug  )
                printErr( ctxt, 1, "DEBUG: reaping thread %d/%d\n", connid, tno );
            ret = pthread_join(thread->tid,&retval);
            if (  ret && ctxt->debug  )
                printErr( ctxt, 1, "DEBUG: pthread_join() failed (%d) for thread %d/%d\n", ret, connid, tno );
            if (  ctxt->debug  )
                printErr( ctxt, 1, "DEBUG: thread %d/%d returned %ld\n", connid, tno, (long)retval );
            else
            if (  retval != NULL  )
                printErr( ctxt, 1, "error: thread %d/%d returned error %ld\n", connid, tno, (long)retval );
            memset( (void *)&(thread->tid), 0, sizeof(pthread_t) );
            thread->state = DEFUNCT;
            thread->retcode = (long)retval;
            if (  thread->conn == NULL  )
                printErr( ctxt, 1, "error: internal: thread %d has a NULL connection\n", tno );
            else
            {
                if (  ( thread->conn->sender->state == DEFUNCT ) &&
                      ( thread->conn->receiver->state == DEFUNCT )  )
                {
                    if (  thread->conn->rwsock >= 0  )
                    {
                        shutdown( thread->conn->rwsock, SHUT_RDWR );
                        close( thread->conn->rwsock );
                        thread->conn->rwsock = -1;
                    }
                    thread->conn->busy = 0;
                }
            }
        }
        if (  thread->state == DEFUNCT  )
        {
            if (  ctxt->debug  )
                printErr( ctxt, 1, "DEBUG: dequeueing thread %d/%d\n", connid, tno );
            dequeueThread( ctxt, &thread );
        }
        else
            thread = thread->next;
    }
} // threadReaper

/*
 * Hand over responsibility for a connection to a dedicated thread.
 */
static int
handoffConn(
    context_t       * ctxt,
    int               connid,
    int               srvsock,
    struct sockaddr * srvaddr,
    socklen_t         lsrvaddr
           )
{
    int ret = 0;
    conn_t * conn = NULL;
    struct timeval rcvto = { MAX_MSG_WAIT, 0 };
    struct timeval sndto = { MAX_MSG_WAIT, 0 };

    if (  (ctxt == NULL) || (connid < 0) || (srvsock < 0) || (srvaddr == NULL) ||
          ( (lsrvaddr != sizeof(struct sockaddr_in)) && 
            (lsrvaddr != sizeof(struct sockaddr_in6)) )  )
        return -1;

    // iniialise / reset fields
    conn = ctxt->conn[connid];
    memcpy( (void *)(conn->peer), (void *)srvaddr, (size_t)lsrvaddr );
    conn->lpeer = lsrvaddr;
    conn->v6peer = ( lsrvaddr == sizeof(struct sockaddr_in6) );
    conn->error = NULL;
    conn->rwsock = srvsock;
    if (  setsockopt( conn->rwsock, SOL_SOCKET, SO_RCVTIMEO, (void *)&rcvto, sizeof( struct timeval ) ) ||
#if defined(ALLOW_NODELAY)
          setsockopt( conn->rwsock, IPPROTO_TCP, TCP_NODELAY, (void *)&(ctxt->nodelay), sizeof( int ) ) ||
#endif /* ALLOW_NODELAY */
          setsockopt( conn->rwsock, SOL_SOCKET, SO_SNDTIMEO, (void *)&sndto, sizeof( struct timeval ) )  )
    {
        conn->sender->state = DEFUNCT;
        shutdown( conn->rwsock, SHUT_RDWR );
        close( conn->rwsock );
        conn->rwsock = -1;
        conn->busy = 0;
        printErr( ctxt, 1, "error: setsockopt() failed with error %d\n", errno );
    }

    conn->startts = 0;
    conn->stopts = 0;
    conn->tpsent = 0;
    conn->tprcvd = 0;
    conn->tbsent = 0;
    conn->tbrcvd = 0;

    // initialise / reset thread fields
    conn->sender->next = NULL;
    conn->sender->prev = NULL;
    conn->sender->state = DEFUNCT;
    conn->sender->startts = 0;
    conn->sender->stopts = 0;
    conn->sender->msent = 0;
    conn->sender->mrcvd = 0;
    conn->sender->bsent = 0;
    conn->sender->brcvd = 0;
    conn->sender->totrt = 0;
    conn->sender->maxrt = 0;
    conn->sender->minrt = 999999999999999999L;

    conn->receiver->next = NULL;
    conn->receiver->prev = NULL;
    conn->receiver->state = DEFUNCT;
    conn->receiver->startts = 0;
    conn->receiver->stopts = 0;
    conn->receiver->msent = 0;
    conn->receiver->mrcvd = 0;
    conn->receiver->bsent = 0;
    conn->receiver->brcvd = 0;
    conn->receiver->totrt = 0;
    conn->receiver->maxrt = 0;
    conn->receiver->minrt = 999999999999999999L;

    // Create and start the sender thread.
    if (  ctxt->ramp > 0  )
        conn->sender->state = RAMP;
    else
        conn->sender->state = MEASURE;
    ret = pthread_create( &(conn->sender->tid), NULL, senderThread, (void *)conn->sender );
    if (  ret  )
    {
        conn->sender->state = DEFUNCT;
        shutdown( conn->rwsock, SHUT_RDWR );
        close( conn->rwsock );
        conn->rwsock = -1;
        conn->busy = 0;
        printErr( ctxt, 1, "error: pthread_create() failed with error %d\n", ret );
    }
    else
        enqueueThread( ctxt, conn->sender );

    return ret;
} //handoffConn

/*
 * Display the performance stats
 */

static void
displayStats(
    context_t * ctxt
            )
{
    int  connid;
    long elapsed;
    long minel = 0;
    long maxel = 0;
    long totel = 0;
    long avgel = 0;
    long msent = 0;
    long mrcvd = 0;
    long bsent = 0;
    long brcvd = 0;
    long minrt = 0;
    long maxrt = 0;
    long totrt = 0;
    long avgrt = 0;
    long minstart = 0;
    long maxstart = 0;
    long cpu_time = 0;
    int  cpu_ustime = 0;
    long cpu_user = 0;
    int  cpu_ususer = 0;
    long cpu_sys = 0;
    int  cpu_ussys = 0;
    long pcpu_seconds = 0;
    int  pcpu_useconds = 0;
    long numcpus = 1;
    long totcpuus = 0;
    long usedcpuus = 0;
    double proccpu = 0.0;
    double syscpu = 0.0;

    if (  ctxt == NULL  )
        return;

    cpu_user = rend.ru_utime.tv_sec - rstart.ru_utime.tv_sec;
    cpu_ususer = rend.ru_utime.tv_usec - rstart.ru_utime.tv_usec;
    if (  cpu_ususer < 0  )
    {
        cpu_user -= 1;
        cpu_ususer += 1000000;
    }

    cpu_sys = rend.ru_stime.tv_sec - rstart.ru_stime.tv_sec;
    cpu_ussys = rend.ru_stime.tv_usec - rstart.ru_stime.tv_usec;
    if (  cpu_ussys < 0  )
    {
        cpu_sys -= 1;
        cpu_ussys += 1000000;
    }

    cpu_time = cpu_user + cpu_sys;
    cpu_ustime = cpu_ususer + cpu_ussys;
    if (  cpu_ustime >= 1000000  )
    {
        cpu_time += 1;
        cpu_ustime %= 1000000;
    }

    pcpu_seconds = pend.tv_sec - pstart.tv_sec;
    pcpu_useconds = pend.tv_usec - pstart.tv_usec;
    if (  pcpu_useconds < 0  )
    {
        pcpu_seconds -= 1;
        pcpu_useconds += 1000000;
    }

    numcpus = sysconf( _SC_NPROCESSORS_ONLN );
    totcpuus = numcpus * ( ( pcpu_seconds * 1000000 ) + pcpu_useconds );
    usedcpuus = ( cpu_time * 1000000 ) + cpu_ustime;
    proccpu = ( 100.0 * (double)usedcpuus ) / (double)( ( pcpu_seconds * 1000000 ) + pcpu_useconds );
    syscpu = ( 100.0 * (double)usedcpuus ) / (double)totcpuus;

    minstart = ctxt->conn[0]->sender->startts;
    minel = ctxt->conn[0]->sender->stopts - minstart;
    if (  ctxt->mode == ASYNC  )
    {
        for ( connid = 0; connid < ctxt->nconn; connid++ )
        {
            if ( ctxt->conn[connid]->sender->startts > maxstart  )
                maxstart = ctxt->conn[connid]->sender->startts;
            if ( ctxt->conn[connid]->receiver->startts > maxstart  )
                maxstart = ctxt->conn[connid]->receiver->startts;
            if ( ctxt->conn[connid]->sender->startts < minstart  )
                minstart = ctxt->conn[connid]->sender->startts;
            if ( ctxt->conn[connid]->receiver->startts < minstart  )
                minstart = ctxt->conn[connid]->receiver->startts;
            elapsed = ctxt->conn[connid]->sender->stopts - ctxt->conn[connid]->sender->startts;
            totel += elapsed;
            if (  elapsed > maxel  )
                maxel = elapsed;
            if (  elapsed < minel  )
                minel = elapsed;
            elapsed = ctxt->conn[connid]->receiver->stopts - ctxt->conn[connid]->receiver->startts;
            totel += elapsed;
            if (  elapsed > maxel  )
                maxel = elapsed;
            if (  elapsed < minel  )
                minel = elapsed;
            msent += ctxt->conn[connid]->sender->msent;
            mrcvd += ctxt->conn[connid]->sender->mrcvd;
            bsent += ctxt->conn[connid]->sender->bsent;
            brcvd += ctxt->conn[connid]->sender->brcvd;
            msent += ctxt->conn[connid]->receiver->msent;
            mrcvd += ctxt->conn[connid]->receiver->mrcvd;
            bsent += ctxt->conn[connid]->receiver->bsent;
            brcvd += ctxt->conn[connid]->receiver->brcvd;
        }
        avgel = totel / ( 2 * ctxt->nconn );
    }
    else
    {
        minrt = ctxt->conn[0]->sender->minrt;
        for ( connid = 0; connid < ctxt->nconn; connid++ )
        {
            if ( ctxt->conn[connid]->sender->startts > maxstart  )
                maxstart = ctxt->conn[connid]->sender->startts;
            if ( ctxt->conn[connid]->sender->startts < minstart  )
                minstart = ctxt->conn[connid]->sender->startts;
            elapsed = ctxt->conn[connid]->sender->stopts - ctxt->conn[connid]->sender->startts;
            totel += elapsed;
            if (  elapsed > maxel  )
                maxel = elapsed;
            if (  elapsed < minel  )
                minel = elapsed;
            msent += ctxt->conn[connid]->sender->msent;
            mrcvd += ctxt->conn[connid]->sender->mrcvd;
            bsent += ctxt->conn[connid]->sender->bsent;
            brcvd += ctxt->conn[connid]->sender->brcvd;
            totrt += ctxt->conn[connid]->sender->totrt;
            if (  ctxt->conn[connid]->sender->maxrt > maxrt  )
                maxrt = ctxt->conn[connid]->sender->maxrt;
            if (  ctxt->conn[connid]->sender->minrt < minrt  )
                minrt = ctxt->conn[connid]->sender->minrt;
        }
        avgel = totel / ctxt->nconn;
        avgrt = totrt / msent;
    }

    if (  ctxt->brief  )
    {
        if (  ctxt->mode == ASYNC  )
            printMsg( ctxt, 0, "info: results A,%d,%ld,%ld,%.3f,%.3f\n",
                      ctxt->nconn, (bsent*1000000)/avgel, (brcvd*1000000)/avgel, proccpu, syscpu );
        else
            printMsg( ctxt, 0, "info: results S,%d,%ld,%ld,%ld,%ld,%.3f,%.3f\n", 
                      ctxt->nconn, (bsent*1000000)/avgel, minrt, avgrt, maxrt, proccpu, syscpu );
    }
    else
    {
    printMsg( ctxt, 0, "====================================================================================================\n" );
    printMsg( ctxt, 0, "\n" );
    printMsg( ctxt, 0, "Mode                 : %s\n", (ctxt->mode==ASYNC)?"ASYNC":"SYNC" );
    printMsg( ctxt, 0, "Message size         : %'d bytes\n", ctxt->msgsz );
    printMsg( ctxt, 0, "Connections          : %'d\n", ctxt->nconn );
    printMsg( ctxt, 0, "Ramp time            : %d seconds\n", ctxt->ramp );
    printMsg( ctxt, 0, "Measure time         : %'d seconds\n", ctxt->dur );
    printMsg( ctxt, 0, "\n" );
    if (  ctxt->mode == ASYNC  )
    {
    printMsg( ctxt, 0, "Total msg sent       : %'ld\n", msent );
    printMsg( ctxt, 0, "Total msg rcvd       : %'ld\n", mrcvd );
    printMsg( ctxt, 0, "Total data sent      : %'ld bytes\n", bsent );
    printMsg( ctxt, 0, "Total data rcvd      : %'ld bytes\n", brcvd );
    printMsg( ctxt, 0, "Avg measure time     : %'ld µs\n", avgel );
    printMsg( ctxt, 0, "Start variance       : %'ld µs\n", maxstart - minstart );
    printMsg( ctxt, 0, "Run variance         : %'ld µs\n", maxel - minel );
    printMsg( ctxt, 0, "\n" );
    printMsg( ctxt, 0, "Send throughput      : %'ld bytes/s\n", (bsent*1000000)/avgel );
    printMsg( ctxt, 0, "Recv throughput      : %'ld bytes/s\n", (brcvd*1000000)/avgel );
    printMsg( ctxt, 0, "Average throughput   : %'ld bytes/s\n", ( ( (bsent*1000000)/avgel ) + ( (brcvd*1000000)/avgel ) ) / 2 );
    }
    else
    {
    printMsg( ctxt, 0, "Total messages       : %'ld\n", msent );
    printMsg( ctxt, 0, "Total data           : %'ld bytes\n", bsent );
    if (  ctxt->nconn > 1  )
    {
        printMsg( ctxt, 0, "Avg measure time     : %'ld µs\n", avgel );
        printMsg( ctxt, 0, "Start variance       : %'ld µs\n", maxstart - minstart );
        printMsg( ctxt, 0, "Run variance         : %'ld µs\n", maxel - minel );
    }
    else
        printMsg( ctxt, 0, "Measure time         : %'ld µs\n", avgel );
    printMsg( ctxt, 0, "\n" );
    printMsg( ctxt, 0, "Throughput           : %'ld bytes/s\n", (bsent*1000000)/avgel );
    printMsg( ctxt, 0, "Minimum R/T          : %'ld µs\n", minrt );
    printMsg( ctxt, 0, "Average R/T          : %'ld µs\n", avgrt );
    printMsg( ctxt, 0, "Maximum R/T          : %'ld µs\n", maxrt );
    }
    printMsg( ctxt, 0, "\n" );
    printMsg( ctxt, 0, "Elapsed test time    : %'ld.%3.3d seconds\n", pcpu_seconds, pcpu_useconds/1000 );
    printMsg( ctxt, 0, "User CPU time        : %'ld.%3.3d seconds\n", cpu_user, cpu_ususer/1000 );
    printMsg( ctxt, 0, "System CPU time      : %'ld.%3.3d seconds\n", cpu_sys, cpu_ussys/1000 );
    printMsg( ctxt, 0, "Total CPU time       : %'ld.%3.3d seconds\n", cpu_time, cpu_ustime/1000 );
    printMsg( ctxt, 0, "Process CPU usage    : %.3f%%\n", proccpu );
    printMsg( ctxt, 0, "System CPU usage     : %.3f%%\n", syscpu );
    printMsg( ctxt, 0, "\n" );

    if (  ctxt->verbose  )
    {
        if (  ctxt->mode == ASYNC  )
        {
            for ( connid = 0; connid < ctxt->nconn; connid++ )
            {
            printMsg( ctxt, 0, "C#%2.2d messages sent   : %'ld\n", connid, ctxt->conn[connid]->sender->msent );
            printMsg( ctxt, 0, "C#%2.2d messages rcvd   : %'ld\n", connid, ctxt->conn[connid]->receiver->mrcvd );
            printMsg( ctxt, 0, "C#%2.2d data sent       : %'ld bytes\n", connid, ctxt->conn[connid]->sender->bsent );
            printMsg( ctxt, 0, "C#%2.2d data rcvd       : %'ld bytes\n", connid, ctxt->conn[connid]->receiver->brcvd );
            elapsed = ctxt->conn[connid]->sender->stopts - ctxt->conn[connid]->sender->startts;
            printMsg( ctxt, 0, "C#%2.2d send time       : %'ld µs\n", connid, elapsed );
            elapsed = ctxt->conn[connid]->receiver->stopts - ctxt->conn[connid]->receiver->startts;
            printMsg( ctxt, 0, "C#%2.2d recv time       : %'ld µs\n", connid, elapsed );
            printMsg( ctxt, 0, "C#%2.2d send start ts   : %'ld µs\n", connid, ctxt->conn[connid]->sender->startts  );
            printMsg( ctxt, 0, "C#%2.2d recv start ts   : %'ld µs\n", connid, ctxt->conn[connid]->receiver->startts  );
            elapsed = ctxt->conn[connid]->sender->stopts - ctxt->conn[connid]->sender->startts;
            bsent = ctxt->conn[connid]->sender->bsent;
            printMsg( ctxt, 0, "C#%2.2d send throughput : %'ld bytes/s\n", connid, (bsent*1000000)/elapsed );
            elapsed = ctxt->conn[connid]->sender->stopts - ctxt->conn[connid]->receiver->startts;
            brcvd = ctxt->conn[connid]->receiver->brcvd;
            printMsg( ctxt, 0, "C#%2.2d recv throughput : %'ld bytes/s\n",connid,  (brcvd*1000000)/elapsed );
            printMsg( ctxt, 0, "\n" );
            }
        }
        else
        {
            for ( connid = 0; connid < ctxt->nconn; connid++ )
            {
            printMsg( ctxt, 0, "C#%2.2d messages        : %'ld\n", connid, ctxt->conn[connid]->sender->msent );
            printMsg( ctxt, 0, "C#%2.2d data            : %'ld bytes\n", connid, ctxt->conn[connid]->sender->bsent );
            elapsed = ctxt->conn[connid]->sender->stopts - ctxt->conn[connid]->sender->startts;
            printMsg( ctxt, 0, "C#%2.2d measure time    : %'ld µs\n", connid, elapsed );
            printMsg( ctxt, 0, "C#%2.2d start ts        : %'ld µs\n", connid, ctxt->conn[connid]->sender->startts  );
            elapsed = ctxt->conn[connid]->sender->stopts - ctxt->conn[connid]->sender->startts;
            bsent = ctxt->conn[connid]->sender->bsent;
            printMsg( ctxt, 0, "C#%2.2d throughput      : %'ld bytes/s\n", connid, (bsent*1000000)/elapsed );
            printMsg( ctxt, 0, "C#%2.2d minimum R/T     : %'ld µs\n", connid, ctxt->conn[connid]->sender->minrt );
            avgrt = ctxt->conn[connid]->sender->totrt / ctxt->conn[connid]->sender->msent;
            printMsg( ctxt, 0, "C#%2.2d average R/T     : %'ld µs\n", connid, avgrt );
            printMsg( ctxt, 0, "C#%2.2d maximum R/T     : %'ld µs\n", connid, ctxt->conn[connid]->sender->maxrt );
            printMsg( ctxt, 0, "\n" );
            }
        }
    }
    printMsg( ctxt, 0, "====================================================================================================\n" );
    }
    
} // displayStats

/******************************************************************************
 * Public functions
 */

/*
 * process the server sub-command
 */

int
cmdClient(
    int    argc,
    char * argv[]
         )
{
    context_t * ctxt = NULL;
    int ret = 0;
    int finished = 0;
    int connid;
    int sno;
    int ramping = 0;
    uint64 now;
    uint64 rlimit = 0;
    uint64 dlimit = 0;
    int tcpmaxseg;
    socklen_t ltcpmaxseg;
    int sosndbuf;
    socklen_t lsosndbuf;
    int sorcvbuf;
    socklen_t lsorcvbuf;
    struct timeval stout;
    struct addrinfo * srvaddr = NULL;
    socklen_t lcltaddr = 0;
    thread_t * thread = NULL;
    tstate_t tstate = RUNNING;
    tstate_t ptstate = RUNNING;

    // setup signal handlers
    if (  handleSignals()  )
    {
        fprintf( stderr, "error: unable to setup signal handlers\n" );
        ret = 30;
        goto fini;
    }

    // parse command line arguments, initialise context
    ret = parseArgsClient( argc, argv, &ctxt );
    if (  ret  )
        goto fini;

    printMsg( ctxt, 0, "info: %s version %s\n", PROGNAME, VERSION );

    // Connect all the connection sockets
    for ( connid = 0; connid < ctxt->nconn; connid++ )
    {
        if (  stopReceived()  )
        {
            ret = INTR_EXIT;
            goto fini;
        }
        ctxt->conn[connid]->rwsock = clientConnect( ctxt, &srvaddr, ctxt->srcaddr );
        if ( ctxt->conn[connid]->rwsock < 0  )
        {
            printErr( ctxt, 0, "error: unable to connect to '%s' (connid = %d)\n", ctxt->host, connid );
            ret = 31;
            goto fini;
        }

        // get some info about the connection
        tcpmaxseg = -1;
        ltcpmaxseg = sizeof( tcpmaxseg );
        if (  getsockopt( ctxt->conn[connid]->rwsock, IPPROTO_TCP, TCP_MAXSEG, (void *)&tcpmaxseg, &ltcpmaxseg )  )
            tcpmaxseg = -1;
        sosndbuf = -1;
        lsosndbuf = sizeof( sosndbuf );
        if (  getsockopt( ctxt->conn[connid]->rwsock, SOL_SOCKET, SO_SNDBUF, (void *)&sosndbuf, &lsosndbuf )  )
            sosndbuf = -1;
        sorcvbuf = -1;
        lsorcvbuf = sizeof( sorcvbuf );
        if (  getsockopt( ctxt->conn[connid]->rwsock, SOL_SOCKET, SO_RCVBUF, (void *)&sorcvbuf, &lsorcvbuf )  )
            sorcvbuf = -1;

#if defined(ALLOW_BUFFSIZE)
        // set socket buffer sizes if required
        if (  ctxt->sbsz && ( ctxt->sbsz != sosndbuf )  )
        {
            errno = 0;
            if (  setsockopt( ctxt->conn[connid]->rwsock, SOL_SOCKET, SO_SNDBUF, (void *)&(ctxt->sbsz), sizeof( ctxt->sbsz ) )  )
            {
                printErr( ctxt, 0, "error: setsockopt( ..., SO_SNDBUF, ...) failed %d (%s)\n",
                          errno, strerror( errno ) );
                ret = 32;
                goto fini;
            }
            sosndbuf = -1;
            lsosndbuf = sizeof( sosndbuf );
            errno = 0;
            if (  getsockopt( ctxt->conn[connid]->rwsock, SOL_SOCKET, SO_SNDBUF, (void *)&sosndbuf, &lsosndbuf )  )
            {
                printErr( ctxt, 0, "error: getsockopt( ..., SO_SNDBUF, ...) failed %d (%s)\n",
                          errno, strerror( errno ) );
                ret = 32;
                goto fini;
            }
        }
        if (  ctxt->rbsz && ( ctxt->rbsz != sorcvbuf )  )
        {
            errno = 0;
            if (  setsockopt( ctxt->conn[connid]->rwsock, SOL_SOCKET, SO_RCVBUF, (void *)&(ctxt->rbsz), sizeof( ctxt->rbsz ) )  )
            {
                printErr( ctxt, 0, "error: setsockopt( ..., SO_RCVBUF, ...) failed %d (%s)\n",
                          errno, strerror( errno ) );
                ret = 33;
                goto fini;
            }
            sorcvbuf = -1;
            lsorcvbuf = sizeof( sorcvbuf );
            errno = 0;
            if (  getsockopt( ctxt->conn[connid]->rwsock, SOL_SOCKET, SO_RCVBUF, (void *)&sorcvbuf, &lsorcvbuf )  )
            {
                printErr( ctxt, 0, "error: getsockopt( ..., SO_RCVBUF, ...) failed %d (%s)\n",
                          errno, strerror( errno ) );
                ret = 33;
                goto fini;
            }
        }
#endif /* ALLOW_BUFFSIZE */

        printMsg( ctxt, 0, "info: connected to '" );
        printIPaddress( getStdOut(ctxt), srvaddr->ai_addr, srvaddr->ai_addrlen, 1 );
        fprintf( getStdOut( ctxt ), "' (conn = %d, %s, msgsz = %d, maxseg = %d, sndbsz = %d, rcvbsz = %d)\n",
                 connid, (ctxt->mode==ASYNC)?"ASYNC":"SYNC", ctxt->msgsz, tcpmaxseg, sosndbuf, sorcvbuf );
    }

    // Hand off connections to dedicated threads
    for ( connid = 0; connid < ctxt->nconn; connid++ )
    {
        if (  stopReceived()  )
        {
            ret = INTR_EXIT;
            goto fini;
        }
        ret = handoffConn( ctxt, connid, ctxt->conn[connid]->rwsock, 
                           srvaddr->ai_addr, srvaddr->ai_addrlen );
        if ( ret  )
            goto fini;
    }

    // Initialise timing stuff
    ramping = (ctxt->ramp > 0);
    now = getTS( 0 );
    if (  ramping  )
    {
        rlimit = now + (ctxt->ramp * 1000000);
        tstate = ptstate = RAMP;
    }
    else
    {
        gettimeofday( &pstart, NULL );
        getrusage( RUSAGE_SELF, &rstart );
        dlimit = now + (ctxt->dur * 1000000);
        tstate = ptstate = MEASURE;
    }

    // Wait for all threads to finish
    while (  ctxt->runqhead != NULL  )
    {
        now = getTS( 0 );
        if (  stopReceived()  )
        {
            tstate = STOP;
            if (  dlimit && ! ramping  )
            {
                getrusage( RUSAGE_SELF, &rend );
                gettimeofday( &pend, NULL );
            }
        }
        else
        if (  ramping  )
        {
            if (  now > rlimit  )
            {
                if (  dlimit == 0  )
                {
                    ramping = 0;
                    dlimit = now + (ctxt->dur * 1000000);
                    tstate = MEASURE;
                    gettimeofday( &pstart, NULL );
                    getrusage( RUSAGE_SELF, &rstart );
                }
                else
                    tstate = END;
            }
        }
        else
        if (  now > dlimit  )
        {
            if (  rlimit != 0  )
            {
                ramping = 1;
                rlimit = now + (ctxt->ramp * 1000000);
                tstate = RAMP;
                getrusage( RUSAGE_SELF, &rend );
                gettimeofday( &pend, NULL );
            }
            else
            {
                tstate = END;
                getrusage( RUSAGE_SELF, &rend );
                gettimeofday( &pend, NULL );
            }
        }
        if (  tstate != ptstate  )
        {
            thread = ctxt->runqhead;
            while (  thread != NULL  )
            {
                if (  ( thread->type == SENDER ) ||
                      ( ( thread->type == RECEIVER ) && ( tstate != STOP ) )  )
                    thread->state = tstate;
                thread = thread->next;
            }
            ptstate = tstate;
        }
        usSleep( 500 );
        threadReaper( ctxt );
    }

fini:
    if (  ctxt != NULL  )
    {
        thread = ctxt->runqhead;
        while (  thread != NULL  )
        {
            waitforThread( thread, FINISHED, 1000 );
            if (  (thread->state != FINISHED) && (thread->state != DEFUNCT)  )
                thread->state = STOP;
            waitforThread( thread, FINISHED, 1000 );
            thread = thread->next;
        }
        sleep( 1 );
        threadReaper( ctxt );
        for ( connid = 0; connid < ctxt->nconn; connid++ )
            if (  ctxt->conn[connid]->rwsock >= 0  )
            {
                shutdown( ctxt->conn[connid]->rwsock, SHUT_RDWR );
                close( ctxt->conn[connid]->rwsock );
                ctxt->conn[connid]->rwsock = -1;
            }
    }

    // display performance metrics
    if (  (ret == 0) && allThreadsOK( ctxt )  )
        displayStats( ctxt );

    return ret;
} // cmdClient

