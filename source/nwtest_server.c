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
#include <netinet/tcp.h>
#include <netdb.h>
#else
#include "Ws2tcpip.h"
#endif

#include <nwtest.h>

#define LISTEN_BACKLOG    5

/******************************************************************************
 * Data
 */

/******************************************************************************
 * Private functions
 */

/*
 * Parse the arguments to the server sub-command
 */

static int
parseArgsServer(
    int          argc,
    char       * argv[],
    context_t ** ctxt
               )
{
static char buff[256];
    int               argno = 0;
    char            * host = NULL;
    char            * ports = NULL;
    char            * logpath = NULL;
    FILE            * log = NULL;
    int               port = 0;
    int               msgsz = 0;
    int               nconn = 0;
    int               v4only = 0;
    int               v6only = 0;
    int               nodelay = 0;
    int               debug = 0;
    long              tmp;
    int               sock;
    struct addrinfo * addr = NULL;

    if (  ctxt == NULL  )
    {
        fprintf( stderr, "error: internal error - NULL context\n" );
        return 1;
    }
    *ctxt = NULL;

    if (  argc < 1  )
        help( SERVER );

    if (  ! isInteger( 0, argv[argno] )  )
        help( SERVER );
    ports = argv[argno++];
    port = atoi( ports );
    if (  (port < MIN_PORT) || (port > MAX_PORT)  )
        help( SERVER );

    while (  argno < argc )
    {
        if (  ( strcmp( argv[argno], "-host" ) == 0 ) ||
              ( strcmp( argv[argno], "-h" ) == 0 )  )
        {
            if (  host != NULL  )
                help( SERVER );
            if (  ++argno >= argc  )
                help( SERVER );
            if (  argv[argno][0] == '\0'  )
                help( SERVER );
            host = argv[argno];
        }
        else
        if (  strcmp( argv[argno], "-debug" ) == 0  )
        {
            debug = 1;
        }
        else
        if (  strcmp( argv[argno], "-4" ) == 0  )
        {
            if (  v4only || v6only  )
                help( SERVER );
            v4only = 1;
        }
        else
        if (  strcmp( argv[argno], "-6" ) == 0  )
        {
            if (  v4only || v6only  )
                help( SERVER );
            v6only = 1;
        }
        else
        if (  ( strcmp( argv[argno], "-msgsz" ) == 0 ) ||
              ( strcmp( argv[argno], "-m" ) == 0 )  )
        {
            if (  msgsz != 0  )
                help( SERVER );
            if (  ++argno >= argc  )
                help( SERVER );
            if (  valueConvert( argv[argno], &tmp )  )
                help( SERVER );
            if (  ( tmp < MIN_MSG_SIZE ) ||
                  ( tmp > MAX_MSG_SIZE )  )
                help( SERVER );
            msgsz = (int)tmp;
        }
        else
        if (  ( strcmp( argv[argno], "-conn" ) == 0 ) ||
              ( strcmp( argv[argno], "-c" ) == 0 )  )
        {
            if (  nconn != 0  )
                help( SERVER );
            if (  ++argno >= argc  )
                help( SERVER );
            if (  ! isInteger( 0, argv[argno] )  )
                help( SERVER );
            nconn = atoi( argv[argno] );
            if (  ( nconn < MIN_SRV_CONN ) ||
                  ( nconn > MAX_SRV_CONN )  )
                help( SERVER );
        }
        else
        if (  ( strcmp( argv[argno], "-log" ) == 0 ) ||
              ( strcmp( argv[argno], "-l" ) == 0 )  )
        {
            if (  logpath != NULL  )
                help( SERVER );
            if (  ++argno >= argc  )
                help( SERVER );
            logpath = argv[argno];
            if (  logpath[0] == '\0'  )
                help( SERVER );
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
            help( SERVER );
        argno += 1;
    }

    // Initialise context fields
    if (  msgsz == 0  )
        msgsz = DFLT_SRV_MSG_SIZE;
    if (  nconn == 0  )
        nconn = DFLT_SRV_CONN;

    *ctxt = contextAlloc( TSERVER, ANY, host, port, NULL, msgsz, 0, 0, 0, 0,
                          nconn, v4only, v6only, 0, 0, log, debug );
    if (  *ctxt == NULL  )
    {
        fprintf( stderr, "error: memory allocation failed (context)\n" );
        return 3;
    }

    if (  v4only == v6only  )
        v4only = v6only = 1;
    if (  hostToAddr( host, ports, v4only, v6only, 1, 
                      &((*ctxt)->v4addr),  &((*ctxt)->v6addr) )  )
    {
        fprintf( stderr, "error: invalid host '%s'\n", host );
        return 4;
    }

    if (  stopReceived()  )
        return INTR_EXIT;

    // Verify hostname/addresses refer to the local system
    addr = (*ctxt)->v4addr;
    while (  addr != NULL  )
    {
        sock = socket( addr->ai_family, addr->ai_socktype, addr->ai_protocol );
        if (  sock < 0  )
        {
            fprintf( stderr, "error: socket() failed (1) for address '" );
            printIPv4address( stderr, addr->ai_addr, 1 );
            fprintf( stderr, "' %d (%s)\n", errno, strerror(errno) );
            return 5;
        }
        errno = 0;
        if (  bind( sock, addr->ai_addr, addr->ai_addrlen )  )
        {
            shutdown( sock, SHUT_RDWR );
            close( sock );
            fprintf( stderr, "error: bind() failed (1) for address '" );
            printIPv4address( stderr, addr->ai_addr, 1 );
            fprintf( stderr, "' %d (%s)\n", errno, strerror(errno) );
            return 6;
        }
        shutdown( sock, SHUT_RDWR );
        close( sock );
        addr = addr->ai_next;
        (*ctxt)->naddr += 1;
        (*ctxt)->nv4addr += 1;
    }

    if (  stopReceived()  )
        return INTR_EXIT;

    addr = (*ctxt)->v6addr;
    while (  addr != NULL  )
    {
        sock = socket( addr->ai_family, addr->ai_socktype, addr->ai_protocol );
        if (  sock < 0  )
        {
            fprintf( stderr, "error: socket() failed (2) for address '" );
            printIPv6address( stderr, addr->ai_addr, 1 );
            fprintf( stderr, "' %d (%s)\n", errno, strerror(errno) );
            return 7;
        }
        errno = 0;
        if (  bind( sock, addr->ai_addr, addr->ai_addrlen )  )
        {
            shutdown( sock, SHUT_RDWR );
            close(sock);
            fprintf( stderr, "error: bind() failed (2) for address '" );
            printIPv6address( stderr, addr->ai_addr, 1 );
            fprintf( stderr, "' %d (%s)\n", errno, strerror(errno) );
            return 8;
        }
        shutdown( sock, SHUT_RDWR );
        close( sock );
        addr = addr->ai_next;
        (*ctxt)->naddr += 1;
        (*ctxt)->nv6addr += 1;
    }

    if (  stopReceived()  )
        return INTR_EXIT;

    (*ctxt)->lsocks = (int *)calloc( (*ctxt)->naddr, sizeof( int ) );
    if (  (*ctxt)->lsocks == NULL  )
    {
        fprintf( stderr, "error: memory allocation failed (lsocks)\n" );
        return 9;
    }
    for ( sock = 0; sock < (*ctxt)->naddr; sock++ )
        (*ctxt)->lsocks[sock] = -1;

    (*ctxt)->tbase = getTS( 0 );

    return 0;
} // parseArgsServer

/*
 * Server 'receive message' function.
 */

static int
srvRecvMsg(
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
            if (  ctxt->conn[connid]->peer != NULL  )
            {
                logLock( ctxt );
                printErr( ctxt, 0, "error: %cthread %d/%d lost connection to client '", sr, connid, tno );
                printIPaddress( getStdErr(ctxt), ctxt->conn[connid]->peer, ctxt->conn[connid]->lpeer, 1 );
                fprintf( getStdErr(ctxt), "'\n" );
                logUnlock( ctxt );
            }
            else
                printErr( ctxt, 1, "error: %cthread %d/%d lost connection to client\n", sr, connid, tno );
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
} // srvRecvMsg

/*
 * Sender thread. Async mode only.
 */

static void * 
senderThread(
    void * arg
            )
{
    thread_t   * thread = NULL;
    thread_t   * sthread = NULL;
    conn_t     * conn = NULL;
    context_t  * ctxt = NULL;
    void       * retval = NULL;
    char       * errmsg = NULL;
    int          ret;
    int          maxmsgsz;
    int          msgsz;
    int          datasz;
    int          connid;
    int          tno;
    uint32       sseqno = 0;
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
    maxmsgsz = ctxt->maxmsgsz;
    msgsz = conn->msgsz;
    datasz = msgsz - offsetof( mdata_t, data);

    if (  ctxt->debug  )
        printErr( ctxt, 1, "DEBUG: sender thread %d/%d started\n", connid, tno );

    mdata = (mdata_t *)msgAlloc( thread, MSG_DATA );
    if (  mdata == NULL  )
    {
        printErr( ctxt, 1, "error: Sthread %d/%d unable to allocate MSG_DATA\n",
                  conn->connid, thread->tno );
        retval = (void *)4;
        goto fini;
    }
    mdisc = (mdisc_t *)msgAlloc( thread, MSG_DISC );
    if (  mdisc == NULL  )
    {
        printErr( ctxt, 1, "error: Sthread %d/%d unable to allocate MSG_DISC\n",
                  conn->connid, thread->tno );
        retval = (void *)5;
        goto fini;
    }

    if (  thread->state == STOP  )
        goto fini;

    if (  ctxt->debug  )
        printErr( ctxt, 1, "DEBUG: first send ts = %'lu\n", getTS( 0 ) );
    //  Main message exchange loop
    do {
        // Send a data message
        mdata->hdr.msglen = HTON32( msgsz );
        mdata->hdr.seqno = HTON32( sseqno );
        sseqno++;
        mdata->datasz = HTON32( datasz );
        ret = sendMsg( ctxt, conn->rwsock, (msg_t *)mdata, &errmsg );
        if (  ret < 0  )
        {
            if (  conn->peer != NULL  )
            {
                logLock( ctxt );
                printErr( ctxt, 0, "error: Sthread %d/%d lost connection to client '", connid, tno );
                printIPaddress( getStdErr(ctxt), conn->peer, conn->lpeer, 1 );
                fprintf( getStdErr(ctxt), "'\n" );
                logUnlock( ctxt );
            }
            else
                printErr( ctxt, 1, "error: Sthread %d/%d lost connection to client\n", connid, tno );
            retval = (void *)90;
            goto fini;
        }
        else
        if (  ret > 0  )
        {
            printErr( ctxt, 1, "error: Sthread %d/%d failed to send data message: %d/%s\n",
                      conn->connid, thread->tno, ret, errmsg );
            retval = (void *)((unsigned long)(ret+10));
            goto fini;
        }
    } while (  thread->state != STOP  );

    if (  ctxt->debug  )
        printErr( ctxt, 1, "DEBUG: last send ts = %'lu\n", getTS( 0 ) );

    // Send a disconnection message
    if (  ctxt->debug  )
        printErr( ctxt, 1, "DEBUG: Sthread %d/%d sending MSG_DISC\n", connid, tno );
    mdisc->hdr.seqno = HTON32( sseqno );
    sseqno++;
    ret = sendMsg( ctxt, conn->rwsock, (msg_t *)mdisc, &errmsg );
    if (  ret < 0  )
    {
        printErr( ctxt, 1, "error: Sthread %d/%d lost connection to client\n", connid, tno );
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

fini:
    if (  ctxt->debug  )
        printErr( ctxt, 1, "DEBUG: sender thread %d/%d terminated (%ld)\n", connid, tno, (long)retval );

    if (  mdata != NULL  )
        msgFree( thread, (msg_t **)&mdata );
    if (  mdisc != NULL  )
        msgFree( thread, (msg_t **)&mdisc );
    if (  thread != NULL  )
        thread->state = FINISHED;
    return retval;
} // senderThread

/*
 * Receiver/Control thread.
 */

static void * 
receiverThread(
    void * arg
            )
{
    thread_t   * thread = NULL;
    thread_t   * sthread = NULL;
    conn_t     * conn = NULL;
    context_t  * ctxt = NULL;
    void       * retval = NULL;
    char       * errmsg = NULL;
    int          ret;
    int          maxmsgsz;
    int          msgsz;
    int          datasz;
    int          async = 0;
    int          nodelay = 0;
    int          connid;
    int          tno;
    int          first = 1;
    int          onoff = 0;
    int          tcpmaxseg;
    socklen_t    ltcpmaxseg;
    int          sosndbuf;
    socklen_t    lsosndbuf;
    int          sorcvbuf;
    socklen_t    lsorcvbuf;
    uint32       sbsz = 0;
    uint32       rbsz = 0;
    uint32       sseqno = 0;
    uint32       rseqno = 0;
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
    maxmsgsz = ctxt->maxmsgsz;

    mconnack = (mconnack_t *)msgAlloc( thread, MSG_CONN_ACK );
    if (  mconnack == NULL  )
    {
        printErr( ctxt, 1, "error: Rthread %d/%d unable to allocate MSG_CONN_ACK\n",
                  conn->connid, thread->tno );
        retval = (void *)7;
        goto fini;
    }
    mdiscack = (mdiscack_t *)msgAlloc( thread, MSG_DISC_ACK );
    if (  mdiscack == NULL  )
    {
        printErr( ctxt, 1, "error: Rthread %d/%d unable to allocate MSG_DISC_ACK\n",
                  conn->connid, thread->tno );
        retval = (void *)8;
        goto fini;
    }
    mdataack = (mdataack_t *)msgAlloc( thread, MSG_DATA_ACK );
    if (  mdataack == NULL  )
    {
        printErr( ctxt, 1, "error: Rthread %d/%d unable to allocate MSG_DATA_ACK\n",
                  conn->connid, thread->tno );
        retval = (void *)9;
        goto fini;
    }

    // Receive the client 'connect' message and validate it.
    ret = srvRecvMsg( ctxt, 'R', conn->connid, thread->tno, conn->rwsock, thread->rcvbuff, sizeof( mconn_t ),
                      MSG_CONN, rseqno++ );
    if (  ret  )
    {
        retval = (void *)((unsigned long)(ret+10));
        goto fini;
    }
    if (  thread->state == STOP  )
        goto fini;

    mconn = (mconn_t *)thread->rcvbuff;
    async = mconn->async;
    nodelay = mconn->nodelay;
    msgsz = mconn->msgsz;
    sbsz = mconn->sbsz;
    rbsz = mconn->rbsz;
    datasz = msgsz - offsetof( mdata_t, data);
    conn->msgsz = msgsz;
    conn->nodelay = nodelay;

    // get some info about the connection
    tcpmaxseg = -1;
    ltcpmaxseg = sizeof( tcpmaxseg );
    if (  getsockopt( conn->rwsock, IPPROTO_TCP, TCP_MAXSEG, (void *)&tcpmaxseg, &ltcpmaxseg )  )
        tcpmaxseg = -1;
    sosndbuf = -1;
    lsosndbuf = sizeof( sosndbuf );
    if (  getsockopt( conn->rwsock, SOL_SOCKET, SO_SNDBUF, (void *)&sosndbuf, &lsosndbuf )  )
        sosndbuf = -1;
    sorcvbuf = -1;
    lsorcvbuf = sizeof( sorcvbuf );
    if (  getsockopt( conn->rwsock, SOL_SOCKET, SO_RCVBUF, (void *)&sorcvbuf, &lsorcvbuf )  )
        sorcvbuf = -1;

#if defined(ALLOW_NODELAY)
    // Set the TCP_NODELAY option accordingly
    onoff = ( nodelay == 1 );
    errno = 0;
    if (  setsockopt( conn->rwsock, IPPROTO_TCP, TCP_NODELAY, (void *)&onoff, sizeof( int ) )  )
    {
        printErr( ctxt, 1, "error: Rthread %d/%d setsockopt(...,TCP_NODELAY,...) failed %d (%s)\n",
                  connid, tno, errno, strerror( errno ) );
        retval = (void *)10;
        goto fini;
    }
#endif /* ALLOW_NODELAY */
#if defined(ALLOW_BUFFSIZE)
    if (  sbsz && ( sbsz != sosndbuf )  )
    {
        errno = 0;
        if (  setsockopt( conn->rwsock, SOL_SOCKET, SO_SNDBUF, (void *)&sbsz, sizeof( sbsz ) )  )
        {
            printErr( ctxt, 1, "error: Rthread %d/%d setsockopt(...,SO_SNDBUF,...) failed %d (%s)\n",
                      connid, tno, errno, strerror( errno ) );
            retval = (void *)10;
            goto fini;
        }
        sosndbuf = -1;
        lsosndbuf = sizeof( sosndbuf );
        errno = 0;
        if (  getsockopt( conn->rwsock, SOL_SOCKET, SO_SNDBUF, (void *)&sosndbuf, &lsosndbuf )  )
        {
            printErr( ctxt, 1, "error: Rthread %d/%d getsockopt( ..., SO_SNDBUF, ...) failed %d (%s)\n",
                      connid, tno, errno, strerror( errno ) );
            retval = (void *)10;
            goto fini;
        }
    }
    if (  rbsz && ( rbsz != sorcvbuf )  )
    {
        errno = 0;
        if (  setsockopt( conn->rwsock, SOL_SOCKET, SO_RCVBUF, (void *)&rbsz, sizeof( rbsz ) )  )
        {
            printErr( ctxt, 1, "error: Rthread %d/%d setsockopt(...,SO_RCVBUF,...) failed %d (%s)\n",
                      connid, tno, errno, strerror( errno ) );
            retval = (void *)10;
            goto fini;
        }
        sorcvbuf = -1;
        lsorcvbuf = sizeof( sorcvbuf );
        errno = 0;
        if (  getsockopt( conn->rwsock, SOL_SOCKET, SO_RCVBUF, (void *)&sorcvbuf, &lsorcvbuf )  )
        {
            printErr( ctxt, 1, "error: Rthread %d/%d getsockopt( ..., SO_RCVBUF, ...) failed %d (%s)\n",
                      connid, tno, errno, strerror( errno ) );
            retval = (void *)10;
            goto fini;
        }
    }
#endif /* ALLOW_BUFFSIZE */

    logLock( ctxt );
    printMsg( ctxt, 0, "info: client connected '" );
    printIPaddress( getStdOut(ctxt), conn->peer, conn->lpeer, 1 );
    fprintf( getStdOut(ctxt), "' (conn = %d, %s, msgsz = %d, maxseg = %d, sndbsz = %d, rcvbsz = %d)\n",
             connid, async?"ASYNC":"SYNC", msgsz, tcpmaxseg, sosndbuf, sorcvbuf );
    logUnlock( ctxt );

    // Send the connection ack message
    if (  ctxt->debug  )
        printErr( ctxt, 1, "DEBUG: Rthread %d/%d sending MSG_CONN_ACK\n", connid, tno );
    mconnack->hdr.seqno = HTON32( sseqno );
    sseqno++;
    mconnack->srcats = HTON64( getTS( 0 ) );
    ret = sendMsg( ctxt, conn->rwsock, (msg_t *)mconnack, &errmsg );
    if (  ret < 0  )
    {
        if (  conn->peer != NULL  )
        {
            logLock( ctxt );
            printErr( ctxt, 0, "error: Rthread %d/%d lost connection to client '", connid, tno );
            printIPaddress( getStdErr(ctxt), conn->peer, conn->lpeer, 1 );
            fprintf( getStdErr(ctxt), "'\n" );
            logUnlock( ctxt );
        }
        else
            printErr( ctxt, 1, "error: Rthread %d/%d lost connection to client\n", connid, tno );
        retval = (void *)90;
        goto fini;
    }
    else
    if (  ret > 0  )
    {
        printErr( ctxt, 1, "error: Rthread %d/%d failed to send connect ack message: %d/%s\n",
                  conn->connid, thread->tno, ret, errmsg );
        retval = (void *)((unsigned long)(ret+10));
        goto fini;
    }
    if (  thread->state == STOP  )
        goto fini;

    if (  async  )
    {
        // Create and start the sender thread.
        conn->sender->state = RUNNING;
        ret = pthread_create( &(conn->sender->tid), NULL, senderThread, (void *)conn->sender );
        if (  ret  )
        {
            conn->sender->state = DEFUNCT;
            printErr( ctxt, 1, "error: pthread_create() failed for sender with error %d\n", ret );
            retval = (void *)11;
            goto fini;
        }
        else
        {
            enqueueThread( ctxt, conn->sender );
            sthread = conn->sender;
        }
    }
    if (  thread->state == STOP  )
        goto fini;

    //  Main message exchange loop

    mdata = (mdata_t *)thread->rcvbuff;
    mdisc = (mdisc_t *)thread->rcvbuff;
    do {
        // Receive a message (should be DATA or DISCONNECT)
        ret = srvRecvMsg( ctxt, 'R', conn->connid, thread->tno, conn->rwsock, thread->rcvbuff, ctxt->maxmsgsz,
                          MSG_ANY, rseqno++ );
        if (  ctxt->debug  )
            if (  first  )
            {
                printErr( ctxt, 1, "DEBUG: first recv ts = %'lu\n", getTS( 0 ) );
                first = 0;
            }
        if (  (ret == 0) && (thread->rcvbuff->hdr.msgtype == MSG_DATA)  )
        {
            // Validate
            if (  (msgsz != mdata->hdr.msglen) || (datasz != mdata->datasz)  )
            {
                printErr( ctxt, 1, "error: Rthread %d/%d invalid data size %d/%d\n",
                          conn->connid, thread->tno, (int)mdata->hdr.msglen, (int)mdata->datasz );
                retval = (void *)12;
                goto fini;
            }
            if (  ! async  )
            {
                // Send a data ack
                mdataack->hdr.msglen = HTON32( msgsz );
                mdataack->hdr.seqno = HTON32( sseqno );
                sseqno++;
                mdataack->datasz = HTON32( datasz );
                ret = sendMsg( ctxt, conn->rwsock, (msg_t *)mdataack, &errmsg );
                if (  ret < 0  )
                {
                    if (  conn->peer != NULL  )
                    {
                        logLock( ctxt );
                        printErr( ctxt, 0, "error: Rthread %d/%d lost connection to client '", connid, tno );
                        printIPaddress( getStdErr(ctxt), conn->peer, conn->lpeer, 1 );
                        fprintf( getStdErr(ctxt), "'\n" );
                        logUnlock( ctxt );
                    }
                    else
                        printErr( ctxt, 1, "error: Rthread %d/%d lost connection to client\n", connid, tno );
                    retval = (void *)90;
                    goto fini;
                }
                else
                if (  ret > 0  )
                {
                    printErr( ctxt, 1, "error: Rthread %d/%d failed to send data ack message: %d/%s\n",
                              conn->connid, thread->tno, ret, errmsg );
                    retval = (void *)((unsigned long)(ret+10));
                    goto fini;
                }
            }
        }
        if (  thread->state == STOP  )
            goto fini;
    } while (  (ret == 0) && (thread->rcvbuff->hdr.msgtype == MSG_DATA)  );

    if (  ctxt->debug  )
        printErr( ctxt, 1, "DEBUG: last recv ts = %'lu\n", getTS( 0 ) );
    if (  ret  )
    {
        retval = (void *)((unsigned long)ret);
        goto fini;
    }
    if (  thread->state == STOP  )
        goto fini;

    // Check the last message was a client 'disconnect' message.
    if (  thread->rcvbuff->hdr.msgtype != MSG_DISC  )
    {
        printErr( ctxt, 1, "error: Rthread %d/%d unexpected message type %d\n",
                  conn->connid, thread->tno, (int)thread->rcvbuff->hdr.msgtype );
        retval = (void *)13;
        goto fini;
    }

    // stop the sender thread
    if (  async && ( sthread != NULL )  )
    {
        sthread->state = STOP;
        if  (  waitforThread( sthread, FINISHED, 5 )  )
        {
            printErr( ctxt, 1, "error: Rthread %d/%d failed to stop sender thread\n",
                      conn->connid, thread->tno );
            retval = (void *)14;
            goto fini;
        }
        sthread = NULL;
    }

    // Send the disconnection ack message
    if (  ctxt->debug  )
        printErr( ctxt, 1, "DEBUG: Rthread %d/%d sending MSG_DISC_ACK\n", connid, tno );
    mdiscack->hdr.seqno = HTON32( sseqno );
    sseqno++;
    ret = sendMsg( ctxt, conn->rwsock, (msg_t *)mdiscack, &errmsg );
    if (  ret < 0  )
    {
        if (  conn->peer != NULL  )
        {
            logLock( ctxt );
            printErr( ctxt, 0, "error: Rthread %d/%d lost connection to client '", connid, tno );
            printIPaddress( getStdErr(ctxt), conn->peer, conn->lpeer, 1 );
            fprintf( getStdErr(ctxt), "'\n" );
            logUnlock( ctxt );
        }
        else
            printErr( ctxt, 1, "error: Rthread %d/%d lost connection to client\n", connid, tno );
        retval = (void *)90;
        goto fini;
    }
    else
    if (  ret > 0  )
    {
        printErr( ctxt, 1, "error: Rthread %d/%d failed to send disconnect ack message: %d/%s\n",
                  conn->connid, thread->tno, ret, errmsg );
        retval = (void *)((unsigned long)(ret+10));
        goto fini;
    }

    logLock( ctxt );
    printMsg( ctxt, 0, "info: client disconnected '" );
    printIPaddress( getStdOut(ctxt), conn->peer, conn->lpeer, 1 );
    fprintf( getStdOut(ctxt), "' (conn = %d)\n", connid );
    logUnlock( ctxt );

fini:
    if (  async && ( sthread != NULL )  )
    {
        sthread->state = STOP;
        waitforThread( sthread, FINISHED, 5 );
    }
    if (  mconnack != NULL  )
        msgFree( thread, (msg_t **)&mconnack );
    if (  mdiscack != NULL  )
        msgFree( thread, (msg_t **)&mdiscack );
    if (  mdataack != NULL  )
        msgFree( thread, (msg_t **)&mdataack );
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
} // receiverThread

/*
 * Checks the run queue for terminated threads and cleans them up.
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
        return; // something i badly wrong!

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
        //if (  (thread->state == FINISHED) || pthread_kill(thread->tid,0)  )
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
    int               cltsock,
    struct sockaddr * cltaddr,
    socklen_t         lcltaddr
           )
{
    int ret = 0;
    conn_t * conn = NULL;
    struct timeval rcvto = { MAX_MSG_WAIT, 0 };
    struct timeval sndto = { MAX_MSG_WAIT, 0 };

    if (  (ctxt == NULL) || (connid < 0) || (cltsock < 0) || (cltaddr == NULL) ||
          ( (lcltaddr != sizeof(struct sockaddr_in)) && 
            (lcltaddr != sizeof(struct sockaddr_in6)) )  )
        return -1;

    // iniialise / reset fields
    conn = ctxt->conn[connid];
    memcpy( (void *)(conn->peer), (void *)cltaddr, (size_t)lcltaddr );
    conn->lpeer = lcltaddr;
    conn->v6peer = ( lcltaddr == sizeof(struct sockaddr_in6) );
    conn->error = NULL;
    conn->rwsock = cltsock;
    if (  setsockopt( conn->rwsock, SOL_SOCKET, SO_RCVTIMEO, (void *)&rcvto, sizeof( struct timeval ) ) ||
          setsockopt( conn->rwsock, SOL_SOCKET, SO_SNDTIMEO, (void *)&sndto, sizeof( struct timeval ) )  )
    {
        conn->receiver->state = DEFUNCT;
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

    // Create and start the receiver thread.

    conn->receiver->state = RUNNING;
    ret = pthread_create( &(conn->receiver->tid), NULL, receiverThread, (void *)conn->receiver );
    if (  ret  )
    {
        conn->receiver->state = DEFUNCT;
        shutdown( conn->rwsock, SHUT_RDWR );
        close( conn->rwsock );
        conn->rwsock = -1;
        conn->busy = 0;
        printErr( ctxt, 1, "error: pthread_create() failed with error %d\n", ret );
    }
    else
        enqueueThread( ctxt, conn->receiver );

    return ret;
} //handoffConn

/******************************************************************************
 * Public functions
 */

/*
 * process the server sub-command
 */

int
cmdServer(
    int    argc,
    char * argv[]
         )
{
    context_t * ctxt = NULL;
    struct addrinfo * addr = NULL;
    int cltsock;
    int ret = 0;
    int sno = 0;
    int finished = 0;
    int one = 1;
#if 0
    int tcpmaxseg;
    socklen_t ltcpmaxseg;
    int sosndbuf;
    socklen_t lsosndbuf;
    int sorcvbuf;
    socklen_t lsorcvbuf;
#endif
    int nready;
    int connid;
    fd_set lfds;
    struct timeval stout;
    unsigned char sabuff[sizeof(struct sockaddr_in6)];
    struct sockaddr * cltaddr = (struct sockaddr *)sabuff;
    socklen_t lcltaddr = 0;
    thread_t * thread = NULL;

    // setup signal handlers
    if (  handleSignals()  )
    {
        fprintf( stderr, "error: unable to setup signal handlers\n" );
        ret = 20;
        goto fini;
    }

    // parse command line arguments, initialise context
    ret = parseArgsServer( argc, argv, &ctxt );
    if (  ret  )
        goto fini;

    // Create and bind listening sockets, set up fd set for select()
    ctxt->maxsocket = 0;

    addr = ctxt->v4addr;
    while (  addr != NULL  )
    {
        if (  ctxt->debug  )
        {
            printErr( ctxt, 0, "DEBUG: setting up listen socket for '" );
            printIPaddress( getStdErr(ctxt), addr->ai_addr, addr->ai_addrlen, 1 );
            fprintf( getStdErr(ctxt), "'\n" );
        }
        errno = 0;
        ctxt->lsocks[sno] = socket( addr->ai_family, addr->ai_socktype, addr->ai_protocol );
        if (  ctxt->lsocks[sno] < 0  )
        {
            printErr( ctxt, 0, "error: unable to create socket for address '" );
            printIPv4address( getStdErr(ctxt), addr->ai_addr, 1 );
            fprintf( getStdErr(ctxt), "'\n" );
            ret = 21;
            goto fini;
        }
        if (  ctxt->lsocks[sno] > ctxt->maxsocket  )
            ctxt->maxsocket = ctxt->lsocks[sno];
        errno = 0;
        if (  bind( ctxt->lsocks[sno], addr->ai_addr, addr->ai_addrlen )  )
        {
            printErr( ctxt, 0, "error: bind() failed (3/fd=%d) for address '", ctxt->lsocks[sno] );
            printIPv4address( getStdErr(ctxt), addr->ai_addr, 1 );
            fprintf( getStdErr(ctxt), "' %d (%s)\n", errno, strerror(errno) );
            shutdown( ctxt->lsocks[sno], SHUT_RDWR );
            close( ctxt->lsocks[sno] );
            ctxt->lsocks[sno] = -1;
            ret = 22;
            goto fini;
        }
        errno = 0;
        if (  listen( ctxt->lsocks[sno], LISTEN_BACKLOG )  )
        {
            printErr( ctxt, 0, "error: listen() failed (fd=%d) for address '", ctxt->lsocks[sno] );
            printIPv4address( getStdErr(ctxt), addr->ai_addr, 1 );
            fprintf( getStdErr(ctxt), "'\n" );
            shutdown( ctxt->lsocks[sno], SHUT_RDWR );
            close( ctxt->lsocks[sno] );
            ctxt->lsocks[sno] = -1;
            ret = 23;
            goto fini;
        }
        FD_SET( ctxt->lsocks[sno], &(ctxt->lfds) );
        addr = addr->ai_next;
        sno += 1;
    }

    if (  stopReceived()  )
    {
        ret = INTR_EXIT;
        goto fini;
    }

    addr = ctxt->v6addr;
    while (  addr != NULL  )
    {
        if (  ctxt->debug  )
        {
            printErr( ctxt, 0, "DEBUG: setting up listen socket for '" );
            printIPaddress( getStdErr(ctxt), addr->ai_addr, addr->ai_addrlen, 1 );
            fprintf( getStdErr(ctxt), "'\n" );
        }
        errno = 0;
        ctxt->lsocks[sno] = socket( addr->ai_family, addr->ai_socktype, addr->ai_protocol );
        if (  ctxt->lsocks[sno] < 0  )
        {
            printErr( ctxt, 0, "error: unable to create socket for address '" );
            printIPv6address( getStdErr(ctxt), addr->ai_addr, 1 );
            fprintf( getStdErr(ctxt), "'\n" );
            ret = 24;
            goto fini;
        }
        if (  ctxt->lsocks[sno] > ctxt->maxsocket  )
            ctxt->maxsocket = ctxt->lsocks[sno];
#if defined( IPV6_V6ONLY )
        errno = 0;
        if (  setsockopt( ctxt->lsocks[sno], IPPROTO_IPV6, IPV6_V6ONLY, (void*) &one, sizeof(one))  )
        {
            printErr( ctxt, 0, "error: setsockopt(...,IPV6_V6ONLY,...) failed for address '" );
            printIPv6address( getStdErr(ctxt), addr->ai_addr, 1 );
            fprintf( getStdErr(ctxt), "'\n" );
            ret = 25;
            goto fini;
        }
#endif /* IPV6_V6ONLY */
        errno = 0;
        if (  bind( ctxt->lsocks[sno], addr->ai_addr, addr->ai_addrlen )  )
        {
            printErr( ctxt, 0, "error: bind() failed (4/fd=%d) for address '", ctxt->lsocks[sno] );
            printIPv6address( getStdErr(ctxt), addr->ai_addr, 1 );
            fprintf( getStdErr(ctxt), "' %d (%s)\n", errno, strerror(errno) );
            shutdown( ctxt->lsocks[sno], SHUT_RDWR );
            close( ctxt->lsocks[sno] );
            ctxt->lsocks[sno] = -1;
            ret = 26;
            goto fini;
        }
        errno = 0;
        if (  listen( ctxt->lsocks[sno], LISTEN_BACKLOG )  )
        {
            printErr( ctxt, 0, "error: listen() failed (fd=%d) for address '", ctxt->lsocks[sno] );
            printIPv6address( getStdErr(ctxt), addr->ai_addr, 1 );
            fprintf( getStdErr(ctxt), "'\n" );
            shutdown( ctxt->lsocks[sno], SHUT_RDWR );
            close( ctxt->lsocks[sno] );
            ctxt->lsocks[sno] = -1;
            ret = 27;
            goto fini;
        }
        FD_SET( ctxt->lsocks[sno], &(ctxt->lfds) );
        addr = addr->ai_next;
        sno += 1;
    }

    if (  stopReceived()  )
    {
        ret = INTR_EXIT;
        goto fini;
    }

    ctxt->maxsocket += 1;

    if (  stopReceived()  )
    {
        ret = INTR_EXIT;
        goto fini;
    }

    // Output server summary
#if defined(ALLOW_NODELAY)
    printMsg( ctxt, 0, "info: %s version %s, max message size = %d, max connections = %d, TCP_NODELAY supported\n",
              PROGNAME, VERSION, ctxt->maxmsgsz, ctxt->nconn );
#else /* ! ALLOW_NODELAY */
    printMsg( ctxt, 0, "info: version %s, max message size = %d, max connections = %d\n",
              VERSION, ctxt->maxmsgsz, ctxt->nconn );
#endif /* ! ALLOW_NODELAY */
    addr = ctxt->v4addr;
    while (  addr != NULL  )
    {
        printMsg( ctxt, 0, "info: listening on '" );
        printIPv4address( getStdOut(ctxt), addr->ai_addr, 1 );
        fprintf( getStdOut(ctxt), "'\n" );
        addr = addr->ai_next;
    }
    addr = ctxt->v6addr;
    while (  addr != NULL  )
    {
        printMsg( ctxt, 0, "info: listening on '" );
        printIPv6address( getStdOut(ctxt), addr->ai_addr, 1 );
        fprintf( getStdOut(ctxt), "'\n" );
        addr = addr->ai_next;
    }

    // Main event loop; accept connection, hand off to a dedicated connection
    while (  ! finished  )
    {
        if (  stopReceived()  )
        {
            ret = INTR_EXIT;
            finished = 1;
            continue;
        }

        // Reap any terminated threads
        threadReaper( ctxt );

        // Wait for incoming connection(s)
        FD_COPY( &(ctxt->lfds), &lfds );
        stout.tv_sec = 1;
        stout.tv_usec = 0;
        nready = select( ctxt->maxsocket, &lfds, NULL, NULL, &stout );
        if (  nready <= 0  ) // no connection; signal or timeout
            continue;

        // Accept the connection(s)
        for ( sno = 0; sno < ctxt->naddr; sno++ )
        {
            if (  stopReceived()  )
            {
                ret = INTR_EXIT;
                finished = 1;
                break;
            }

            if (  ! FD_ISSET( ctxt->lsocks[sno], &lfds )  )
                continue;

            lcltaddr = sizeof(sabuff);
            cltsock = accept( ctxt->lsocks[sno], cltaddr, &lcltaddr );
            connid = getConnection( ctxt );
            if (  connid < 0  )
            {
                shutdown( cltsock, SHUT_RDWR );
                close( cltsock );
                printErr( ctxt, 1, "error: no free connection to handle request from client - rejected\n" );
                continue;
            }

#if 0
            // get some info about the connection 
            tcpmaxseg = -1;
            ltcpmaxseg = sizeof( tcpmaxseg );
            if (  getsockopt( cltsock, IPPROTO_TCP, TCP_MAXSEG, (void *)&tcpmaxseg, &ltcpmaxseg )  )
                tcpmaxseg = -1;
            sosndbuf = -1;
            lsosndbuf = sizeof( sosndbuf );
            if (  getsockopt( cltsock, SOL_SOCKET, SO_SNDBUF, (void *)&sosndbuf, &lsosndbuf )  )
                sosndbuf = -1;
            sorcvbuf = -1;
            lsorcvbuf = sizeof( sorcvbuf );
            if (  getsockopt( cltsock, SOL_SOCKET, SO_RCVBUF, (void *)&sorcvbuf, &lsorcvbuf )  )
                sorcvbuf = -1;

            logLock( ctxt );
            printMsg( ctxt, 0, "info: client connected '" );
            printIPaddress( getStdOut(ctxt), cltaddr, lcltaddr, 1 );
            fprintf( getStdOut(ctxt), "' (conn = %d, maxseg = %d, sndbsz = %d, rcvbsz = %d)\n",
                     connid, tcpmaxseg, sosndbuf, sorcvbuf );
            logUnlock( ctxt );
#endif

            if (  handoffConn( ctxt, connid, cltsock, cltaddr, lcltaddr ) < 0  )
            {
                shutdown( cltsock, SHUT_RDWR );
                close( cltsock );
                ctxt->conn[connid]->busy = 0;
                printErr( ctxt, 1, "error: internal: NULL invalid parameters passed to handoffConn()\n" );
                continue;
            }
        }
    } // main loop

fini:
    if (  ctxt != NULL  )
    {
        thread = ctxt->runqhead;
        while (  thread != NULL  )
        {
            waitforThread( thread, FINISHED, 3 );
            if (  ( thread->state != FINISHED ) && ( thread->state != DEFUNCT )  )
                thread->state = STOP;
            thread = thread->next;
            waitforThread( thread, FINISHED, 3 );
        }
        sleep( 1 );
        threadReaper( ctxt );
        if (  ctxt->lsocks != NULL  )
            for ( sno = 0; sno < ctxt->naddr; sno++ )
                if (  ctxt->lsocks[sno] >= 0  )
                {
                    shutdown( ctxt->lsocks[sno], SHUT_RDWR );
                    close( ctxt->lsocks[sno] );
                    ctxt->lsocks[sno] = -1;
                }
    }
    return ret;
} // cmdServer

