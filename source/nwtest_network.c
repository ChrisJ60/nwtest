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
#include <errno.h>
#if !defined(WINDOWS)
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#else
#include "Ws2tcpip.h"
#endif

#include <nwtest.h>

/******************************************************************************
 * Data
 */

static char * validIPv6chars = "0123456789ABCDEFabcdef";

/******************************************************************************
 * Private functions
 */

/*
 * Initialise network library (if required)
 */

static int
nwinit(void)
{
volatile static int initdone = 0;
    int      wserr = 0;

    if (  initdone  )
        return wserr;
#if defined(WINDOWS)
    WORD     wVersionRequested;
    WSADATA  wsaData;

    wVersionRequested = MAKEWORD( 2, 0 );

    wserr = WSAStartup( wVersionRequested, &wsaData );
#endif /* WINDOWS */

    if (  wserr == 0  )
        initdone = 1;
    return wserr;
} // nwinit

/*
 * Deinitialise network library (if required)
 */

static void
nwcleanup(void)
{
#if defined(WINDOWS)
    WSACleanup();
#endif /* WINDOWS */
} // nwcleanup

/*
 *  Internal low level 'receive' function.
 */

static int
mRecv(
    int    sock,
    void * buff,
    int    rcvlen
     )
{
    char * dptr = (char *) buff;
    int ret, serrno;

    do {
        errno = 0;
        ret = recv( sock, (void *)dptr, rcvlen, MSG_WAITALL );
        serrno = errno;
        if (  ret == rcvlen  )
        {
            ret = 0;
            break;
        }
        else
        if (  ret < 0  ) // error
        {
            if (  (serrno != EAGAIN) && (serrno != EWOULDBLOCK)  )
                return 1;
            if (  serrno == ECONNRESET  )
                return -1;
            ret = 0;
        }
        else
        if (  ret == 0  )
        {
            if (  serrno == ECONNRESET  )
                return -1;
            if (  (serrno != EAGAIN) && (serrno != EWOULDBLOCK)  )
                return 2;
        }
        else
        if (  ret > rcvlen  )
            return 3;

        dptr += ret;
        rcvlen -= ret;
    } while (  dptr != NULL  );

    return ret;
} // mRecv


/******************************************************************************
 * Public functions
 */

#if defined(SOLARIS) || defined(WINDOWS)
/*
 * The 'strsep' function for platforms that don't have it.
 */

char *
strsep(
       char **stringp,
       const char *delim
      )
{
    char * str, * p, * d;

    if (  (stringp == NULL) || (*stringp == NULL) ||
          (delim == NULL) || (*delim == '\0')  )
        return NULL;

    p = str = *stringp;
    while (  *p  )
    {
        if (  strchr(delim, (int)*p) != NULL  )
            break;
        p++;
    }
    if (  *p  )
    {
        *p++ = '\0';
        *stringp = p;
    }
    else
        *stringp = NULL;

    return str;
} /* strsep */
#endif /* SOLARIS || WINDOWS */

/*
 * Send a message on a socket.
 */

int
sendMsg(
    context_t * ctxt,
    int         sock,
    msg_t     * msg,
    char     ** errmsg
       )
{
    int ret = 0;
    int nbytes = 0;
    char * dptr = NULL;
    uint32 sndlen;

    if (  (ctxt == NULL) || (sock < 0) || (msg == NULL)  )
    {
        if (  errmsg != NULL  )
            *errmsg = "internal: invalid parameter passed to sendMsg()";
        return 1;
    }
    sndlen = NTOH32( msg->hdr.msglen );
    msg->hdr.ts = HTON32( (uint32)getTS( ctxt->tbase ) );
    dptr = (char *)msg;
    
    // send the message
    do {
        errno = 0;
        ret = send( sock, (void *)dptr, sndlen, 0 );
        if (  ( ctxt->debug ) && ( ( ret < 0) || ( errno != 0 ) )  )
            printErr( ctxt, 1, "DEBUG: send() returned %d / %d (%s)\n", ret, errno, errno?strerror(errno):"Success" );
        if (  (ret == 0) || (errno == ECONNRESET) || (errno == EPIPE) || (errno == EPROTOTYPE)  )
        {
            if (  errmsg != NULL  )
                *errmsg = "connection reset";
            return -1;
        }
        else
        if (  ret < 0  ) // error
        {
            if (  errno != EAGAIN  )
            {
                if (  errmsg != NULL  )
                    *errmsg = "send() returned an error";
                return 2;
            }
            ret = 0;
        }
        nbytes = ret;
        if (  nbytes > sndlen  )
        {
            if (  errmsg != NULL  )
                *errmsg = "long send";
            return 4;
        }
        if (  nbytes == sndlen  )
            dptr = NULL;
        else
        {
            dptr += nbytes;
            sndlen -= nbytes;
        }
    } while (  dptr != NULL  );
    
    return 0;
} // sendMsg

/*
 * Receive a message on a socket.
 */

int
recvMsg(
    context_t * ctxt,
    int         sock,
    msg_t     * msg,
    int         maxsz,
    char     ** errmsg
       )
{
    int ret = 0;
    int msz;
    uint32 msglen;
    uint32 secret;
    uint32 ts;
    uint32 seqno;
    uint8 msgtype;

    if (  (ctxt == NULL) || (sock < 0) || (msg == NULL) || (maxsz < sizeof(msghdr_t))  )
    {
        if (  errmsg != NULL  )
            *errmsg = "internal: invalid parameter passed to recvMsg()";
        return 1;
    }

    // receive the message header
    ret = mRecv( sock, (void *)&(msg->hdr), sizeof( msghdr_t ) );
    if (  ret < 0  )
    {
        *errmsg = "connection reset";
        return -1;
    }
    else
    if (  ret > 0  )
    {
        if (  errno  )
        {
            if (  errmsg != NULL  )
                *errmsg = strerror( errno );
        }
        else
        {
            if (  errmsg != NULL  )
                *errmsg = "long receive (header)";
        }
        return ret;
    }

    // Convert values to host representation
    msglen = NTOH32( msg->hdr.msglen );
    msg->hdr.msglen = msglen;
    secret = NTOH32( msg->hdr.secret );
    msg->hdr.secret = secret;
    ts = NTOH32( msg->hdr.ts );
    msg->hdr.ts = ts;
    seqno = NTOH32( msg->hdr.seqno );
    msg->hdr.seqno = seqno;
    msgtype = NTOH8( msg->hdr.msgtype );
    msg->hdr.msgtype = msgtype;

    // Validate header values
    if (  (msglen > maxsz) || (secret != SECRET) ||
          ! validMsgType( msgtype )  )
    {
        if (  errmsg != NULL  )
            *errmsg = "invalid message header";
        return 4;
    }
    msz = getMsgSize( ctxt, msgtype );
    if (  (msgtype == MSG_DATA) || (msgtype == MSG_DATA_ACK)  )
    {
        if (  msglen > msz  )
        {
            if (  errmsg != NULL  )
                *errmsg = "invalid message length (data/dataack)";
            return 5;
        }
    }
    else
    if (  msglen != msz  )
    {
        if (  errmsg != NULL  )
            *errmsg = "invalid message length (control)";
        return 5;
    }
    msglen -= sizeof( msghdr_t );

    // All good, now try to receive the body of the message (if any)
    if (  msglen > 0  )
    {
        ret = mRecv( sock, (void *)&(msg->data), msglen );
        if (  ret < 0  )
        {
            *errmsg = "connection reset";
            return -1;
        }
        else
        if (  ret > 0  )
        {
            if (  errno  )
            {
                if (  errmsg != NULL  )
                    *errmsg = strerror( errno );
            }
            else
            {
                if (  errmsg != NULL  )
                    *errmsg = "long receive (header)";
            }
            return ret;
        }

        // Convert message specific values to host representation
        switch (  msgtype  )
        {
            case MSG_CONN:
                {
                    mconn_t * mconn = (mconn_t *)msg;
                    uint8 async = NTOH8( mconn->async );
                    mconn->async = async;
                    uint32 msgsz = NTOH32( mconn->msgsz );
                    mconn->msgsz = msgsz;
                    uint32 sbsz = NTOH32( mconn->sbsz );
                    mconn->sbsz = sbsz;
                    uint32 rbsz = NTOH32( mconn->rbsz );
                    mconn->rbsz = rbsz;
                    uint64 srcats = NTOH64( mconn->srcats );
                    mconn->srcats = srcats;
                }
                break;
            case MSG_CONN_ACK:
                {
                    mconnack_t * mconnack = (mconnack_t *)msg;
                    uint64 srcats = NTOH64( mconnack->srcats );
                    mconnack->srcats = srcats;
                }
                break;
            case MSG_DATA:
                {
                    mdata_t * mdata = (mdata_t *)msg;
                    uint32 datasz = NTOH32( mdata->datasz );
                    mdata->datasz = datasz;
                }
                break;
            case MSG_DATA_ACK:
                {
                    mdataack_t * mdataack = (mdataack_t *)msg;
                    uint32 datasz = NTOH32( mdataack->datasz );
                    mdataack->datasz = datasz;
                }
                break;
            default:
                if (  errmsg != NULL  )
                    *errmsg = "unexpected payload";
                return 8;
                break;
        }
    }

    return 0;
} // recvMsg

/*
 * Create a (dynamically allocated) deep copy of a 'struct addrinfo'.
 */

struct addrinfo *
copyAddrInfo(
    struct addrinfo * addr
            )
{
    struct addrinfo * naddr = NULL;

    if (  addr == NULL  )
        goto err;
    naddr = (struct addrinfo *)calloc( 1, sizeof( struct addrinfo ) );
    if (  naddr == NULL  )
        goto err;

    *naddr = *addr; // top level copy
    naddr->ai_next = NULL;

    if (  addr->ai_canonname != NULL  )
    {
        naddr->ai_canonname = strdup( addr->ai_canonname );
        if (  naddr->ai_canonname == NULL  )
            goto err;
    }

    if (  addr->ai_addr != NULL  )
    {
        naddr->ai_addr = (struct sockaddr *)calloc( 1, addr->ai_addrlen );
        if (  naddr->ai_addr == NULL  )
            goto err;
        memcpy( naddr->ai_addr, addr->ai_addr, addr->ai_addrlen );
    }

    goto fini;

err:
    if (  naddr == NULL  )
        goto fini;
    if (  naddr->ai_addr != NULL  )
    {
        free( (void *)naddr->ai_addr );
        naddr->ai_addr = NULL;
    }
    if (  naddr->ai_canonname != NULL  )
    {
        free( (void *)naddr->ai_canonname );
        naddr->ai_canonname = NULL;
    }
    free( (void *)naddr );
    naddr = NULL;

fini:
    return naddr;
}

/*
 * Print an IPv4 address.
 */

void
printIPv4address(
    FILE *f,
    struct sockaddr *addr4,
    int full
                )
{
    unsigned char * addr;
    int adbyte, port,  i;

    if (  (f != NULL) && (addr4 != NULL)  )
    {
        addr = (unsigned char *)&(addr4->sa_data[2]);
        for (i=0; i<3; i++)
        {
            adbyte = (int)*addr++;
            fprintf( f, "%d.", adbyte );
        }
        adbyte = (int)*addr++;
        fprintf( f, "%d", adbyte );
        if (  full )
        {
            port = (int)NTOH16( *((uint16_t *)&(addr4->sa_data[0])) );
            if (  port  )
                fprintf( f, ":%d", port );
        }
    }
} // printIPv4address

/*
 * Print an IPv6 address.
 */

void
printIPv6address(
    FILE *f,
    struct sockaddr *addr6,
    int full
                )
{
    int advalue, port = 0, i;
    int zrl = 0, zrlm = 0, zrls = -1, zrle = -1;
    unsigned char * addr;
    unsigned char * p;
    char colon[2];

    if (  (f != NULL) && (addr6 != NULL)  )
    {
        addr = (unsigned char *)&(addr6->sa_data[6]);
        p = addr + 15;
        if (  full )
            port = (int)NTOH16( *((uint16_t *)&(addr6->sa_data[0])) );
        if (  port  )
            fprintf( f, "[" );
        for (i=7; i>=0; i--)
        {
            advalue = (int)*p--;
            advalue += (256 * (int)*p--);
            if (  advalue == 0  )
                zrl++;
            else
            {
                if (  zrl  )
                {
                    if (  (zrl > 1) && (zrl >= zrlm)  )
                    {
                        zrls = i + 1;
                        zrlm = zrl;
                    }
                    zrl = 0;
                }
            }
        }
        if (  zrl  )
        {
            if (  (zrl > 1) && (zrl >= zrlm)  )
            {
                zrls = i + 1;
                zrlm = zrl;
            }
            zrl = 0;
        }
        if (  zrlm  )
        {
            zrle = zrls + zrlm - 1;
            strcpy(colon,":");
        }
        for (i=0; i<7; i++)
        {
            advalue = (256 * (int)*addr++);
            advalue += (int)*addr++;
            if ( ! zrlm )
                fprintf( f, "%x:", advalue );
            else
            if ( advalue || (i < zrls) || (i > zrle) )
                fprintf( f, "%x:", advalue );
            else
            {
                fprintf( f, "%s", colon );
                if ( i )
                    colon[0] = '\0';
            }
        }
        advalue = (256 * (int)*addr++);
        advalue += (int)*addr++;
        if ( ! zrlm )
            fprintf( f, "%x", advalue );
        else
        if ( advalue || (i < zrls) || (i > zrle) )
            fprintf( f, "%x", advalue );
        else
            fprintf( f, "%s", colon );
        if (  port  )
            fprintf( f, "]:%d", port );
    }
} // printIPv6address

/*
 * Print an IPv4 or an IPv6 address.
 */

void
printIPaddress(
    FILE *f,
    struct sockaddr *addr,
    socklen_t laddr,
    int full
              )
{
    if (  (f != NULL) && (addr != NULL)  )
        switch ( laddr  )
        {
            case sizeof( struct sockaddr_in ):
                printIPv4address( f, addr, full );
                break;
            case sizeof( struct sockaddr_in6 ):
                printIPv6address( f, addr, full );
                break;
            default:
                break;
        }
} // printIPAddress

/*
 * Check if a string is a valid IPv4 address.
 */

int
isIPv4Address(
    char * s
             )
{
    char * freeptr, * addr, * p, * p2;
    int i, l;
    long n;

    addr = strdup(s);
    if (  addr == NULL  )
        return 0;
    freeptr = addr;

    for (i = 0; i < 3; i++)
    {
        p = strsep( &addr, "." );
        if (  p == NULL  )
        {
            free( (void *)freeptr );
            return 0;
        }
        l = strlen(p);
        if (  (l < 1) || (l > 3)  )
        {
            free( (void *)freeptr );
            return 0;
        }
        n = strtol(p, &p2, 10);
        if (  *p2 || (n < 0) || (n > 255)  )
        {
            free( (void *)freeptr );
            return 0;
        }
    }

    free( (void *)freeptr );

    return 1;
} // isIPv4Address

/*
 * Check if a string is a valid IPv4 address.
 */

int
isIPv6Address(
    char * s
             )
{
    char * freeptr, * addr, * p, * p2;
    int i, l, n = 0;

    addr = strdup(s);
    if (  addr == NULL  )
        return 0;
    freeptr = addr;

    while (  (p = strsep(&addr,":")) != NULL  )
    {
        n++;
        l = strlen(p);
        if ( l > 4  )
        {
            free( (void *)freeptr );
            return 0;
        }
        while ( *p  )
            if (  strchr(validIPv6chars, (int)*p++) == NULL  )
            {
                free( (void *)freeptr );
                return 0;
            }
    }
    if (  (n < 3) || (n > 8)  )
    {
        free( (void *)freeptr );
        return 0;
    }

    free( (void *)freeptr );

    return 1;
} // isIPv6Address

/*
 * Check if a string is a valid IP address.
 */

int
isIPAddress(
    char * s
           )
{
    return isIPv4Address(s) || isIPv6Address(s);
} // isIPAddress

/*
 * Convert a hostname and/or a service name to a list of
 * address structures that can be used either for listen()
 * or connect().
 */

int
hostToAddr(
           char * hostname,
           char * servname,
           int    v4,
           int    v6,
           int    listen,
           struct addrinfo ** v4addr,
           struct addrinfo ** v6addr
          )
{
    struct addrinfo * haddr = NULL, * caddr = NULL, gaihints;
    struct addrinfo * lv4 = NULL, * lv6 = NULL, * taddr;
    int ret = -1;
    char hostnm[NI_MAXHOST+1];

    if (  (v4addr == NULL) || (v6addr == NULL)  )
        return ret;
    if (  (hostname == NULL) && (servname == NULL)  )
        return ret;
    if (  (hostname == NULL) && ! listen  )
        return ret;

    *v4addr = NULL;
    *v6addr = NULL;

    if (  nwinit()  )
        return ret;

    memset( (void *)&gaihints, 0, sizeof(struct addrinfo) );
    gaihints.ai_family = PF_UNSPEC;
    gaihints.ai_protocol = IPPROTO_TCP;
    gaihints.ai_flags = AI_ADDRCONFIG;
    if (  (hostname != NULL) && isIPAddress( hostname )  )
        gaihints.ai_flags |= AI_NUMERICHOST;
    if (  listen  )
        gaihints.ai_flags |= AI_PASSIVE;

    if (  getaddrinfo( hostname, servname, &gaihints, &haddr )  )
        return ret;

    /* get addresses */
    ret = 1;
    caddr = haddr;
    while (  caddr != NULL  )
    {
        if (  v4 && (caddr->ai_family == PF_INET)  ) // IPv4
        {
            taddr = copyAddrInfo( caddr );
            if (  taddr == NULL  )
                goto err;
            ret = 0;
            if (  lv4 == NULL  )
                *v4addr = taddr;
            else
                lv4->ai_next = taddr;
            lv4 = taddr;
        }
        else
        if (  v6 && (caddr->ai_family == PF_INET6)  ) // IPv6
        {
            taddr = copyAddrInfo( caddr );
            if (  taddr == NULL  )
                goto err;
            ret = 0;
            if (  lv6 == NULL  )
                *v6addr = taddr;
            else
                lv6->ai_next = taddr;
            lv6 = taddr;
        }
        caddr = caddr->ai_next;
    }

    goto fini;

err:
    if (  *v4addr != NULL  )
    {
        freeaddrinfo( *v4addr );
        *v4addr = NULL;
    }
    if (  *v6addr != NULL  )
    {
        freeaddrinfo( *v6addr );
        *v6addr = NULL;
    }

fini:
    freeaddrinfo( haddr );
    return ret;
} // hostToAddr

