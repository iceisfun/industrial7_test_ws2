/* Shared helpers for the AFD information / option / control-code tests.
 *
 * The tests send AFD control codes straight to a socket handle with NtDeviceIoControlFile and use
 * ws2_32 only to create and drive the sockets. Nothing is linked: every entry point is resolved at
 * run time (LoadLibrary -> GetProcAddress) and called through a pointer in the table W.
 */
#ifndef AIO_H
#define AIO_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>

/* NTSTATUS values used by the expectations (own names). */
#define NTS_SUCCESS              0x00000000L
#define NTS_PENDING              0x00000103L
#define NTS_BUFFER_OVERFLOW      ((LONG)0x80000005)
#define NTS_ACCESS_VIOLATION     ((LONG)0xC0000005)
#define NTS_INVALID_HANDLE       ((LONG)0xC0000008)
#define NTS_INVALID_PARAMETER    ((LONG)0xC000000D)
#define NTS_INVALID_DEVICE_REQ   ((LONG)0xC0000010)
#define NTS_END_OF_FILE          ((LONG)0xC0000011)
#define NTS_BUFFER_TOO_SMALL     ((LONG)0xC0000023)
#define NTS_NOT_SUPPORTED        ((LONG)0xC00000BB)
#define NTS_INVALID_CONNECTION   ((LONG)0xC0000140)
#define NTS_INVALID_ADDRESS      ((LONG)0xC0000141)
#define NTS_CANCELLED            ((LONG)0xC0000120)
#define NTS_INSUFF_RESOURCES     ((LONG)0xC000009A)
#define NTS_INVALID_INFO_CLASS   ((LONG)0xC0000003)
#define NTS_INFO_LEN_MISMATCH    ((LONG)0xC0000004)
#define NTS_TIMEOUT              0x00000102L
#define NTS_TIMEOUT_LOCAL        ((LONG)0x7fff0102) /* aio_ctl gave up waiting and cancelled */

/* AFD control codes (Windows 10 numbering). */
#define IOC_BIND            0x12003u
#define IOC_CONNECT         0x12007u
#define IOC_START_LISTEN    0x1200bu
#define IOC_WAIT_FOR_LISTEN 0x1200cu
#define IOC_ACCEPT          0x12010u
#define IOC_RECV            0x12017u
#define IOC_RECV_DGRAM      0x1201bu
#define IOC_SEND            0x1201fu
#define IOC_SEND_DGRAM      0x12023u
#define IOC_POLL            0x12024u
#define IOC_PARTIAL_DISC    0x1202bu
#define IOC_GET_ADDRESS     0x1202fu
#define IOC_QUERY_RECV_INFO 0x12033u
#define IOC_QUERY_HANDLES   0x12037u
#define IOC_SET_INFO        0x1203bu
#define IOC_GET_REMOTE      0x1203fu
#define IOC_GET_CONTEXT     0x12043u
#define IOC_SET_CONTEXT     0x12047u
#define IOC_SET_CONN_DATA   0x1204bu
#define IOC_SET_CONN_OPT    0x1204fu
#define IOC_SET_DISC_DATA   0x12053u
#define IOC_SET_DISC_OPT    0x12057u
#define IOC_GET_CONN_DATA   0x1205bu
#define IOC_GET_CONN_OPT    0x1205fu
#define IOC_GET_DISC_DATA   0x12063u
#define IOC_GET_DISC_OPT    0x12067u
#define IOC_SIZE_CONN_DATA  0x1206bu
#define IOC_SIZE_CONN_OPT   0x1206fu
#define IOC_SIZE_DISC_DATA  0x12073u
#define IOC_SIZE_DISC_OPT   0x12077u
#define IOC_GET_INFO        0x1207bu
#define IOC_TRANSMIT_FILE   0x1207fu
#define IOC_SUPER_ACCEPT    0x12083u
#define IOC_EVENT_SELECT    0x12087u
#define IOC_ENUM_EVENTS     0x1208bu
#define IOC_DEFER_ACCEPT    0x1208cu
#define IOC_WAIT_LISTEN_LIFO 0x12090u
#define IOC_SET_QOS         0x12094u
#define IOC_GET_QOS         0x12098u
#define IOC_NO_OPERATION    0x1209fu
#define IOC_VALIDATE_GROUP  0x120a0u
#define IOC_GET_UNACCEPTED  0x120a7u
#define IOC_ROUTE_QUERY     0x120abu
#define IOC_ROUTE_CHANGE    0x120acu
#define IOC_ADDRLIST_QUERY  0x120b3u
#define IOC_ADDRLIST_CHANGE 0x120b4u
#define IOC_CONNECT_EX      0x120bbu   /* second connect slot */
#define IOC_TLI_CONTROL     0x120bfu
#define IOC_TRANSMIT_PKTS   0x120c3u
#define IOC_SUPER_CONNECT   0x120c7u
#define IOC_SUPER_DISCONNECT 0x120cbu
#define IOC_RECV_DGRAM2     0x120cfu
#define IOC_SEND_MESSAGE    0x120d3u
#define IOC_UNBIND          0x12113u
#define IOC_SQM             0x12117u
#define IOC_RIO             0x1211bu
#define IOC_XFER_BEGIN      0x1211fu
#define IOC_XFER_END        0x12123u

/* IOCTL_AFD_GET_INFORMATION / SET_INFORMATION information classes. */
#define AI_INLINE_MODE       1
#define AI_NONBLOCKING       2
#define AI_MAX_SEND_SIZE     3
#define AI_SENDS_PENDING     4
#define AI_MAX_PATH_SEND     5
#define AI_RECEIVE_WINDOW    6
#define AI_SEND_WINDOW       7
#define AI_CONNECT_TIME      8
#define AI_CIRCULAR_QUEUE    9
#define AI_GROUP_ID_TYPE     10
#define AI_REPORT_UNREACH    11
#define AI_DELIVERY_STATUS   14

/* The 0x10-byte information record both ioctls use. */
typedef struct {
    ULONG Class;
    ULONG Pad0;
    union { UCHAR Bool; ULONG Ulong; LONGLONG Large; } V;
} aio_info_t;

typedef LONG (NTAPI *aio_ioctl_fn)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef struct {
    __typeof__(&WSAStartup) WSAStartup;
    __typeof__(&WSAGetLastError) WSAGetLastError;
    __typeof__(&WSASocketW) WSASocketW;
    __typeof__(&closesocket) closesocket;
    __typeof__(&bind) bind;
    __typeof__(&listen) listen;
    __typeof__(&connect) connect;
    __typeof__(&accept) accept;
    __typeof__(&getsockname) getsockname;
    __typeof__(&send) send;
    __typeof__(&recv) recv;
    __typeof__(&setsockopt) setsockopt;
    __typeof__(&getsockopt) getsockopt;
    __typeof__(&ioctlsocket) ioctlsocket;
    __typeof__(&WSAIoctl) WSAIoctl;
    __typeof__(&shutdown) shutdown;
    __typeof__(&sendto) sendto;
    aio_ioctl_fn ioctl;
    LONG (NTAPI *cancel)(HANDLE, PIO_STATUS_BLOCK);
} AIOF;
extern AIOF W;

int aio_init(void);
#define AIO_BEGIN() do { if (!aio_init()) { t_skip("ws2_32 or ntdll entry points missing"); return; } } while (0)

extern DWORD aio_wait_ms;   /* bound on a pended request, default 3000 */
#define BE16(x) ((USHORT)__builtin_bswap16((unsigned short)(x)))
#define BE32(x) ((ULONG)__builtin_bswap32((unsigned)(x)))
#define LO4_HOST 0x7f000001UL

SOCKET aio_sock(int af, int type, int proto);   /* overlapped-capable; checks the result */
#define aio_tcp() aio_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP)
#define aio_udp() aio_sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
void   aio_close(SOCKET s);
struct sockaddr_in aio_lo4(USHORT port_be);
/* Fresh endpoints of the seven kinds the tables are indexed by. aio_kind returns INVALID_SOCKET when the
 * kind cannot be created (a raw socket needs elevation); the connected kind closes its peer. */
enum { AK_TCP, AK_UDP, AK_RAW, AK_TCP_BOUND, AK_TCP_LISTEN, AK_UDP_BOUND, AK_TCP_CONN, AK_COUNT };
extern const char *const aio_kind_name[AK_COUNT];
SOCKET aio_kind(int kind);
SOCKET aio_bound(int type);                      /* winsock-bound loopback socket, ephemeral port */
SOCKET aio_listener(struct sockaddr_in *addr);   /* TCP listening on loopback */
void   aio_pair(SOCKET *client, SOCKET *server); /* connected loopback TCP pair */
void   aio_nonblock(SOCKET s, int on);

/* Submit one control request with a private event; a request that pends is waited for (bounded) and
 * cancelled on timeout, reported as NTS_TIMEOUT_LOCAL. Returns the final status; *first (optional)
 * receives the status of the submitting call; io (optional) the final status block. */
LONG aio_ctl(SOCKET s, ULONG code, void *in, ULONG inl, void *out, ULONG outl, IO_STATUS_BLOCK *io, LONG *first);

/* One information request: get fills *v (the whole record) and returns the status. */
LONG aio_get_info(SOCKET s, ULONG cls, aio_info_t *v);
LONG aio_set_info(SOCKET s, ULONG cls, ULONGLONG val);

/* Endpoints opened directly on the AFD device with an open packet (no Winsock helper involved), so
 * their context area starts empty. kind: AIOK_*. Returns NULL on failure (status in *st if given). */
enum { AIOK_TCP4, AIOK_UDP4, AIOK_RAW4, AIOK_TCP6, AIOK_UDP6 };
HANDLE aio_open_raw(int kind, LONG *st);   /* like the provider: no transport device name, driver picks the transport */
HANDLE aio_open_tdi(int kind, LONG *st);   /* names the legacy transport device ("\\Device\\Tcp" ...) explicitly */
void   aio_close_raw(HANDLE h);

#define EXPECT_NTS(call, want) do { LONG st_ = (LONG)(call); \
    t_check(st_ == (LONG)(want), __FILE__, __LINE__, #call, "got 0x%08lx want 0x%08lx", (unsigned long)st_, (unsigned long)(LONG)(want)); } while (0)
#endif
