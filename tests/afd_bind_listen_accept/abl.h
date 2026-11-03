/* Shared definitions for the AFD bind / listen / accept contract tests.
 *
 * Nothing in this area links the DLLs under test. Winsock is reached through function pointers resolved
 * with GetProcAddress, and the AFD device is reached through the socket handle itself with ntdll's
 * NtDeviceIoControlFile (also resolved at run time). The control codes, structure layouts and status
 * values below are written out here under our own names.
 */
#ifndef ABL_H
#define ABL_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>

/* ---- NTSTATUS values --------------------------------------------------------------------------------- */
#define NS_SUCCESS               0x00000000UL
#define NS_TIMEOUT               0x00000102UL
#define NS_PENDING               0x00000103UL
#define NS_BUFFER_OVERFLOW       0x80000005UL
#define NS_INVALID_HANDLE        0xC0000008UL
#define NS_INVALID_PARAMETER     0xC000000DUL
#define NS_INVALID_DEVICE_REQUEST 0xC0000010UL
#define NS_BUFFER_TOO_SMALL      0xC0000023UL
#define NS_SHARING_VIOLATION     0xC0000043UL
#define NS_NOT_SUPPORTED         0xC00000BBUL
#define NS_CANCELLED             0xC0000120UL
#define NS_INVALID_CONNECTION    0xC0000140UL
#define NS_INVALID_ADDRESS       0xC0000141UL
#define NS_INVALID_ADDRESS_COMPONENT 0xC0000207UL
#define NS_CONNECTION_REFUSED    0xC0000236UL
#define NS_ADDRESS_ALREADY_ASSOCIATED 0xC0000238UL
#define NS_ACCESS_VIOLATION      0xC0000005UL

/* ---- control codes ------------------------------------------------------------------------------------ */
#define IO_BIND            0x12003u
#define IO_START_LISTEN    0x1200bu
#define IO_WAIT_FOR_LISTEN 0x1200cu
#define IO_ACCEPT          0x12010u
#define IO_GET_ADDRESS     0x1202fu
#define IO_GET_REMOTE      0x1203fu
#define IO_SUPER_ACCEPT    0x12083u
#define IO_DEFER_ACCEPT    0x1208cu
#define IO_WAIT_LISTEN_LIFO 0x12090u
#define IO_UNBIND_SOCKET   0x12113u
#define IO_POLL            0x12024u
#define IO_SET_CONTEXT     0x12047u
#define IO_GET_CONTEXT     0x12043u
#define IO_QUERY_HANDLES   0x12037u
#define IO_GET_INFORMATION 0x1207bu
#define IO_SET_INFORMATION 0x1203bu

/* number of entries in the driver's control-code table; slots 0 .. ABL_SLOTS-1 are indexed by bits 2..11 */
#define ABL_SLOTS 73
extern const unsigned abl_code_table[ABL_SLOTS];

/* ---- request blocks (64-bit layouts) ------------------------------------------------------------------ */
typedef struct { UCHAR use_san; UCHAR pad[3]; ULONG backlog; ULONG delayed; } ABL_LISTEN;       /* 12 bytes */
typedef struct { UCHAR use_san; UCHAR pad[3]; ULONG sequence; HANDLE accept_handle; } ABL_ACCEPT; /* 16 bytes */
typedef struct { ULONG sequence; ULONG addr_count; USHORT addr_len; USHORT addr_type; UCHAR addr[24]; } ABL_LRESP;
typedef struct { ULONG sequence; ULONG defer; } ABL_DEFER;                                       /* 8 bytes */

/* ---- function table ----------------------------------------------------------------------------------- */
typedef LONG (NTAPI *abl_ioctl_fn)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef struct {
    __typeof__(&WSAStartup) WSAStartup;
    __typeof__(&WSAGetLastError) WSAGetLastError;
    __typeof__(&WSASocketW) WSASocketW;
    __typeof__(&socket) socket;
    __typeof__(&closesocket) closesocket;
    __typeof__(&bind) bind;
    __typeof__(&listen) listen;
    __typeof__(&connect) connect;
    __typeof__(&accept) accept;
    __typeof__(&getsockname) getsockname;
    __typeof__(&getpeername) getpeername;
    __typeof__(&setsockopt) setsockopt;
    __typeof__(&getsockopt) getsockopt;
    __typeof__(&ioctlsocket) ioctlsocket;
    __typeof__(&send) send;
    __typeof__(&recv) recv;
    __typeof__(&shutdown) shutdown;
    __typeof__(&select) select;
    abl_ioctl_fn ioctl;
} ABLF;
extern ABLF W;

int abl_init(void);
#define ABL_BEGIN() do { if (!abl_init()) { t_skip("ws2_32 or ntdll entry points missing"); return; } } while (0)

#define WAIT_MS 4000
#define LO4 0x7f000001UL
#define BE32(x) ((ULONG)__builtin_bswap32((unsigned)(x)))
#define BE16(x) ((USHORT)__builtin_bswap16((unsigned short)(x)))

/* ---- sockets ------------------------------------------------------------------------------------------ */
void   abl_timeouts(SOCKET s);                        /* receive/send timeouts of WAIT_MS */
SOCKET abl_sock(int af, int type);                     /* overlapped-capable handle; checks the result */
#define abl_tcp() abl_sock(AF_INET, SOCK_STREAM)
#define abl_udp() abl_sock(AF_INET, SOCK_DGRAM)
void   abl_close(SOCKET s);
struct sockaddr_in abl_lo4(USHORT port_be);            /* 127.0.0.1:port */
int    abl_have_v6(void);
struct sockaddr_in6 abl_lo6(USHORT port_be);
SOCKET abl_listener(struct sockaddr_in *addr);         /* TCP, winsock bind+listen on loopback, ephemeral port */
SOCKET abl_bound(int type, struct sockaddr_in *addr);  /* winsock-bound loopback socket, not listening */
void   abl_pair(SOCKET *client, SOCKET *server);       /* connected loopback TCP pair */
int    abl_connect(SOCKET c, const struct sockaddr_in *to);   /* blocking winsock connect; returns 0 on success */
void   abl_nonblock(SOCKET s, int on);

/* ---- raw control requests ------------------------------------------------------------------------------
 * abl_ctl submits a request with a private event and, when the driver answers "pending", waits (bounded) for
 * the completion. It returns the final status (the status block's value for a pended request) and fills *io;
 * *first receives the status returned by the submit call itself when first is not NULL. A request that does
 * not complete in WAIT_MS is cancelled and reported as NS_TIMEOUT. */
LONG abl_ctl(SOCKET s, ULONG code, void *in, ULONG inl, void *out, ULONG outl, IO_STATUS_BLOCK *io, LONG *first);
/* Submit only; the caller owns the event and waits itself. Returns the submit status. */
LONG abl_submit(SOCKET s, HANDLE ev, ULONG code, void *in, ULONG inl, void *out, ULONG outl, IO_STATUS_BLOCK *io);
/* Wait for a pended request's event; returns the wait result (cancels the request on timeout). */
DWORD abl_wait(SOCKET s, HANDLE ev, IO_STATUS_BLOCK *io, DWORD ms);

/* One-step helpers over abl_ctl */
LONG abl_raw_bind(SOCKET s, ULONG share, const void *sa, ULONG salen, void *out, ULONG outl, IO_STATUS_BLOCK *io);
LONG abl_raw_bind4(SOCKET s, ULONG share, ULONG host_addr, USHORT port_be, struct sockaddr_in *out);
LONG abl_raw_listen(SOCKET s, ULONG backlog, ULONG delayed);
LONG abl_raw_name(SOCKET s, void *out, ULONG outl, IO_STATUS_BLOCK *io);

/* ---- compare helpers ---------------------------------------------------------------------------------- */
#define CHECK_NS(got, want) do { ULONG g_ = (ULONG)(got); \
    t_check(g_ == (ULONG)(want), __FILE__, __LINE__, #got " == " #want, "got 0x%08lx want 0x%08lx", (unsigned long)g_, (unsigned long)(ULONG)(want)); } while (0)
#define CHECK_NSV(got, want, why) do { ULONG g_ = (ULONG)(got); \
    t_check(g_ == (ULONG)(want), __FILE__, __LINE__, #got " == " #want, "%s: got 0x%08lx want 0x%08lx", why, (unsigned long)g_, (unsigned long)(ULONG)(want)); } while (0)
#define FILL_IO(io, b) memset(&(io), b, sizeof(io))
#define CHECK_INFO(io, n) t_check((io).Information == (ULONG_PTR)(n), __FILE__, __LINE__, #io ".Information == " #n, "got 0x%llx", (unsigned long long)(io).Information)

/* Loopback connection helpers shared by accept tests: connect a client in a helper thread-free way
 * (non-blocking connect issued from the test thread) and report when a connection is queued. */
SOCKET abl_client_to(const struct sockaddr_in *to);    /* nonblocking client, connect issued, returned */
int    abl_wait_readable(SOCKET s, DWORD ms);          /* select-based wait on a listener / data socket */
int    abl_wait_writable(SOCKET s, DWORD ms);
#endif
