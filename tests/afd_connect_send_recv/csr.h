/* Shared definitions for the AFD data-path tests (connect, send, receive, datagrams, partial disconnect).
 *
 * Nothing here is linked. Winsock is reached through pointers resolved with GetProcAddress, and the AFD
 * device is driven through the socket handle with ntdll's NtDeviceIoControlFile / NtReadFile / NtWriteFile /
 * NtCancelIoFile (also resolved at run time). Control codes, request layouts (64-bit) and NTSTATUS values are
 * written out under our own names.
 *
 * Request layouts used (x64):
 *   data request (receive / send)        24 bytes: buffers*, count, afd flags @0xc, tdi flags @0x10
 *   datagram receive                     40 bytes: the above + address buffer* @0x18 + address length* @0x20
 *   datagram send                       104 bytes: buffers*, count, afd flags @0xc, ..., address length @0x58,
 *                                                  address* @0x60
 *   connect                              header of 0x18 bytes followed by the raw socket address
 *   partial disconnect                   16 bytes: flags @0, timeout (LARGE_INTEGER) @8
 */
#ifndef CSR_H
#define CSR_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>

/* ---- NTSTATUS ------------------------------------------------------------------------------------------ */
#define CS_SUCCESS             0x00000000UL
#define CS_TIMEOUT             0x00000102UL
#define CS_PENDING             0x00000103UL
#define CS_BUFFER_OVERFLOW     0x80000005UL
#define CS_INVALID_HANDLE      0xC0000008UL
#define CS_INVALID_PARAMETER   0xC000000DUL
#define CS_INVALID_DEVICE_REQ  0xC0000010UL
#define CS_DEVICE_NOT_READY    0xC00000A3UL
#define CS_PIPE_DISCONNECTED   0xC00000B0UL
#define CS_NOT_SUPPORTED       0xC00000BBUL
#define CS_CANCELLED           0xC0000120UL
#define CS_LOCAL_DISCONNECT    0xC000013BUL
#define CS_INVALID_CONNECTION  0xC0000140UL
#define CS_INVALID_ADDRESS     0xC0000141UL
#define CS_ADDR_COMPONENT      0xC0000207UL
#define CS_CONNECTION_RESET    0xC000020DUL
#define CS_CONNECTION_REFUSED  0xC0000236UL
#define CS_GRACEFUL_DISCONNECT 0xC0000237UL
#define CS_ADDR_ALREADY_ASSOC  0xC0000238UL
#define CS_CONNECTION_ABORTED  0xC0000241UL

/* ---- control codes ------------------------------------------------------------------------------------- */
#define CS_IOCTL_BIND            0x12003u
#define CS_IOCTL_CONNECT         0x12007u
#define CS_IOCTL_START_LISTEN    0x1200bu
#define CS_IOCTL_RECV            0x12017u
#define CS_IOCTL_RECV_DGRAM      0x1201bu
#define CS_IOCTL_SEND            0x1201fu
#define CS_IOCTL_SEND_DGRAM      0x12023u
#define CS_IOCTL_POLL            0x12024u
#define CS_IOCTL_PARTIAL_DISC    0x1202bu
#define CS_IOCTL_GET_ADDRESS     0x1202fu

/* tdi flags of data requests */
#define CS_TDI_EXPEDITED   0x0040u    /* receive: urgent data */
#define CS_TDI_NORMAL      0x0020u    /* receive: normal data */
#define CS_TDI_PEEK        0x0080u
#define CS_TDI_WAITALL     0x4000u
/* afd flags */
#define CS_AFD_FORCE_ASYNC 0x0002u

/* partial disconnect flags */
#define CS_DISC_SEND       0x01u
#define CS_DISC_RECEIVE    0x02u
#define CS_DISC_ABORTIVE   0x04u
#define CS_DISC_UNCONNECT  0x08u

typedef struct { WSABUF *buf; ULONG count; ULONG afd; ULONG tdi; ULONG pad; } CS_DATA;           /* 24 */
typedef struct { WSABUF *buf; ULONG count; ULONG afd; ULONG tdi; ULONG pad; void *addr; ULONG *addrlen; } CS_RDG; /* 40 */
typedef struct {                                                                               /* 104 */
    WSABUF *buf; ULONG count; ULONG afd; UCHAR rsv[0x48]; ULONG addrlen; ULONG pad2; const void *addr;
} CS_SDG;
typedef struct { ULONG flags; ULONG pad; LARGE_INTEGER timeout; } CS_DISC;                       /* 16 */

typedef void (NTAPI *CS_APC)(PVOID ctx, PIO_STATUS_BLOCK io, ULONG reserved);
UDECL(LONG, NtDeviceIoControlFile, (HANDLE, HANDLE, CS_APC, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG));
UDECL(LONG, NtReadFile, (HANDLE, HANDLE, CS_APC, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG));
UDECL(LONG, NtWriteFile, (HANDLE, HANDLE, CS_APC, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG));
UDECL(LONG, NtCancelIoFile, (HANDLE, PIO_STATUS_BLOCK));
UDECL(LONG, NtTestAlert, (void));

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
    __typeof__(&getpeername) getpeername;
    __typeof__(&send) send;
    __typeof__(&recv) recv;
    __typeof__(&sendto) sendto;
    __typeof__(&recvfrom) recvfrom;
    __typeof__(&shutdown) shutdown;
    __typeof__(&setsockopt) setsockopt;
    __typeof__(&getsockopt) getsockopt;
    __typeof__(&ioctlsocket) ioctlsocket;
    __typeof__(&select) select;
    NtDeviceIoControlFile_pfn ioctl;
    NtReadFile_pfn            read;
    NtWriteFile_pfn           write;
    NtCancelIoFile_pfn        cancel;
} CSF;
extern CSF X;

#define CS_WAIT 2000
#define LO4 0x7f000001UL
#define BE32(x) ((ULONG)__builtin_bswap32((unsigned)(x)))
#define BE16(x) ((USHORT)__builtin_bswap16((unsigned short)(x)))

int csr_init(void);
#define CS_BEGIN() do { if (!csr_init()) { t_skip("ws2_32 or ntdll entry points missing"); return; } } while (0)

/* ---- sockets -------------------------------------------------------------------------------------------- */
void   cs_bound_blocking(SOCKET s);
SOCKET cs_sock(int af, int type);                                  /* overlapped-capable handle */
void   cs_close(SOCKET s);
struct sockaddr_in cs_lo4(USHORT port_be);
void   cs_bind_lo(SOCKET s, struct sockaddr_in *out);              /* winsock bind to 127.0.0.1:0, name returned */
SOCKET cs_listener(struct sockaddr_in *addr);                      /* TCP listening on loopback */
void   cs_pair(SOCKET *client, SOCKET *server);                    /* connected loopback TCP pair */
void   cs_udp_pair(SOCKET *a, SOCKET *b, struct sockaddr_in *aa, struct sockaddr_in *ba); /* two bound UDP sockets */
int    cs_readable(SOCKET s, DWORD ms);                            /* select-based wait, 1 when readable */
void   cs_rst_close(SOCKET s);                                     /* zero-linger close: the peer sees a reset */
int    cs_have_v6(void);

/* ---- raw requests ---------------------------------------------------------------------------------------
 * One request submitted with a private event. When the submit call says "pending" the completion is awaited
 * (bounded); a request that does not complete is cancelled and reported with final == CS_TIMEOUT.
 * first: status returned by the submit call. final: IO_STATUS_BLOCK.Status after completion (== first when the
 * request completed in the submit call). */
typedef struct { LONG first; LONG final; IO_STATUS_BLOCK io; int signalled; } CS_R;
CS_R   cs_ioctl(SOCKET s, ULONG code, void *in, ULONG inl, void *out, ULONG outl);
CS_R   cs_ioctl_ms(SOCKET s, ULONG code, void *in, ULONG inl, void *out, ULONG outl, DWORD ms);  /* explicit bound */
/* submit only; ev may be NULL */
LONG   cs_submit(SOCKET s, HANDLE ev, CS_APC apc, void *apc_ctx, IO_STATUS_BLOCK *io, ULONG code, void *in, ULONG inl, void *out, ULONG outl);
DWORD  cs_await(SOCKET s, HANDLE ev, IO_STATUS_BLOCK *io, DWORD ms);   /* wait result; cancels on timeout */

/* data requests built from a flat buffer */
CS_R   cs_recv(SOCKET s, void *buf, ULONG len, ULONG tdi, ULONG afd);
CS_R   cs_send(SOCKET s, const void *buf, ULONG len, ULONG tdi, ULONG afd);
CS_R   cs_connect(SOCKET s, const void *sa, ULONG salen);
/* A connect to a closed loopback port is refused only after the stack's connection retries (about two
   seconds), so refusal tests use this longer bound. */
#define CS_REFUSE_WAIT 10000
CS_R   cs_connect_ms(SOCKET s, const void *sa, ULONG salen, DWORD ms);          /* header + address */
CS_R   cs_disc(SOCKET s, ULONG flags);
CS_R   cs_recvfrom(SOCKET s, void *buf, ULONG len, struct sockaddr_in *from, ULONG *fromlen, ULONG tdi);
CS_R   cs_sendto(SOCKET s, const void *buf, ULONG len, const void *to, ULONG tolen, ULONG afd);

/* ---- compare helpers ----------------------------------------------------------------------------------- */
#define CHECK_ST(got, want) do { ULONG g_ = (ULONG)(got); \
    t_check(g_ == (ULONG)(want), __FILE__, __LINE__, #got " == " #want, "got 0x%08lx want 0x%08lx", (unsigned long)g_, (unsigned long)(ULONG)(want)); } while (0)
#define CHECK_ST2(got, w1, w2) do { ULONG g_ = (ULONG)(got); \
    t_check(g_ == (ULONG)(w1) || g_ == (ULONG)(w2), __FILE__, __LINE__, #got " in {" #w1 "," #w2 "}", "got 0x%08lx", (unsigned long)g_); } while (0)
/* completed in the submit call or after pending, final status and byte count */
/* the request expression is evaluated exactly once (it may well be a send that must not happen twice) */
#define CHECK_DONE(r, st, info) do { CS_R rr_ = (r); CHECK_ST(rr_.final, st); \
    t_check(rr_.io.Information == (ULONG_PTR)(info), __FILE__, __LINE__, #r ".io.Information == " #info, "got 0x%llx", (unsigned long long)rr_.io.Information); } while (0)
#define CHECK_SYNC(r, st) do { CS_R rr_ = (r); CHECK_ST(rr_.first, st); CHECK_ST(rr_.final, st); } while (0)
#define CHECK_ASYNC_OK(r) do { CS_R rr_ = (r); CHECK_ST2(rr_.first, CS_PENDING, CS_SUCCESS); } while (0)
#endif
