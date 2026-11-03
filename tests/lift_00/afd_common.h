/* Shared helpers for the AFD poll / device-open tests in this area.
 *
 * Nothing here links ws2_32: every Winsock entry point and every ntdll Nt* call is resolved at run
 * time through the harness (LoadLibrary -> GetProcAddress) and called through a pointer.
 */
#ifndef AFD_COMMON_H
#define AFD_COMMON_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

/* ---- NTSTATUS values used by the expectations -------------------------- */
#define AS_SUCCESS            ((NTSTATUS)0x00000000)
#define AS_TIMEOUT            ((NTSTATUS)0x00000102)
#define AS_PENDING            ((NTSTATUS)0x00000103)
#define AS_INVALID_HANDLE     ((NTSTATUS)0xC0000008)
#define AS_INVALID_PARAMETER  ((NTSTATUS)0xC000000D)
#define AS_CANCELLED          ((NTSTATUS)0xC0000120)
#define AS_CONNECTION_REFUSED ((NTSTATUS)0xC0000236)

/* ---- AFD poll contract -------------------------------------------------- */
#define AFDX_IOCTL_POLL   0x00012024u

#define AFDX_POLL_READ        0x0001
#define AFDX_POLL_OOB         0x0002
#define AFDX_POLL_WRITE       0x0004
#define AFDX_POLL_HUP         0x0008
#define AFDX_POLL_RESET       0x0010
#define AFDX_POLL_CLOSE       0x0020
#define AFDX_POLL_CONNECT     0x0040
#define AFDX_POLL_ACCEPT      0x0080
#define AFDX_POLL_CONNECT_ERR 0x0100

typedef struct {
    ULONG_PTR socket;   /* the handle value of the socket being polled */
    ULONG     flags;    /* in: events wanted; out: events present */
    LONG      status;   /* out: NTSTATUS attached to the event (connect error) */
} pollent_t;

typedef struct {
    LONGLONG  timeout;      /* 100ns units; negative = relative, positive = absolute, 0 = do not wait */
    ULONG     count;
    ULONG     exclusive;
    pollent_t sockets[1];
} pollreq_t;

#define POLL_BYTES(n)  (offsetof(pollreq_t, sockets) + (n) * sizeof(pollent_t))
#define POLL_MAXENT    4
#define REL_MS(ms)     (-(LONGLONG)(ms) * 10000)

typedef union {
    pollreq_t req;
    char      raw[POLL_BYTES(POLL_MAXENT)];
} pollbuf_t;

/* ---- run-time resolved entry points ------------------------------------- */
UDECL(LONG, NtOpenFile, (HANDLE *, ULONG, OBJECT_ATTRIBUTES *, IO_STATUS_BLOCK *, ULONG, ULONG));
UDECL(LONG, NtDeviceIoControlFile, (HANDLE, HANDLE, void *, void *, IO_STATUS_BLOCK *, ULONG,
                                    void *, ULONG, void *, ULONG));
UDECL(LONG, NtQueryObject, (HANDLE, int, void *, ULONG, ULONG *));
UDECL(LONG, NtQuerySystemTime, (LARGE_INTEGER *));
UDECL(LONG, NtRemoveIoCompletion, (HANDLE, ULONG_PTR *, ULONG_PTR *, IO_STATUS_BLOCK *, LARGE_INTEGER *));

typedef struct {
    NtOpenFile_pfn              NtOpenFile;
    NtDeviceIoControlFile_pfn   NtDeviceIoControlFile;
    NtQueryObject_pfn           NtQueryObject;
    NtQuerySystemTime_pfn       NtQuerySystemTime;
    NtRemoveIoCompletion_pfn    NtRemoveIoCompletion;
    __typeof__(&WSAStartup)   WSAStartup;
    __typeof__(&WSAGetLastError) WSAGetLastError;
    __typeof__(&socket)       socket;
    __typeof__(&bind)         bind;
    __typeof__(&listen)       listen;
    __typeof__(&accept)       accept;
    __typeof__(&connect)      connect;
    __typeof__(&getsockname)  getsockname;
    __typeof__(&send)         send;
    __typeof__(&recv)         recv;
    __typeof__(&sendto)       sendto;
    __typeof__(&shutdown)     shutdown;
    __typeof__(&closesocket)  closesocket;
    __typeof__(&setsockopt)   setsockopt;
    __typeof__(&ioctlsocket)  ioctlsocket;
    __typeof__(&WSAIoctl)     WSAIoctl;
    __typeof__(&WSARecv)      WSARecv;
} afdfn_t;
extern afdfn_t F;

/* Resolve everything and start Winsock once; returns 0 when something is missing. */
int afd_ready(void);
#define NEED_AFD() do { if (!afd_ready()) { t_skip("winsock/ntdll entry points unavailable"); return; } } while (0)

/* ---- helpers ------------------------------------------------------------ */
SOCKET mk_sock(int type);                         /* AF_INET socket, checks the result */
#define mk_tcp()  mk_sock(SOCK_STREAM)
#define mk_udp()  mk_sock(SOCK_DGRAM)
SOCKET mk_listener(struct sockaddr_in *addr_out); /* loopback, ephemeral port, backlog 1 */
void   mk_pair(SOCKET *client, SOCKET *server);   /* connected loopback TCP pair, blocking */
void   set_nonblock(SOCKET s, int on);
void   close_rst(SOCKET s);                       /* zero linger then close: peer sees a reset */
void   sock_close(SOCKET s);
HANDLE mk_event(void);
HANDLE open_afd(const wchar_t *path);             /* NtOpenFile on a device path, NULL on failure */
LONG   afd_poll(HANDLE h, HANDLE ev, IO_STATUS_BLOCK *io, void *in, ULONG inlen, void *out, ULONG outlen);
LONG   afd_poll_ex(HANDLE h, HANDLE ev, void *apc_ctx, IO_STATUS_BLOCK *io, void *in, ULONG inlen, void *out, ULONG outlen);
void   fill_poll(pollbuf_t *b, LONGLONG timeout, ULONG exclusive, int n, const SOCKET *socks, const ULONG *flags);
void   fill_poll1(pollbuf_t *b, LONGLONG timeout, SOCKET s, ULONG flags);
/* Wait for a pending request to finish; returns the wait result. Gives up after ms. */
DWORD  wait_done(HANDLE ev, DWORD ms);
/* Cancel everything outstanding on h from this thread and wait for the event (bounded). */
void   cancel_and_drain(HANDLE h, HANDLE ev);

/* Poll one socket with a 1s relative timeout and verify the full single-entry result:
 * completion (immediate or pending), io.Information, timeout echo, count 1, socket, flags, status 0.
 * mask is the flag set requested. */
void   poll_one_expect(const char *file, int line, SOCKET s, HANDLE ev, ULONG mask, ULONG expect);
#define POLL_EXPECT(s, ev, expect)            poll_one_expect(__FILE__, __LINE__, s, ev, ~0u, expect)
#define POLL_EXPECT_MASK(s, ev, mask, expect) poll_one_expect(__FILE__, __LINE__, s, ev, mask, expect)

/* Evaluate the call exactly once (EXPECT_EQ would evaluate its argument twice). */
#define EXPECT_ST(call, want) do { LONG st_ = (LONG)(call); CHECKF(st_ == (LONG)(want), "got %#lx want %#lx", (unsigned long)st_, (unsigned long)(want)); } while (0)
#define CHECK_IO(io, st, info)  do { CHECK((io).Status == (st)); CHECK((io).Information == (ULONG_PTR)(info)); } while (0)
#endif
