/* Shared helpers for the AFD poll / event-select state tests.
 *
 * Winsock is only used to create sockets and to drive loopback traffic; everything that is measured is
 * the device contract reached through ntdll's NtDeviceIoControlFile on the socket handle. No entry point
 * is linked: all of them are resolved at run time through the harness and called through pointers.
 *
 * Wire layouts (x64):
 *   poll request   16-byte header: LONGLONG timeout, ULONG count, BOOLEAN exclusive + 3 pad bytes,
 *                  followed by count 16-byte entries { handle value, event mask, NTSTATUS }.
 *   event select   16 bytes { event handle, event mask } (method-neither input)
 *   get events     method-neither: the "input pointer" is an optional event handle to reset,
 *                  output is 0x38 bytes { ULONG pending, LONG status[13] }.
 */
#ifndef AP_H
#define AP_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>

/* ---- NTSTATUS (own names) ---------------------------------------------- */
#define APS_SUCCESS          0x00000000UL
#define APS_TIMEOUT          0x00000102UL
#define APS_PENDING          0x00000103UL
#define APS_MISALIGNED       0x80000002UL
#define APS_INVALID_HANDLE   0xC0000008UL
#define APS_INVALID_PARAM    0xC000000DUL
#define APS_ACCESS_DENIED    0xC0000022UL
#define APS_TYPE_MISMATCH    0xC0000024UL
#define APS_CANCELLED        0xC0000120UL
#define APS_NOT_FOUND        0xC0000225UL
#define APS_REFUSED          0xC0000236UL

/* ---- control codes ------------------------------------------------------ */
#define AP_IOCTL_POLL         0x12024u
#define AP_IOCTL_EVENT_SELECT 0x12087u
#define AP_IOCTL_GET_EVENTS   0x1208bu

/* ---- event bits --------------------------------------------------------- */
#define APE_RECEIVE     0x0001u
#define APE_EXPEDITED   0x0002u
#define APE_SEND        0x0004u
#define APE_DISCONNECT  0x0008u
#define APE_ABORT       0x0010u
#define APE_CLOSE       0x0020u
#define APE_CONNECT     0x0040u
#define APE_ACCEPT      0x0080u
#define APE_CONNECT_FAIL 0x0100u
#define APE_QOS         0x0200u
#define APE_GROUP_QOS   0x0400u
#define APE_ROUTING     0x0800u
#define APE_ADDRLIST    0x1000u
#define APE_ALL         0xFFFFFFFFu

typedef struct { ULONG_PTR h; ULONG ev; LONG st; } ap_ent;
#define AP_MAXE 160
typedef struct { LONGLONG to; ULONG n; UCHAR ex; UCHAR pad[3]; ap_ent e[AP_MAXE]; } ap_req;
#define AP_SZ(n)  ((ULONG)(16 + 16 * (n)))
#define AP_REL_MS(ms) (-(LONGLONG)(ms) * 10000)
#define AP_INFINITE   0x7fffffffffffffffLL

typedef struct { HANDLE event; ULONG_PTR mask_lo; } ap_evsel_pad;   /* unused placeholder to keep sizes explicit */
typedef struct { HANDLE event; ULONG mask; ULONG pad; } ap_evsel;   /* 16 bytes */
typedef struct { ULONG pending; LONG status[13]; } ap_getev;         /* 0x38 bytes */

typedef void (NTAPI *ap_apc)(PVOID, PIO_STATUS_BLOCK, ULONG);
UDECL(LONG, NtDeviceIoControlFile, (HANDLE, HANDLE, ap_apc, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG));
UDECL(LONG, NtCancelIoFile, (HANDLE, PIO_STATUS_BLOCK));
UDECL(LONG, NtCancelIoFileEx, (HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK));
UDECL(LONG, NtQuerySystemTime, (PLARGE_INTEGER));
UDECL(LONG, NtOpenFile, (PHANDLE, ULONG, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG));

typedef struct {
    NtDeviceIoControlFile_pfn ioctl;
    NtCancelIoFile_pfn cancel_all;
    NtCancelIoFileEx_pfn cancel_ex;
    NtQuerySystemTime_pfn systime;
    NtOpenFile_pfn open_file;
    __typeof__(&WSAStartup) WSAStartup;
    __typeof__(&WSAGetLastError) WSAGetLastError;
    __typeof__(&socket) socket;
    __typeof__(&WSASocketW) WSASocketW;
    __typeof__(&bind) bind;
    __typeof__(&listen) listen;
    __typeof__(&accept) accept;
    __typeof__(&connect) connect;
    __typeof__(&getsockname) getsockname;
    __typeof__(&send) send;
    __typeof__(&sendto) sendto;
    __typeof__(&recv) recv;
    __typeof__(&shutdown) shutdown;
    __typeof__(&closesocket) closesocket;
    __typeof__(&setsockopt) setsockopt;
    __typeof__(&ioctlsocket) ioctlsocket;
} ap_fns;
extern ap_fns X;

int ap_init(void);
#define AP_BEGIN() do { if (!ap_init()) { t_skip("ws2_32 or ntdll entry points missing"); return; } } while (0)

SOCKET ap_sock(int type);                                   /* AF_INET stream or datagram */
SOCKET ap_listener(struct sockaddr_in *addr, int backlog);  /* loopback, ephemeral port */
SOCKET ap_dial(const struct sockaddr_in *addr);             /* blocking connect to addr */
void   ap_pair(SOCKET *client, SOCKET *server);
void   ap_closeS(SOCKET s);
void   ap_rst_close(SOCKET s);                              /* zero linger, close: the peer is reset */
void   ap_nonblock(SOCKET s);
HANDLE ap_event(void);
void   ap_send_n(SOCKET s, int n);                          /* n bytes of payload */
void   ap_drain(SOCKET s);                                  /* recv until nothing is queued (non-blocking read) */

/* Raw submit: status of the NtDeviceIoControlFile call (pending is 0x103). */
LONG   ap_submit(HANDLE carrier, HANDLE ev, IO_STATUS_BLOCK *io, const void *in, ULONG inlen, void *out, ULONG outlen);

/* Result of a one-entry (or small) poll that was driven to completion. */
typedef struct {
    LONG       ret;      /* status returned by the call */
    LONG       ios;      /* IO_STATUS_BLOCK.Status after completion */
    ULONG_PTR  info;     /* IO_STATUS_BLOCK.Information */
    int        waited;   /* the request was pending and completed on its own */
    int        hung;     /* never completed within the bound (cancelled) */
    ap_req     out;
} ap_res;
/* Poll entries (h[i], mask[i]) with the given timeout/exclusive flag on a carrier handle, wait for the end. */
void ap_run(HANDLE carrier, LONGLONG to, UCHAR ex, int n, const SOCKET *h, const ULONG *mask, DWORD wait_ms, ap_res *r);
/* One socket, carrier = the socket itself. */
void ap_run1(SOCKET s, ULONG mask, LONGLONG to, ap_res *r);
/* Convenience: flags reported for s, or 0 when nothing was reported. */
ULONG  ap_wait_flags(SOCKET s, ULONG mask);   /* waits up to a few seconds for any requested event */
ULONG  ap_now_flags(SOCKET s, ULONG mask);    /* zero timeout snapshot */
int    ap_idle(SOCKET s, ULONG mask);         /* zero timeout snapshot reports nothing */

#define CK_ST(got, want) do { ULONG g_ = (ULONG)(got); \
    t_check(g_ == (ULONG)(want), __FILE__, __LINE__, #got " == " #want, "got 0x%08lx want 0x%08lx", (unsigned long)g_, (unsigned long)(ULONG)(want)); } while (0)
#define CK_FLAGS(got, want) do { ULONG g_ = (ULONG)(got); \
    t_check(g_ == (ULONG)(want), __FILE__, __LINE__, #got " == " #want, "got 0x%lx want 0x%lx", (unsigned long)g_, (unsigned long)(ULONG)(want)); } while (0)
#endif

/* Submit a prepared poll request as is (declared entry count n_decl is taken from in->n); returns the call
 * status. A request that unexpectedly pends is cancelled and drained so no buffer outlives the call. */
LONG ap_try(HANDLE carrier, const ap_req *in, ULONG inlen, ULONG outlen);
/* Fill a request for n entries naming h[i] with the same mask. */
void ap_fill(ap_req *r, LONGLONG to, UCHAR ex, int n, const SOCKET *h, ULONG mask);
