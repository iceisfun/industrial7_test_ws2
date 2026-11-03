/* Shared helpers for the gap_05 area: AFD control codes driven through NtDeviceIoControlFile.
 *
 * Nothing here links the DLLs under test. Winsock is resolved with GetProcAddress (U) and the device is
 * reached through the socket handle itself with the ntdll entry point, also resolved at run time.
 * Status values, request layouts and code numbers are written out under our own names. Layouts are the
 * 64-bit ones. Requests are always submitted with a private event so they take the IRP path. */
#ifndef G5_H
#define G5_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>

#define ST_SUCCESS            0x00000000L
#define ST_PENDING            0x00000103L
#define ST_TIMEOUT            0x00000102L
#define ST_BUFFER_OVERFLOW    ((LONG)0x80000005)
#define ST_INVALID_HANDLE     ((LONG)0xC0000008)
#define ST_INVALID_PARAMETER  ((LONG)0xC000000D)
#define ST_INVALID_DEVICE_REQ ((LONG)0xC0000010)
#define ST_NOT_IMPLEMENTED    ((LONG)0xC0000002)
#define ST_TYPE_MISMATCH      ((LONG)0xC0000024)
#define ST_BUFFER_TOO_SMALL   ((LONG)0xC0000023)
#define ST_NOT_SUPPORTED      ((LONG)0xC00000BB)
#define ST_DEVICE_NOT_READY   ((LONG)0xC00000A3)
#define ST_CANCELLED          ((LONG)0xC0000120)
#define ST_LOCAL_GAVE_UP      ((LONG)0x7FFF0102)   /* g5_ctl waited and cancelled: never a driver answer */

/* control codes (Windows 10 numbering) */
#define C_BIND            0x12003u
#define C_START_LISTEN    0x1200bu
#define C_WAIT_FOR_LISTEN 0x1200cu
#define C_ACCEPT          0x12010u
#define C_GET_ADDRESS     0x1202fu
#define C_GET_REMOTE      0x1203fu
#define C_SET_CONN_DATA   0x1204bu
#define C_SET_CONN_OPT    0x1204fu
#define C_SET_DISC_DATA   0x12053u
#define C_SET_DISC_OPT    0x12057u
#define C_GET_CONN_DATA   0x1205bu
#define C_GET_CONN_OPT    0x1205fu
#define C_GET_DISC_DATA   0x12063u
#define C_GET_DISC_OPT    0x12067u
#define C_SIZE_CONN_DATA  0x1206bu
#define C_SIZE_CONN_OPT   0x1206fu
#define C_SIZE_DISC_DATA  0x12073u
#define C_SIZE_DISC_OPT   0x12077u

typedef LONG (NTAPI *g5_ioctl_fn)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
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
    __typeof__(&setsockopt) setsockopt;
    __typeof__(&ioctlsocket) ioctlsocket;
    __typeof__(&send) send;
    __typeof__(&recv) recv;
    __typeof__(&sendto) sendto;
    __typeof__(&shutdown) shutdown;
    __typeof__(&select) select;
    __typeof__(&WSAIoctl) WSAIoctl;
    g5_ioctl_fn ioctl;
    LONG (NTAPI *cancel)(HANDLE, PIO_STATUS_BLOCK);
    LONG (NTAPI *nt_close)(HANDLE);
    LONG (NTAPI *nt_create)(HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES *, IO_STATUS_BLOCK *, LARGE_INTEGER *, ULONG, ULONG, ULONG, ULONG, void *, ULONG);
} G5F;
extern G5F W;
int g5_init(void);
#define G5_BEGIN() do { if (!g5_init()) { t_skip("ws2_32 or ntdll entry points missing"); return; } } while (0)

#define WAIT_MS 3000
#define BE16(x) ((USHORT)__builtin_bswap16((unsigned short)(x)))
#define BE32(x) ((ULONG)__builtin_bswap32((unsigned)(x)))

/* request records */
typedef struct { UCHAR use_san; UCHAR pad[3]; ULONG backlog; ULONG delayed; } G5_LISTEN;          /* 12 */
typedef struct { UCHAR use_san; UCHAR pad[3]; ULONG sequence; HANDLE accept; } G5_ACCEPT;         /* 16 */
typedef struct { ULONG sequence; ULONG reject; } G5_DEFER;
/* a transport-address answer: count, then { length, type, port, ipv4 address, zeros } */
#pragma pack(push, 1)
typedef struct { ULONG count; USHORT len; USHORT type; USHORT port; ULONG addr; UCHAR zero[8]; } G5_TA;
#pragma pack(pop)                                        /* 8 */
typedef struct { ULONG sequence; ULONG count; USHORT alen; USHORT atype; UCHAR addr[24]; } G5_WAITRES;

/* sockets (all closed by the caller) */
SOCKET g5_sock(int af, int type);                          /* overlapped-capable; checked */
#define g5_tcp() g5_sock(AF_INET, SOCK_STREAM)
#define g5_udp() g5_sock(AF_INET, SOCK_DGRAM)
void   g5_close(SOCKET s);
struct sockaddr_in g5_lo4(USHORT port_be);
SOCKET g5_bound(int type, struct sockaddr_in *addr);        /* loopback, ephemeral port */
SOCKET g5_listener(struct sockaddr_in *addr);               /* winsock listen, backlog 4 */
void   g5_pair(SOCKET *client, SOCKET *server);             /* connected loopback TCP pair */
SOCKET g5_connect_nb(const struct sockaddr_in *to);         /* non-blocking client, connect issued */
int    g5_readable(SOCKET s, DWORD ms);
void   g5_timeouts(SOCKET s);

/* raw requests */
LONG g5_ctl(HANDLE h, ULONG code, void *in, ULONG inl, void *out, ULONG outl, IO_STATUS_BLOCK *io, LONG *first);
LONG g5_submit(HANDLE h, HANDLE ev, ULONG code, void *in, ULONG inl, void *out, ULONG outl, IO_STATUS_BLOCK *io);
LONG g5_finish(HANDLE h, HANDLE ev, IO_STATUS_BLOCK *io, DWORD ms);   /* wait for a pended request; cancels on timeout */
#define S(s) ((HANDLE)(s))
LONG g5_raw_listen(SOCKET s, ULONG backlog, ULONG delayed);
LONG g5_raw_bind4(HANDLE h, USHORT port_be);                           /* loopback address, 0 = ephemeral */
LONG g5_wait_listen(SOCKET l, ULONG code, ULONG *seq, IO_STATUS_BLOCK *io);   /* waits for one arrival */

/* endpoints opened directly on the device; legacy = names a transport device explicitly (TDI style) */
enum { EK_TCP4, EK_UDP4, EK_TCP6 };
HANDLE g5_open_ep(int kind, int legacy, LONG *st);
void   g5_close_h(HANDLE h);

#define EXPECT_NTS(call, want) do { LONG st_ = (LONG)(call); \
    t_check(st_ == (LONG)(want), __FILE__, __LINE__, #call, "got 0x%08lx want 0x%08lx", (unsigned long)st_, (unsigned long)(LONG)(want)); } while (0)
#define EXPECT_NTSV(call, want, why) do { LONG st_ = (LONG)(call); \
    t_check(st_ == (LONG)(want), __FILE__, __LINE__, #call, "%s: got 0x%08lx want 0x%08lx", why, (unsigned long)st_, (unsigned long)(LONG)(want)); } while (0)
#endif
