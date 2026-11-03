/* Shared definitions for the AFD device-contract tests in this area.
 *
 * The tests talk to the socket handle directly through ntdll's NtDeviceIoControlFile / NtReadFile / NtWriteFile
 * (resolved with GetProcAddress) using the Windows 10 AFD control codes, and use ws2_32 only to create the
 * sockets and to cross-check the results. Nothing here is linked: every entry point lives in a function table
 * filled by afdx_init() through U()/UN().
 */
#ifndef AFDX_H
#define AFDX_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>

/* ---- NTSTATUS values used by the tests (own names, no ntstatus.h) ----------------------------------------- */
#define AX_STATUS_SUCCESS                  0x00000000UL
#define AX_STATUS_TIMEOUT                  0x00000102UL
#define AX_STATUS_PENDING                  0x00000103UL
#define AX_STATUS_BUFFER_OVERFLOW          0x80000005UL
#define AX_STATUS_INVALID_PARAMETER        0xC000000DUL
#define AX_STATUS_BUFFER_TOO_SMALL         0xC0000023UL
#define AX_STATUS_SHARING_VIOLATION        0xC0000043UL
#define AX_STATUS_DEVICE_NOT_READY         0xC00000A3UL
#define AX_STATUS_PIPE_DISCONNECTED        0xC00000B0UL
#define AX_STATUS_CANCELLED                0xC0000120UL
#define AX_STATUS_INVALID_CONNECTION       0xC0000140UL
#define AX_STATUS_INVALID_ADDRESS          0xC0000141UL
#define AX_STATUS_INVALID_ADDRESS_COMPONENT 0xC0000207UL
#define AX_STATUS_CONNECTION_REFUSED       0xC0000236UL
#define AX_STATUS_ADDRESS_ALREADY_ASSOCIATED 0xC0000238UL

/* ---- AFD control codes (Windows 8 and later numbering) ----------------------------------------------------- */
#define AX_IOCTL_BIND          0x12003
#define AX_IOCTL_RECV          0x12017
#define AX_IOCTL_POLL          0x12024
#define AX_IOCTL_GETSOCKNAME   0x1202f
#define AX_IOCTL_EVENT_SELECT  0x12087
#define AX_IOCTL_GET_EVENTS    0x1208b

/* poll / event bits */
#define AX_POLL_READ        0x0001
#define AX_POLL_OOB         0x0002
#define AX_POLL_WRITE       0x0004
#define AX_POLL_HUP         0x0008
#define AX_POLL_RESET       0x0010
#define AX_POLL_CLOSE       0x0020
#define AX_POLL_CONNECT     0x0040
#define AX_POLL_ACCEPT      0x0080
#define AX_POLL_CONNECT_ERR 0x0100
#define AX_POLL_BIT_CONNECT_ERR 8

/* receive request flags: "recv_flags" is the AFD-level word, "msg_flags" the TDI-level word */
#define AX_RECV_FORCE_ASYNC 0x0002
#define AX_MSG_NOT_OOB      0x0020
#define AX_MSG_OOB          0x0040
#define AX_MSG_PEEK         0x0080
#define AX_MSG_WAITALL      0x4000

typedef struct {                  /* IOCTL_AFD_RECV input, 64-bit layout (24 bytes) */
    WSABUF *buffers;
    ULONG   count;
    ULONG   recv_flags;
    ULONG   msg_flags;
} AX_RECV;

typedef struct { SOCKET socket; ULONG flags; LONG status; } AX_POLL_ENTRY;
typedef struct {                  /* IOCTL_AFD_POLL input and output */
    LONGLONG timeout;
    ULONG    count;
    BOOLEAN  exclusive;
    AX_POLL_ENTRY sockets[1];
} AX_POLL;
#define AX_POLL_SIZE(n) (offsetof(AX_POLL, sockets) + (n) * sizeof(AX_POLL_ENTRY))

typedef struct { HANDLE event; ULONG mask; } AX_EVENT_SELECT;       /* IOCTL_AFD_EVENT_SELECT input */
typedef struct { ULONG flags; LONG status[13]; } AX_GET_EVENTS;     /* IOCTL_AFD_GET_EVENTS output (0x38 bytes) */

/* IOCTL_AFD_BIND input: a 4-byte word followed by the socket address, directly (no length field). */
#define AX_BIND_ADDR_OFF   4
#define AX_BIND_MAXSIZE    (AX_BIND_ADDR_OFF + sizeof(struct sockaddr_in6))
#define AX_SOCKADDR_IN6_OLD_SIZE 24      /* sockaddr_in6 without the scope id */

typedef void (NTAPI *AX_APC)(PVOID ctx, PIO_STATUS_BLOCK io, ULONG reserved);
UDECL(LONG, NtDeviceIoControlFile, (HANDLE, HANDLE, AX_APC, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG));
UDECL(LONG, NtReadFile, (HANDLE, HANDLE, AX_APC, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG));
UDECL(LONG, NtWriteFile, (HANDLE, HANDLE, AX_APC, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG));
UDECL(LONG, NtRemoveIoCompletion, (HANDLE, PULONG_PTR, PULONG_PTR, PIO_STATUS_BLOCK, PLARGE_INTEGER));

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
    __typeof__(&sendto) sendto;
    __typeof__(&shutdown) shutdown;
    __typeof__(&ioctlsocket) ioctlsocket;
    __typeof__(&setsockopt) setsockopt;
    __typeof__(&WSAEventSelect) WSAEventSelect;
    __typeof__(&WSAEnumNetworkEvents) WSAEnumNetworkEvents;
    NtDeviceIoControlFile_pfn  ioctl;
    NtReadFile_pfn             read;
    NtWriteFile_pfn            write;
    NtRemoveIoCompletion_pfn   remove_completion;
} AFDX;
extern AFDX X;

#define AX_WAIT 3000                              /* upper bound for any wait on loopback traffic */
#define LO4 0x7f000001UL
#define AX_HTONL(x) ((ULONG)__builtin_bswap32((unsigned)(x)))   /* no ws2 call needed for byte order */

/* returns 1 when everything resolved and Winsock is started; else records a skip reason */
int  afdx_init(void);
#define AFDX_BEGIN() do { if (!afdx_init()) { t_skip("ws2_32 or ntdll entry points missing"); return; } } while (0)

SOCKET afdx_socket(int af, int type, int proto, DWORD flags);     /* WSASocketW; checks the result */
void   afdx_close(SOCKET s);
void   afdx_pair_sync(SOCKET *client, SOCKET *server);              /* both ends synchronous handles */
void   afdx_listener(SOCKET *l, struct sockaddr_in *addr);         /* TCP, loopback, ephemeral port, listening */
void   afdx_pair(SOCKET *client, SOCKET *server, DWORD flags);     /* connected loopback TCP pair */
void   afdx_set_blocking(SOCKET s, int blocking);
void   afdx_close_rst(SOCKET s);                                   /* zero linger, close: peer sees a reset */
void   afdx_fill_sin(struct sockaddr_in *a, ULONG host_order_addr, USHORT port_be);
/* One-shot IOCTL_AFD_POLL on s with event; checks the completion and the reported mask (expect). */
void   afdx_wait_poll(SOCKET s, HANDLE event, ULONG mask, ULONG expect, const char *file, int line);
#define AFDX_WAIT_POLL(s, ev, mask, expect) afdx_wait_poll(s, ev, mask, expect, __FILE__, __LINE__)

/* NTSTATUS compare that does not sign-extend */
#define CHECK_ST(got, want) do { ULONG g_ = (ULONG)(got); \
    t_check(g_ == (ULONG)(want), __FILE__, __LINE__, #got " == " #want, "got 0x%08lx want 0x%08lx", (unsigned long)g_, (unsigned long)(ULONG)(want)); } while (0)
#define CHECK_IOSB(io, st, info) do { CHECK_ST((io).Status, st); \
    t_check((io).Information == (ULONG_PTR)(info), __FILE__, __LINE__, #io ".Information == " #info, "got 0x%llx", (unsigned long long)(io).Information); } while (0)
#define FILL_IOSB(io, b) memset(&(io), b, sizeof(io))
#endif
