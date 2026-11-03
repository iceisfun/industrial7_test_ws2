/* x_error_mapping: shared helpers.
 *
 * This area measures how failures are reported: the Winsock error number left by failing calls, its identity with
 * the thread's last-error slot, FormatMessage texts for the Winsock error range, name-service error numbers, and
 * the translation of NTSTATUS values produced by the AFD driver into Winsock errors.
 *
 * Nothing from the DLLs under test is linked. Every call goes through a pointer resolved with GetProcAddress.
 * Table rows carry the expected value; the placeholder XE_UNK makes a row report what it observed (as a NOTE)
 * instead of checking it. */
#ifndef XE_H
#define XE_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

/* Route the plain Winsock names through the harness lookup. */
#define WSAStartup U(WSAStartup)
#define WSACleanup U(WSACleanup)
#define WSAGetLastError U(WSAGetLastError)
#define WSASetLastError U(WSASetLastError)
#define WSASocketW U(WSASocketW)
#define socket U(socket)
#define closesocket U(closesocket)
#define bind U(bind)
#define listen U(listen)
#define connect U(connect)
#define accept U(accept)
#define send U(send)
#define recv U(recv)
#define sendto U(sendto)
#define recvfrom U(recvfrom)
#define shutdown U(shutdown)
#define getsockname U(getsockname)
#define getpeername U(getpeername)
#define getsockopt U(getsockopt)
#define setsockopt U(setsockopt)
#define ioctlsocket U(ioctlsocket)
#define select U(select)
#define WSAIoctl U(WSAIoctl)
#define WSARecv U(WSARecv)
#define WSASend U(WSASend)
#define WSARecvFrom U(WSARecvFrom)
#define WSASendTo U(WSASendTo)
#define WSAGetOverlappedResult U(WSAGetOverlappedResult)
#define WSACreateEvent U(WSACreateEvent)
#define WSACloseEvent U(WSACloseEvent)
#define WSASetEvent U(WSASetEvent)
#define WSAResetEvent U(WSAResetEvent)
#define WSAWaitForMultipleEvents U(WSAWaitForMultipleEvents)
#define WSAEventSelect U(WSAEventSelect)
#define WSAEnumNetworkEvents U(WSAEnumNetworkEvents)
#define WSAEnumProtocolsW U(WSAEnumProtocolsW)
#define WSAStringToAddressW U(WSAStringToAddressW)
#define WSAAddressToStringW U(WSAAddressToStringW)
#define WSALookupServiceBeginW U(WSALookupServiceBeginW)
#define WSALookupServiceNextW U(WSALookupServiceNextW)
#define WSALookupServiceEnd U(WSALookupServiceEnd)
#define WSAAccept U(WSAAccept)
#define WSAConnect U(WSAConnect)
#define WSADuplicateSocketW U(WSADuplicateSocketW)
#define WSACancelBlockingCall U(WSACancelBlockingCall)
#define WSAUnhookBlockingHook U(WSAUnhookBlockingHook)
#define WSAIsBlocking U(WSAIsBlocking)
#define WSAHtonl U(WSAHtonl)
#define WSANtohl U(WSANtohl)
#define WSAHtons U(WSAHtons)
#define WSAAsyncSelect U(WSAAsyncSelect)
#define WSAAsyncGetHostByName U(WSAAsyncGetHostByName)
#define WSACancelAsyncRequest U(WSACancelAsyncRequest)
#define WSAGetServiceClassInfoW U(WSAGetServiceClassInfoW)
#define WSARemoveServiceClass U(WSARemoveServiceClass)
#define WSASetServiceW U(WSASetServiceW)
#define WSAEnumNameSpaceProvidersW U(WSAEnumNameSpaceProvidersW)
#define WSCEnumProtocols U(WSCEnumProtocols)
#define gethostbyname U(gethostbyname)
#define gethostbyaddr U(gethostbyaddr)
#define gethostname U(gethostname)
#define getservbyname U(getservbyname)
#define getservbyport U(getservbyport)
#define getprotobyname U(getprotobyname)
#define getprotobynumber U(getprotobynumber)
#define getaddrinfo U(getaddrinfo)
#define GetAddrInfoW U(GetAddrInfoW)
#define freeaddrinfo U(freeaddrinfo)
#define getnameinfo U(getnameinfo)
#define GetNameInfoW U(GetNameInfoW)
#define inet_addr U(inet_addr)
#define inet_pton U(inet_pton)
#define InetPtonW U(InetPtonW)

#define XE_UNK (-2)
#define XE_NOCALL (-1)           /* the call under test unexpectedly succeeded */
#define XE_BAD 0xdead
#define XE_ABORT_BIT 0

/* Row bookkeeping: report an observation or check it. */
static inline void xe_row_ll(const char *tag, const char *name, long long got, long long want) {
    if (want == XE_UNK) { t_note("ROW %s %s %lld", tag, name, got); return; }
    t_check(got == want, "x_error_mapping", 0, name, "%s: got %lld (0x%llx) want %lld (0x%llx)", tag, got, got, want, want);
}

extern int xe_gle_seen, xe_wsa_seen;
/* Evaluate to the Winsock error of a call that is required to have failed; -1 if it did not fail. Also records the
 * GetLastError value so the identity of the two slots can be examined. */
#define XE_FAIL(cond) ((cond) ? (xe_gle_seen = (int)GetLastError(), xe_wsa_seen = WSAGetLastError(), (long)xe_wsa_seen) : -1L)

int xe_up(void);
#define XE_UP() do { if (!xe_up()) { t_skip("ws2_32 unavailable"); return; } } while (0)

/* sockets */
SOCKET xe_sock(int type);                     /* AF_INET socket, overlapped-capable */
SOCKET xe_sock6(int type);
void xe_close(SOCKET s);
SOCKET xe_listener(struct sockaddr_in *a);    /* listening on 127.0.0.1:0, name returned */
void xe_pair(SOCKET *c, SOCKET *s);           /* connected TCP pair */
void xe_bind_lo(SOCKET s, struct sockaddr_in *a);
struct sockaddr_in xe_lo(USHORT port_be);
SOCKET xe_dead_port(struct sockaddr_in *a);   /* returns nothing useful; fills a with a loopback port nobody listens on */
void xe_wait_readable(SOCKET s, DWORD ms);
#define XE_BE16(x) ((USHORT)__builtin_bswap16((unsigned short)(x)))

/* ---- raw AFD ------------------------------------------------------------------------------------------------ */
typedef void (NTAPI *xe_apc)(PVOID, PIO_STATUS_BLOCK, ULONG);
typedef LONG (NTAPI *xe_NtIoctl)(HANDLE, HANDLE, xe_apc, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef struct { LONG status; ULONG_PTR info; } xe_r;
/* Submit one control request with a private event; when pending wait up to ms (then cancel) and report the final
 * status, or 0x102 when it did not complete. */
xe_r xe_afd(SOCKET s, ULONG code, void *in, ULONG inl, void *out, ULONG outl, DWORD ms);
xe_r xe_afd_connect(SOCKET s, const struct sockaddr_in *a);
xe_r xe_afd_bind(SOCKET s, const void *sa, ULONG salen);
xe_r xe_afd_recv(SOCKET s, void *b, ULONG n, ULONG tdi, DWORD ms);
xe_r xe_afd_send(SOCKET s, const void *b, ULONG n, DWORD ms);
xe_r xe_afd_disc(SOCKET s, ULONG flags);
xe_r xe_afd_listen(SOCKET s);
#define XE_IOCTL_BIND 0x12003u
#define XE_IOCTL_CONNECT 0x12007u
#define XE_IOCTL_LISTEN 0x1200bu
#define XE_IOCTL_RECV 0x12017u
#define XE_IOCTL_RECV_DG 0x1201bu
#define XE_IOCTL_SEND 0x1201fu
#define XE_IOCTL_SEND_DG 0x12023u
#define XE_IOCTL_DISC 0x1202bu
#define XE_IOCTL_ADDR 0x1202fu
#define XE_IOCTL_ACCEPT 0x12010u
#define XE_IOCTL_REMOTE 0x1203fu
#define XE_ST(x) ((long long)(unsigned long)(x))
#endif
