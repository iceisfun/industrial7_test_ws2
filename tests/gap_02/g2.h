/* Shared declarations for the gap_02 area: public Winsock exports with thin coverage elsewhere
 * (service-class and registration calls, name-space catalog and lookup calls, address-info calls, the
 * connection helpers and the name-space provider entry point of the DNS provider).
 * The libraries under test are never linked: every entry point is reached through
 * LoadLibrary -> GetProcAddress (WS() pins ws2_32.dll, MS() pins mswsock.dll). */
#ifndef G2_H
#define G2_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2spi.h>
#include <mswsock.h>
#include <nspapi.h>
#include <wchar.h>

/* The harness macros evaluate their operands twice; most calls here have side effects. */
#undef EXPECT_EQ
#define EXPECT_EQ(a, b) do { unsigned long long ea_ = (unsigned long long)(ULONG_PTR)(a), eb_ = (unsigned long long)(ULONG_PTR)(b); \
    t_check(ea_ == eb_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", ea_, eb_); } while (0)
#undef EXPECT_NE
#define EXPECT_NE(a, b) do { unsigned long long ea_ = (unsigned long long)(ULONG_PTR)(a), eb_ = (unsigned long long)(ULONG_PTR)(b); \
    t_check(ea_ != eb_, __FILE__, __LINE__, #a " != " #b, "got 0x%llx", ea_); } while (0)

#define WS(name) UIN("ws2_32.dll", name)
#define MS(name) UIN("mswsock.dll", name)
#define G2_N(a) ((int)(sizeof(a) / sizeof((a)[0])))

/* Error values spelled numerically so expectations do not depend on header spellings. */
#define GE_FAULT       10014   /* WSAEFAULT */
#define GE_INVAL       10022   /* WSAEINVAL */
#define GE_NOTSOCK     10038   /* WSAENOTSOCK */
#define GE_OPNOTSUPP   10045   /* WSAEOPNOTSUPP */
#define GE_AFNOSUPPORT 10047   /* WSAEAFNOSUPPORT */
#define GE_ADDRNOTAVAIL 10049  /* WSAEADDRNOTAVAIL */
#define GE_NOTINIT     10093   /* WSANOTINITIALISED */
#define GE_INVPROCTAB  10104   /* WSAEINVALIDPROCTABLE */
#define GE_NOTFOUND    10108   /* WSASERVICE_NOT_FOUND */
#define GE_NO_MORE     10110   /* WSA_E_NO_MORE */
#define GE_NODATA      11004   /* WSANO_DATA */
#define GE_NOTSUPP32   50      /* ERROR_NOT_SUPPORTED */
#define GE_BADHANDLE   6       /* ERROR_INVALID_HANDLE */

#define W_ERR()        (WS(WSAGetLastError)())
#define W_SETERR(e)    (WS(WSASetLastError)(e))

/* WSAStartup(2.2) once for the process; nonzero when sockets are usable. */
int g2_up(void);
#define G2_NEED() do { if (!g2_up()) { t_skip("WSAStartup failed"); return; } } while (0)

/* ---- sockets ---- */
SOCKET g2_tcp4(void);                         /* unbound AF_INET stream socket, INVALID_SOCKET on failure */
SOCKET g2_udp4(void);
SOCKET g2_tcp6(void);                         /* AF_INET6 stream; INVALID_SOCKET when v6 is unavailable */
SOCKET g2_listen4(unsigned short *port_be);   /* loopback listener on an ephemeral port (network order out) */
void   g2_close(SOCKET s);
void   g2_loop4(struct sockaddr_in *sa, unsigned short port_be);
int    g2_bind_any4(SOCKET s);                /* bind to loopback port 0 */
/* Connect s to a listener and accept; returns the accepted socket or INVALID_SOCKET. */
SOCKET g2_connect_accept(SOCKET lst, SOCKET cli);

/* ---- names / providers ---- */
extern const GUID g2_guid_throwaway;          /* id owned by this corpus; no real provider or class uses it */
extern const GUID g2_svc_hostname;
extern const GUID g2_svc_addr_by_name;
/* Provider id of the active catalog entry for a name space (W catalog); 0 when none. */
int g2_provider_for(DWORD ns, GUID *id);
/* Copy of the whole W catalog (HeapAlloc'd; free with g2_free); *n entries, NULL on failure. */
WSANAMESPACE_INFOW *g2_catalog(int *n);
void g2_free(void *p);
int  g2_is_elevated(void);

void g2_qs_w(WSAQUERYSETW *qs, LPWSTR name, const GUID *cls, DWORD ns);
void g2_qs_a(WSAQUERYSETA *qs, LPSTR name, const GUID *cls, DWORD ns);
int  g2_wide_to_ansi_equal(const WCHAR *w, const char *a);   /* a is the code-page narrowing of w */
#endif
