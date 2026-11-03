/* Shared declarations for the name-space lookup area.
 * Nothing here links the libraries under test: every entry point is reached through
 * LoadLibrary -> GetProcAddress (UIN pins ws2_32.dll). */
#ifndef NSP_H
#define NSP_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2spi.h>
#include <nspapi.h>
#include <wchar.h>

/* Single-evaluation equality check: the harness macro evaluates its arguments twice, which is
 * wrong for calls with side effects (Next, End, startup). */
#undef EXPECT_EQ
#define EXPECT_EQ(a, b) do { ULONG_PTR a_ = (ULONG_PTR)(a), b_ = (ULONG_PTR)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", (unsigned long long)a_, (unsigned long long)b_); } while (0)

#define NSP_N(a) (sizeof(a) / sizeof((a)[0]))
#define NSP_SZ_QS_W 0x78u   /* x64 sizeof(WSAQUERYSETW) */

/* Last-error values spelled numerically so the expectations do not depend on header spellings. */
#define E_FAULT        10014u   /* WSAEFAULT */
#define E_INVAL        10022u   /* WSAEINVAL */
#define E_NOTINIT      10093u   /* WSANOTINITIALISED */
#define E_SVC_NOTFOUND 10108u   /* WSASERVICE_NOT_FOUND */
#define E_NO_MORE      10110u   /* WSA_E_NO_MORE */
#define E_NODATA       11004u   /* WSANO_DATA */
#define E_BADHANDLE    6u       /* ERROR_INVALID_HANDLE / WSA_INVALID_HANDLE */
#define E_BADPARAM     87u      /* ERROR_INVALID_PARAMETER / WSA_INVALID_PARAMETER */

/* WSAStartup(2.2) once; nonzero when sockets are usable. */
int nsp_up(void);
#define NSP_NEED() do { if (!nsp_up()) { t_skip("WSAStartup failed"); return; } } while (0)

extern const GUID nsp_svcid_hostname;        /* host-name service class */
extern const GUID nsp_svcid_addr_by_string;  /* address-by-numeric-string class */
extern const GUID nsp_svcid_service_by_name; /* service-by-name class */
extern const GUID nsp_svcid_addr_by_name;    /* address-by-name class */
extern const GUID nsp_guid_nla;              /* NLA name-space provider id */
extern const GUID nsp_guid_throwaway;        /* class/provider id used by the guarded installs */

/* Typed entry points (ws2_32.dll). */
#define W_BEGIN_W   UIN("ws2_32.dll", WSALookupServiceBeginW)
#define W_BEGIN_A   UIN("ws2_32.dll", WSALookupServiceBeginA)
#define W_NEXT_W    UIN("ws2_32.dll", WSALookupServiceNextW)
#define W_NEXT_A    UIN("ws2_32.dll", WSALookupServiceNextA)
#define W_END       UIN("ws2_32.dll", WSALookupServiceEnd)
#define W_ERR       UIN("ws2_32.dll", WSAGetLastError)
#define W_SETERR    UIN("ws2_32.dll", WSASetLastError)

/* Fill a WSAQUERYSETW for a plain name query. The set is zeroed first; dwSize is the real size. */
void nsp_query_w(WSAQUERYSETW *qs, LPWSTR name, const GUID *cls, DWORD ns);
void nsp_query_a(WSAQUERYSETA *qs, LPSTR name, const GUID *cls, DWORD ns);

/* Provider id of the catalog entry for a name space, via WSAEnumNameSpaceProvidersW. 0 when absent. */
int nsp_provider_for(DWORD ns, GUID *id);

/* A result buffer that grows on WSAEFAULT. */
typedef struct { BYTE *p; DWORD cap; DWORD need; } nsp_buf;
void nsp_buf_free(nsp_buf *b);
/* One Next call with the documented size protocol; returns 0 on success else the WSA error.
 * *grew reports whether a WSAEFAULT/retry round happened, b->need the size the DLL asked for. */
int nsp_next_w(HANDLE h, DWORD flags, nsp_buf *b, int *grew);
int nsp_next_a(HANDLE h, DWORD flags, nsp_buf *b, int *grew);

/* Begin + drain; returns the number of results (>= 0), -1 when Begin failed (error in *err_begin).
 * The last Next error is stored in *err_last. */
int nsp_count_w(const WSAQUERYSETW *qs, DWORD flags, int *err_begin, int *err_last);

/* True when every sockaddr in the CSADDR array is loopback; *n counts addresses seen. */
int nsp_csaddrs_loopback(const CSADDR_INFO *c, DWORD count, int *n);
#endif
