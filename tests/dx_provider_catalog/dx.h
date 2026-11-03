/* Shared helpers for the dx_provider_catalog area (guarded mutation of the Winsock provider catalogs).
 *
 * Every catalog entry, namespace provider and application category this area creates carries a throwaway
 * identity (see dx_guid): the first GUID field is a fixed marker, the rest derives from a small index, so
 * leftovers of an earlier crashed run are recognisable and swept before and after every test. Nothing here
 * ever touches an entry it did not create. The libraries under test are never linked: every entry point is
 * reached through LoadLibrary -> GetProcAddress (t_proc_in). */
#ifndef DX_H
#define DX_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2spi.h>
#include <stdlib.h>

/* The harness macros evaluate their operands twice; the calls in this area have side effects (installs,
 * order changes), so the operands are evaluated exactly once here. */
#undef EXPECT_EQ
#define EXPECT_EQ(a, b) do { unsigned long long ea_ = (unsigned long long)(ULONG_PTR)(a), eb_ = (unsigned long long)(ULONG_PTR)(b); \
    t_check(ea_ == eb_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", ea_, eb_); } while (0)
#undef EXPECT_NE
#define EXPECT_NE(a, b) do { unsigned long long ea_ = (unsigned long long)(ULONG_PTR)(a), eb_ = (unsigned long long)(ULONG_PTR)(b); \
    t_check(ea_ != eb_, __FILE__, __LINE__, #a " != " #b, "got 0x%llx", ea_); } while (0)

#define DX_N(a) ((int)(sizeof(a) / sizeof((a)[0])))

/* Error values spelled numerically so expectations do not depend on header spellings. */
#define DXE_FAULT        10014  /* WSAEFAULT */
#define DXE_INVAL        10022  /* WSAEINVAL */
#define DXE_INVALIDPROC  10105  /* WSAEINVALIDPROVIDER */
#define DXE_PROVFAILED   10106  /* WSAEPROVIDERFAILEDINIT */
#define DXE_NOTFOUND     10108  /* WSASERVICE_NOT_FOUND */
#define DXE_NO_RECOVERY  11003  /* WSANO_RECOVERY */
#define DXE_NODATA       11004  /* WSANO_DATA */
#define DXE_REGFAIL      10107  /* WSASYSCALLFAILURE */

#define DX_INFO_SIZE 628        /* sizeof(WSAPROTOCOL_INFOW) */
#define DX_AF_BASE   0x7e00     /* address families no real socket will ever ask for */

/* Which catalog an operation addresses. */
enum { DX_NATIVE = 0, DX_WOW = 1 };

/* ---- throwaway identities ---- */
GUID dx_guid(unsigned idx);            /* provider / class / namespace id #idx of this area */
int  dx_is_ours(const GUID *g);        /* carries the area marker (any idx, any run) */

/* ---- raw entry points ---- */
typedef INT  (WSAAPI *dx_install_fn)(const GUID *, const WCHAR *, const WSAPROTOCOL_INFOW *, DWORD, LPINT);
typedef INT  (WSAAPI *dx_deinstall_fn)(const GUID *, LPINT);
typedef INT  (WSAAPI *dx_order_fn)(LPDWORD, DWORD);
typedef INT  (WSAAPI *dx_update_fn)(const GUID *, const WCHAR *, const WSAPROTOCOL_INFOW *, DWORD, LPINT);
typedef INT  (WSAAPI *dx_nsinstall_fn)(const WCHAR *, const WCHAR *, DWORD, DWORD, const GUID *);
typedef INT  (WSAAPI *dx_nsuninstall_fn)(const GUID *);
typedef INT  (WSAAPI *dx_nsenable_fn)(const GUID *, BOOL);
typedef INT  (WSAAPI *dx_enum_fn)(LPINT, LPWSAPROTOCOL_INFOW, LPDWORD, LPINT);
typedef INT  (WSAAPI *dx_enumw_fn)(LPINT, LPWSAPROTOCOL_INFOW, LPDWORD);
typedef INT  (WSAAPI *dx_enumnsw_fn)(LPDWORD, LPWSANAMESPACE_INFOW);

#define DX_FN(type, name) ((type)t_proc_in("ws2_32.dll", name))
#define DX_INSTALL      DX_FN(dx_install_fn, "WSCInstallProvider")
#define DX_INSTALL64_32 DX_FN(dx_install_fn, "WSCInstallProvider64_32")
#define DX_DEINSTALL    DX_FN(dx_deinstall_fn, "WSCDeinstallProvider")
#define DX_DEINSTALL32  DX_FN(dx_deinstall_fn, "WSCDeinstallProvider32")
#define DX_ORDER        DX_FN(dx_order_fn, "WSCWriteProviderOrder")
#define DX_ORDER32      DX_FN(dx_order_fn, "WSCWriteProviderOrder32")
#define DX_UPDATE       DX_FN(dx_update_fn, "WSCUpdateProvider")
#define DX_UPDATE32     DX_FN(dx_update_fn, "WSCUpdateProvider32")
#define DX_NSINSTALL    DX_FN(dx_nsinstall_fn, "WSCInstallNameSpace")
#define DX_NSINSTALL32  DX_FN(dx_nsinstall_fn, "WSCInstallNameSpace32")
#define DX_NSUNINSTALL  DX_FN(dx_nsuninstall_fn, "WSCUnInstallNameSpace")
#define DX_NSUNINSTALL32 DX_FN(dx_nsuninstall_fn, "WSCUnInstallNameSpace32")
#define DX_NSENABLE     DX_FN(dx_nsenable_fn, "WSCEnableNSProvider")
#define DX_NSENABLE32   DX_FN(dx_nsenable_fn, "WSCEnableNSProvider32")

/* ---- catalog views ---- */
typedef struct { WSAPROTOCOL_INFOW *e; int n; } dx_list;
/* which: 0 WSCEnumProtocols (native, SPI list incl. hidden), 1 WSCEnumProtocols32, 2 WSAEnumProtocolsW (API list). */
int  dx_enum(int which, dx_list *out);   /* entry count, -1 on failure */
int  dx_enum_f(int which, INT *filter, dx_list *out);   /* same with a protocol filter (zero terminated) */
void dx_free(dx_list *l);
const WSAPROTOCOL_INFOW *dx_by_id(const dx_list *l, DWORD id);
int  dx_index_of_id(const dx_list *l, DWORD id);              /* -1 when absent */
int  dx_count_guid(const dx_list *l, const GUID *g);
const WSAPROTOCOL_INFOW *dx_first_guid(const dx_list *l, const GUID *g);
int  dx_has_guid(int which, const GUID *g);                    /* fresh enumeration */
/* The API list is refreshed lazily after a catalog change; poll (bounded) until `g` is present/absent. */
int  dx_api_wait_guid(const GUID *g, int present);
/* The API lists are cached per process, so they are read in a fresh child process that loads the catalog from
 * its persistent store. Exit code of the child: 0 condition true, 1 false, anything else an error. */
int  dx_child_query(const char *fmt, ...);
unsigned dx_guid_index(const GUID *g);                          /* index given to dx_guid() */

typedef struct { WSANAMESPACE_INFOW *e; int n; } dx_nslist;
int  dx_ns_enum(dx_nslist *out);
void dx_ns_free(dx_nslist *l);
const WSANAMESPACE_INFOW *dx_ns_by_guid(const dx_nslist *l, const GUID *g);
int  dx_ns_wait_guid(const GUID *g, int present);

/* ---- entry builders ---- */
const WCHAR *dx_dll_path(void);                                /* the stock mswsock path, unexpanded form */
void dx_base_entry(WSAPROTOCOL_INFOW *p, unsigned idx);        /* a base provider record on a private family */
void dx_layered_entry(WSAPROTOCOL_INFOW *p, unsigned idx);     /* chain length 0 placeholder */
void dx_chain_entry(WSAPROTOCOL_INFOW *p, unsigned idx, DWORD layered_id, DWORD base_id); /* chain length 2 */

/* Install helpers: return 0 on success else the lpErrno value (never 0 on failure; -1 when export missing). */
int  dx_install_one(const GUID *g, const WSAPROTOCOL_INFOW *p);                 /* DX_INSTALL, dx_dll_path */
int  dx_install64_32_one(const GUID *g, const WSAPROTOCOL_INFOW *p);
DWORD dx_id_of(int which, const GUID *g);
int  dx_path_of(const GUID *g, WCHAR *out, int cch);           /* WSCGetProviderPath; 0 on success else error */                      /* catalog id of the first entry for g, 0 if none */

/* ---- guard ---- */
/* Call first in every test. Returns 1 when the area may mutate the catalog; otherwise it has already
 * called t_skip with the reason and the test must return. Sweeps leftovers on entry. */
int  dx_begin(void);
#define DX_BEGIN() do { if (!dx_begin()) return; } while (0)
/* Call last (and it also runs at process exit): removes everything created, restores provider order and
 * checks that the catalogs are identical to the baseline taken at the first dx_begin. */
void dx_end(void);

int  dx_elevated(void);
extern int dx_ns_order_dirty;                                   /* set by tests that rewrite the name-space order */
int  dx_wow_available(void);                                   /* the 32-bit catalog operations exist */
void dx_sweep(void);                                           /* silent removal of every item of ours */

/* Baseline comparison for custom assertions: 1 when native/WOW protocol catalogs equal the baseline. */
int  dx_native_matches_baseline(void);
int  dx_wow_matches_baseline(void);
int  dx_ns_matches_baseline(void);
int  dx_baseline_count(void);

/* Application category entry points (not declared in the SDK headers). */
typedef int (WSAAPI *dx_appget_fn)(const WCHAR *, DWORD, const WCHAR *, DWORD, DWORD *, LPINT);
typedef int (WSAAPI *dx_appset_fn)(const WCHAR *, DWORD, const WCHAR *, DWORD, DWORD, DWORD *, LPINT);
#define DX_APPGET DX_FN(dx_appget_fn, "WSCGetApplicationCategory")
#define DX_APPSET DX_FN(dx_appset_fn, "WSCSetApplicationCategory")
/* The throwaway application path used for category entries (never exists on disk). */
extern const WCHAR dx_app_path[];
extern const WCHAR dx_app_path2[];
#endif
