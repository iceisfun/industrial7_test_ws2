/* Shared helpers for the gap_01 area: extra depth for the catalog-writer, provider-SPI and notification
 * exports of ws2_32.dll that other areas touch only lightly.
 *
 * Everything in this area is non-destructive: each call either fails before it would write anything, or is
 * a pure query. After every failing call the affected catalogs are compared with a signature taken before it.
 * The DLL under test is never linked; every entry point is reached with LoadLibrary -> GetProcAddress.
 * Scenarios that need a pristine process (nothing started yet) run in a child: exe --child <name>. */
#ifndef G1_H
#define G1_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2spi.h>
#include <stdlib.h>

/* The harness macros evaluate their operands twice; calls here have side effects. */
#undef EXPECT_EQ
#define EXPECT_EQ(a, b) do { unsigned long long ea_ = (unsigned long long)(ULONG_PTR)(a), eb_ = (unsigned long long)(ULONG_PTR)(b); \
    t_check(ea_ == eb_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", ea_, eb_); } while (0)

#define G1_N(a) ((int)(sizeof(a) / sizeof((a)[0])))
#define G1_STEP(n, c) do { if (!(c)) return (n); } while (0)
#define G1_NOERR 0x55555555     /* sentinel written into an error out-parameter before a call */

/* Error values spelled numerically so expectations do not depend on header spellings. */
#define G1E_FAULT       10014   /* WSAEFAULT */
#define G1E_INVAL       10022   /* WSAEINVAL */
#define G1E_NOTINIT     10093   /* WSANOTINITIALISED */
#define G1E_INVPROCTBL  10104   /* WSAEINVALIDPROCTABLE */
#define G1E_NOTFOUND    10108   /* WSASERVICE_NOT_FOUND */
#define G1E_NORECOVERY  11003   /* WSANO_RECOVERY */
#define G1E_NODATA      11004   /* WSANO_DATA */
#define G1E_PENDING     997     /* ERROR_IO_PENDING (WSA_IO_PENDING) */
#define G1E_CALLNOTIMPL 120     /* ERROR_CALL_NOT_IMPLEMENTED */

void *g1_fn(const char *name);                  /* export of ws2_32.dll, NULL when absent */
#define G1_NEED(p) do { if (!(p)) { t_skip("missing export: " #p); return; } } while (0)

int  g1_up(void);                               /* WSAStartup(2.2) once per process; 0 on success */
#define G1_UP() do { if (g1_up()) { t_skip("WSAStartup failed"); return; } } while (0)
int  g1_elevated(void);

/* Catalog signatures: entry count plus a hash over the identifying fields. */
typedef struct { int n; unsigned long long h; } g1_sig;
int  g1_proto_sig(int wow, g1_sig *s);          /* 0 native SPI list, 1 32-bit list; 0 ok, -1 unreadable */
int  g1_ns32_sig(g1_sig *s);                    /* 32-bit name-space catalog */
int  g1_ns_native_sig(unsigned *code);          /* native name-space catalog, read in a fresh process */
int  g1_sig_eq(const g1_sig *a, const g1_sig *b);

/* Provider ids / name-space ids present in the stock catalogs (de-duplicated). */
int  g1_proto_ids(int wow, GUID *out, int max);
int  g1_ns_ids(int wow, GUID *out, DWORD *ns, int max);

/* A complete snapshot of the three catalogs, taken and compared in one step. */
typedef struct { g1_sig nat, wow, ns32; unsigned nsnat; int ok_wow, ok_ns32, ok_nsnat; } g1_snapshot;
void g1_snap(g1_snapshot *s);
int  g1_snap_same(const g1_snapshot *before);   /* 1 when every readable catalog equals the snapshot */

extern const GUID g1_guid_a, g1_guid_b, g1_guid_zero, g1_guid_ones;
void g1_fill_w(WCHAR *dst, int len, WCHAR c);   /* len characters followed by a terminator */
void g1_base_info(WSAPROTOCOL_INFOW *p, int af);  /* a plausible one-entry base provider record */
#endif
