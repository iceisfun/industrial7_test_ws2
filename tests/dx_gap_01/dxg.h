/* Shared helpers for the dx_gap_01 area: state-changing depth for the name-space and chained-install exports.
 *
 * Every entry this area creates carries a throwaway identity (a fixed marker plus a small index); each test
 * removes what it made, and a sweep at the start and at exit removes leftovers of an earlier crashed run.
 * Skipped unless the process is elevated. The DLL under test is never linked: LoadLibrary -> GetProcAddress. */
#ifndef DXG_H
#define DXG_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2spi.h>
#include <stdlib.h>

/* The harness macros evaluate their operands twice; calls here have side effects. */
#undef EXPECT_EQ
#define EXPECT_EQ(a, b) do { unsigned long long ea_ = (unsigned long long)(ULONG_PTR)(a), eb_ = (unsigned long long)(ULONG_PTR)(b); \
    t_check(ea_ == eb_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", ea_, eb_); } while (0)

#define DXG_N(a) ((int)(sizeof(a) / sizeof((a)[0])))
#define DXG_STEP(n, c) do { if (!(c)) return (n); } while (0)
#define DXG_NOERR 0x55555555     /* sentinel written into an error out-parameter before a call */

/* Error values spelled numerically so expectations do not depend on header spellings. */
#define DXGE_FAULT       10014   /* WSAEFAULT */
#define DXGE_INVAL       10022   /* WSAEINVAL */
#define DXGE_NOTINIT     10093   /* WSANOTINITIALISED */
#define DXGE_INVPROCTBL  10104   /* WSAEINVALIDPROCTABLE */
#define DXGE_NOTFOUND    10108   /* WSASERVICE_NOT_FOUND */
#define DXGE_NORECOVERY  11003   /* WSANO_RECOVERY */
#define DXGE_NODATA      11004   /* WSANO_DATA */
#define DXGE_PENDING     997     /* ERROR_IO_PENDING (WSA_IO_PENDING) */
#define DXGE_CALLNOTIMPL 120     /* ERROR_CALL_NOT_IMPLEMENTED */

void *dxg_fn(const char *name);                  /* export of ws2_32.dll, NULL when absent */
#define DXG_NEED(p) do { if (!(p)) { t_skip("missing export: " #p); return; } } while (0)

int  dxg_up(void);                               /* WSAStartup(2.2) once per process; 0 on success */
#define DXG_UP() do { if (dxg_up()) { t_skip("WSAStartup failed"); return; } } while (0)
int  dxg_elevated(void);

/* Catalog signatures: entry count plus a hash over the identifying fields. */
typedef struct { int n; unsigned long long h; } dxg_sig;
int  dxg_proto_sig(int wow, dxg_sig *s);          /* 0 native SPI list, 1 32-bit list; 0 ok, -1 unreadable */
int  dxg_ns32_sig(dxg_sig *s);                    /* 32-bit name-space catalog */
int  dxg_ns_native_sig(unsigned *code);          /* native name-space catalog, read in a fresh process */
int  dxg_sig_eq(const dxg_sig *a, const dxg_sig *b);

/* Provider ids / name-space ids present in the stock catalogs (de-duplicated). */
int  dxg_proto_ids(int wow, GUID *out, int max);
int  dxg_ns_ids(int wow, GUID *out, DWORD *ns, int max);

/* A complete snapshot of the three catalogs, taken and compared in one step. */
typedef struct { dxg_sig nat, wow, ns32; unsigned nsnat; int ok_wow, ok_ns32, ok_nsnat; } dxg_snapshot;
void dxg_snap(dxg_snapshot *s);
int  dxg_snap_same(const dxg_snapshot *before);   /* 1 when every readable catalog equals the snapshot */

extern const GUID dxg_guid_a, dxg_guid_b, dxg_guid_zero, dxg_guid_ones;
void dxg_fill_w(WCHAR *dst, int len, WCHAR c);   /* len characters followed by a terminator */
void dxg_base_info(WSAPROTOCOL_INFOW *p, int af);  /* a plausible one-entry base provider record */
#endif
