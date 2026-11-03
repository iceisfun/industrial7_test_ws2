/* Shared helpers for the GetAddrInfoEx asynchronous / struct-version area.
 * ws2_32 is never linked: every service is reached through U()/UN() function pointers.
 * Only loopback names and literals are ever resolved. */
#ifndef GX_H
#define GX_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>

/* ws2_32 is not linked: byte order helpers are local. */
static unsigned short gx_bs16(unsigned short v) { return (unsigned short)((v << 8) | (v >> 8)); }
static unsigned long gx_bs32(unsigned long v) { return ((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v >> 8) & 0xff00) | ((v >> 24) & 0xff); }
#undef ntohs
#undef htons
#undef htonl
#undef ntohl
#define ntohs(x) gx_bs16(x)
#define htons(x) gx_bs16(x)
#define htonl(x) gx_bs32(x)
#define ntohl(x) gx_bs32(x)
/* Single-evaluation equality check (EXPECT_EQ evaluates its operands twice, which is wrong for API calls). */
#define GX_EQ(a, b) do { long long a_ = (long long)(a), b_ = (long long)(b); \
    t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", a_, b_); } while (0)
#define NARR(a) (sizeof(a) / sizeof((a)[0]))

/* The SDK-visible ADDRINFOEXW stops at ai_next; later versions append fields. This is the full v5 layout. */
typedef struct gx_ex {
    int      ai_flags, ai_family, ai_socktype, ai_protocol;
    size_t   ai_addrlen;
    PWSTR    ai_canonname;
    struct sockaddr *ai_addr;
    void    *ai_blob;
    size_t   ai_bloblen;
    LPGUID   ai_provider;
    struct gx_ex *ai_next;
    int      ai_version;
    PWSTR    ai_fqdn;
    int      ai_interfaceindex;
    HANDLE   ai_resolutionhandle;
    int      ai_ttl;
} GXEX;
typedef struct gx_exa {
    int      ai_flags, ai_family, ai_socktype, ai_protocol;
    size_t   ai_addrlen;
    PSTR     ai_canonname;
    struct sockaddr *ai_addr;
    void    *ai_blob;
    size_t   ai_bloblen;
    LPGUID   ai_provider;
    struct gx_exa *ai_next;
    int      ai_version;
    PSTR     ai_fqdn;
} GXEXA;

UDECL(int, GetAddrInfoExCancel, (HANDLE *handle));
UDECL(int, GetAddrInfoExOverlappedResult, (LPOVERLAPPED ov));
typedef int (WINAPI *gx_getw_fn)(PCWSTR, PCWSTR, DWORD, LPGUID, const void *, void **, struct timeval *, LPOVERLAPPED, PVOID, HANDLE *);
typedef int (WINAPI *gx_geta_fn)(PCSTR, PCSTR, DWORD, LPGUID, const void *, void **, struct timeval *, LPOVERLAPPED, PVOID, HANDLE *);
typedef void (CALLBACK *gx_cr_fn)(DWORD, DWORD, LPOVERLAPPED);

/* SVCID_HOSTNAME {0002A800-0000-0000-C000-000000000046}: the host-name service class. */
static const GUID gx_svcid_hostname = {0x0002A800, 0, 0, {0xC0, 0, 0, 0, 0, 0, 0, 0x46}};
#define GXFREE(p) (U(FreeAddrInfoExW)((PADDRINFOEXW)(p)))
#define GXW() ((gx_getw_fn)t_proc("GetAddrInfoExW"))
#define GXA() ((gx_geta_fn)t_proc("GetAddrInfoExA"))
#define WSERR()     (U(WSAGetLastError)())
#define SETWSERR(e) (U(WSASetLastError)(e))

static int gx_up(void)
{
    WSADATA d;
    if (!U(WSAStartup)) return -1;
    return U(WSAStartup)(0x202, &d);
}
static void gx_down(void) { if (U(WSACleanup)) U(WSACleanup)(); }

#define GX_BEGIN() \
    do { if (!GXW() || !U(FreeAddrInfoExW) || !UN(GetAddrInfoExOverlappedResult) || !UN(GetAddrInfoExCancel) \
             || !U(WSAGetLastError) || !U(WSASetLastError)) { t_skip("missing export"); return; } \
         if (gx_up()) { t_skip("WSAStartup failed"); return; } } while (0)
#define GX_END() gx_down()

static WCHAR *gx_w(const char *s)
{
    static WCHAR buf[8][300];
    static int n;
    WCHAR *b = buf[n++ & 7];
    int i = 0;
    for (; s[i] && i < 299; i++) b[i] = (unsigned char)s[i];
    b[i] = 0;
    return b;
}
/* ASCII rendering of a wide string, '?' for non-ASCII, "(null)" for NULL. */
static const char *gx_s(const WCHAR *w)
{
    static char buf[8][300];
    static int n;
    char *b = buf[n++ & 7];
    int i = 0;
    if (!w) return "(null)";
    for (; w[i] && i < 299; i++) b[i] = (w[i] < 128) ? (char)w[i] : '?';
    b[i] = 0;
    return b;
}
/* Loopback address text for a result entry. */
static const char *gx_addr(const struct sockaddr *sa, size_t len)
{
    static char buf[8][80];
    static int n;
    char *b = buf[n++ & 7];
    if (!sa) return "(null)";
    if (sa->sa_family == AF_INET && len == sizeof(struct sockaddr_in)) {
        const unsigned char *p = (const unsigned char *)&((const struct sockaddr_in *)sa)->sin_addr;
        snprintf(b, 80, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    } else if (sa->sa_family == AF_INET6 && len == sizeof(struct sockaddr_in6)) {
        const unsigned short *p = (const unsigned short *)&((const struct sockaddr_in6 *)sa)->sin6_addr;
        snprintf(b, 80, "v6:%x:%x:%x:%x:%x:%x:%x:%x", ntohs(p[0]), ntohs(p[1]), ntohs(p[2]), ntohs(p[3]),
                 ntohs(p[4]), ntohs(p[5]), ntohs(p[6]), ntohs(p[7]));
    } else snprintf(b, 80, "af%d/len%d", sa->sa_family, (int)len);
    return b;
}
static int gx_port(const struct sockaddr *sa)
{
    if (!sa) return -1;
    if (sa->sa_family == AF_INET) return ntohs(((const struct sockaddr_in *)sa)->sin_port);
    if (sa->sa_family == AF_INET6) return ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
    return -2;
}
static int gx_count(const GXEX *r) { int n = 0; for (; r; r = r->ai_next) n++; return n; }

static const WCHAR gx_localhost[] = {'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0};
/* A literal that always resolves without a lookup, used where the test is about the call protocol. */
static const WCHAR gx_lit4[] = {'1', '2', '7', '.', '0', '.', '0', '.', '1', 0};

/* Wait for an event handle for at most 5 seconds (bounded; never timed tightly). */
static DWORD gx_wait(HANDLE h) { return WaitForSingleObject(h, 5000); }

/* Run one overlapped event-mode query and wait for it. Returns the call's return value; *fin gets the
 * final status after the wait (or -1 if the wait timed out). */
static int gx_event_query(const WCHAR *name, const WCHAR *svc, DWORD ns, const GXEX *hint, GXEX **res, OVERLAPPED *ov,
                          int *fin, struct timeval *tv)
{
    int r;
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(ov, 0, sizeof *ov);
    ov->hEvent = ev;
    *res = NULL;
    r = GXW()(name, svc, ns, NULL, hint, (void **)res, tv, ov, NULL, NULL);
    *fin = -1;
    if (r == ERROR_IO_PENDING) {
        if (gx_wait(ev) == WAIT_OBJECT_0) *fin = UN(GetAddrInfoExOverlappedResult)(ov);
    }
    CloseHandle(ev);
    return r;
}

/* ---- synchronous query result record -------------------------------------------------------- */
static GXEX gx_sentinel_ex;    /* never freed; proves that a failing call cleared the result slot */
typedef struct { int ret, wsa; GXEX *res; } gx_res;

/* One synchronous GetAddrInfoExW call (no overlapped). The result slot starts at the sentinel and the
 * thread error slot at a marker so both "cleared" and "untouched" are observable. */
static gx_res gx_call(const char *name, const char *svc, DWORD ns, const GXEX *hint)
{
    gx_res r;
    r.res = &gx_sentinel_ex;
    SETWSERR(0x7777);
    r.ret = GXW()(name ? gx_w(name) : NULL, svc ? gx_w(svc) : NULL, ns, NULL, hint, (void **)&r.res, NULL, NULL, NULL, NULL);
    r.wsa = WSERR();
    return r;
}
static void gx_release(gx_res *r) { if (r->res && r->res != &gx_sentinel_ex) GXFREE(r->res); r->res = NULL; }
static GXEX gx_hint(int flags, int family, int socktype, int protocol)
{
    GXEX h;
    memset(&h, 0, sizeof h);
    h.ai_flags = flags; h.ai_family = family; h.ai_socktype = socktype; h.ai_protocol = protocol;
    return h;
}
/* Family sequence of a chain as a string, e.g. "23,2". */
static const char *gx_fams(const GXEX *r)
{
    static char buf[8][64];
    static int n;
    char *b = buf[n++ & 7];
    int len = 0;
    b[0] = 0;
    for (; r && len < 50; r = r->ai_next) len += snprintf(b + len, 64 - len, "%s%d", len ? "," : "", r->ai_family);
    return b;
}
/* Expect a successful single-address answer for a numeric/literal name. */
#define GX_IS_V4(e, text) (e && (e)->ai_family == AF_INET && !strcmp(gx_addr((e)->ai_addr, (e)->ai_addrlen), text))
#define GX_IS_V6LOOP(e) (e && (e)->ai_family == AF_INET6 && !strcmp(gx_addr((e)->ai_addr, (e)->ai_addrlen), "v6:0:0:0:0:0:0:0:1"))

/* Wait for a thread-pool completion routine event; returns WAIT_* . */
typedef struct { HANDLE done; volatile LONG calls; DWORD err, bytes; LPOVERLAPPED ov; DWORD tid; } gx_cb;
static gx_cb gx_cbs;
static void gx_cb_reset(void) { memset(&gx_cbs, 0, sizeof gx_cbs); gx_cbs.done = CreateEventW(NULL, TRUE, FALSE, NULL); }
static void gx_cb_close(void) { CloseHandle(gx_cbs.done); gx_cbs.done = NULL; }
static void CALLBACK gx_cb_routine(DWORD err, DWORD bytes, LPOVERLAPPED ov)
{
    gx_cbs.err = err; gx_cbs.bytes = bytes; gx_cbs.ov = ov; gx_cbs.tid = GetCurrentThreadId();
    InterlockedIncrement(&gx_cbs.calls);
    SetEvent(gx_cbs.done);
}

/* Slots for cancel tests: OVERLAPPED, result pointer, cancel handle and event live in static storage that is
 * never reused, so a late write by the worker after a cancel can never land in a recycled stack frame. */
typedef struct { OVERLAPPED ov; GXEX *res; HANDLE h; HANDLE ev; } gx_slot;
static gx_slot gx_slots[256];
static int gx_slot_count;
static gx_slot *gx_slot_new(void)
{
    gx_slot *s = &gx_slots[gx_slot_count++ % 256];
    memset(s, 0, sizeof *s);
    s->ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    s->ov.hEvent = s->ev;
    return s;
}
#endif
