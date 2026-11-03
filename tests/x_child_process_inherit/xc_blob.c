/* x_child_process_inherit / blob: edge cases of the WSADuplicateSocket blob: a missing blob buffer, a blob used twice,
 * a blob used by a process other than its target, damaged blobs, and the ANSI form. The target process reports what
 * its WSASocket calls returned through its exit code. */
#include "xc.h"

/* Start <name> with a pipe whose read end is argv[1]; the caller writes the blob bytes into *wr. */
static HANDLE spawn_pipe(const char *name, const char *args, HANDLE *wr)
{
    HANDLE rd, list[1], p; SECURITY_ATTRIBUTES sa; char a[512];
    sa.nLength = sizeof sa; sa.lpSecurityDescriptor = NULL; sa.bInheritHandle = TRUE;
    if (!CreatePipe(&rd, wr, &sa, 4096)) return NULL;
    SetHandleInformation(*wr, HANDLE_FLAG_INHERIT, 0);
    list[0] = rd;
    snprintf(a, sizeof a, "%llu %s", (unsigned long long)(ULONG_PTR)rd, args ? args : "");
    p = xc_spawn(name, a, list, 1, NULL);
    CloseHandle(rd);
    if (!p) { CloseHandle(*wr); *wr = NULL; }
    return p;
}

/* mode 'w': two WSASocketW calls from one blob; 'a': one WSASocketA call from an ANSI blob. Exit code: bit0 first
 * call worked, bit1 second call worked, bit2 the first socket is a stream socket, bits 8..15 error class of the first, bits 16..23 error class of the second. */
CHILD(blob_try)
{
    HANDLE pipe = (HANDLE)(ULONG_PTR)_strtoui64(argv[1], NULL, 10); char mode = argv[2][0]; DWORD n = 0; unsigned r = 0;
    union { WSAPROTOCOL_INFOW w; WSAPROTOCOL_INFOA a; } pi;
    SOCKET s1 = INVALID_SOCKET, s2 = INVALID_SOCKET;
    xc_child_up();
    memset(&pi, 0, sizeof pi);
    ReadFile(pipe, &pi, mode == 'a' ? sizeof pi.a : sizeof pi.w, &n, NULL);
    if (mode == 'a') {
        s1 = U(WSASocketA)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pi.a, 0, OVLD);
    } else {
        s1 = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pi.w, 0, OVLD);
        if (s1 != INVALID_SOCKET) { r |= 1; int ty = 0, tl = sizeof ty; xc_setwerr(0); if (U(getsockopt)(s1, SOL_SOCKET, SO_TYPE, (char *)&ty, &tl) == 0) { if (ty == SOCK_STREAM) r |= 4; } else r |= xc_e8(xc_werr()) << 24; } else r |= xc_e8(xc_werr()) << 8;
        s2 = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &pi.w, 0, OVLD);
        if (s2 != INVALID_SOCKET) r |= 2; else r |= xc_e8(xc_werr()) << 16;
        xc_close(s1); xc_close(s2);
        return (int)r;
    }
    if (s1 != INVALID_SOCKET) { r |= 1; int ty = 0, tl = sizeof ty; xc_setwerr(0); if (U(getsockopt)(s1, SOL_SOCKET, SO_TYPE, (char *)&ty, &tl) == 0) { if (ty == SOCK_STREAM) r |= 4; } else r |= xc_e8(xc_werr()) << 24; } else r |= xc_e8(xc_werr()) << 8;
    xc_close(s1);
    return (int)r;
}
static HANDLE idle2(void) { return xc_spawn("idle", "", NULL, 0, NULL); }

TEST(blob_null_buffer_is_wsaefault)
{
    SOCKET s; HANDLE p; int rc;
    UP(); s = xc_make(AF_INET, SOCK_STREAM, OVLD); p = idle2();
    if (s == INVALID_SOCKET || !p) { t_skip("setup"); return; }
    xc_setwerr(0);
    rc = U(WSADuplicateSocketW)(s, GetProcessId(p), NULL);
    XEQ(rc, SOCKET_ERROR);
    XEQ(xc_werr(), WSAEFAULT);
    xc_close(s); xc_kill(p);
}
/* Feed one blob (possibly altered) to a fresh target and return its exit code. 'how' selects the alteration. */
static DWORD blob_case(int how, int wrong_target, char mode)
{
    SOCKET s; HANDLE wr, p, other = NULL; WSAPROTOCOL_INFOW pi; DWORD n;
    if (!xc_up()) return 0xFFFF0000;
    s = xc_make(AF_INET, SOCK_STREAM, OVLD);
    if (s == INVALID_SOCKET) return 0xFFFF0001;
    p = spawn_pipe("blob_try", mode == 'w' ? "w" : "a", &wr);
    if (!p) { xc_close(s); return 0xFFFF0002; }
    if (wrong_target) other = idle2();
    if (U(WSADuplicateSocketW)(s, GetProcessId(wrong_target ? other : p), &pi)) { xc_kill(p); xc_close(s); return 0xFFFF0003; }
    if (how == 1) pi.dwCatalogEntryId = 0;
    if (how == 2) pi.dwServiceFlags1 = 0;
    if (how == 3) memset(&pi.ProviderId, 0, sizeof(GUID));
    if (how == 4) pi.iAddressFamily = AF_INET6;
    if (how == 5) pi.dwProviderReserved ^= 1;
    WriteFile(wr, &pi, sizeof pi, &n, NULL); CloseHandle(wr);
    n = xc_wait(p, XC_CHILD_TIMEOUT);
    xc_close(s); if (other) xc_kill(other);
    return n;
}
#define BLOB_BOTH_OK 7u
TEST(blob_may_be_consumed_twice)                 { XEQ(blob_case(0, 0, 'w'), BLOB_BOTH_OK); }
/* The calls succeed, but the handle that comes back is not a socket of the consuming process. */
TEST(blob_consumed_by_other_process_gives_unusable_handle) { XEQ(blob_case(0, 1, 'w'), (0x26u << 24) | 3u); }
TEST(blob_zero_catalog_entry_is_einval)          { XEQ(blob_case(1, 0, 'w'), (0x16u << 8) | (0x16u << 16)); }
TEST(blob_provider_reserved_bit_flip_still_usable) { XEQ(blob_case(5, 0, 'w'), BLOB_BOTH_OK); }
TEST(blob_zero_service_flags_still_usable)       { XEQ(blob_case(2, 0, 'w'), BLOB_BOTH_OK); }
TEST(blob_zero_provider_id_still_usable)         { XEQ(blob_case(3, 0, 'w'), BLOB_BOTH_OK); }
TEST(blob_wrong_family_field_still_usable)       { XEQ(blob_case(4, 0, 'w'), BLOB_BOTH_OK); }
TEST(blob_ansi_form_usable_in_child)             { XEQ(blob_case(0, 0, 'a'), 5); }
TEST(blob_ansi_matches_wide_fields)
{
    SOCKET s; HANDLE p; WSAPROTOCOL_INFOA a; WSAPROTOCOL_INFOW w;
    UP(); s = xc_make(AF_INET, SOCK_STREAM, OVLD); p = idle2();
    if (s == INVALID_SOCKET || !p) { t_skip("setup"); return; }
    memset(&a, 0xcc, sizeof a); memset(&w, 0xcc, sizeof w);
    XEQ(U(WSADuplicateSocketA)(s, GetProcessId(p), &a), 0);
    XEQ(U(WSADuplicateSocketW)(s, GetProcessId(p), &w), 0);
    XEQ(a.iAddressFamily, w.iAddressFamily); XEQ(a.iSocketType, w.iSocketType); XEQ(a.iProtocol, w.iProtocol);
    XEQ(a.dwServiceFlags1, w.dwServiceFlags1); XEQ(a.dwCatalogEntryId, w.dwCatalogEntryId);
    XEQ(memcmp(&a.ProviderId, &w.ProviderId, sizeof(GUID)), 0);
    XEQ(a.ProtocolChain.ChainLen, w.ProtocolChain.ChainLen);
    XEQ(sizeof a, 372); 
    xc_close(s); xc_kill(p);
}
/* A parent-side event selection made by a child puts the shared endpoint into non-blocking mode. */
TEST(blob_evsel_in_child_makes_parent_recv_nonblocking)
{
    SOCKET c, s; char a[64], b; HANDLE h[1]; int r, e;
    UP(); PAIR_OR_SKIP(c, s, OVLD);
    xc_rcvtimeo(c, 300);
    XEQ(xc_send(s, "x", 1), 1);
    h[0] = H(c);
    XEQ(xc_run("evsel_read", XARGS(a, "%llu", xc_u(c)), h, 1), 0);
    XEQ(xc_recv_n(c, &b, 1), 1);
    xc_setwerr(0);
    r = U(recv)(c, &b, 1, 0); e = xc_werr();
    XEQ(r, SOCKET_ERROR);
    XEQ(e, WSAEWOULDBLOCK);                           /* a blocking call with a 300 ms timeout would give WSAETIMEDOUT */
    xc_close(c); xc_close(s);
}
