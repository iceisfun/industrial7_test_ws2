/* RIORegisterBuffer / RIODeregisterBuffer.
 *
 * RIORegisterBuffer returns RIO_INVALID_BUFFERID (0xFFFFFFFF) on failure and sets the Winsock error. A zero length
 * is checked first (WSAEINVAL, even for a NULL pointer); after that the whole range must be committed, writable
 * memory of the caller (WSAEFAULT otherwise: NULL, reserved-only, read-only, partly committed, past the end of
 * the allocation). There is no page-granularity requirement: byte-sized and unaligned ranges register. Every
 * successful call returns a distinct id, also for the same or overlapping ranges. RIODeregisterBuffer returns
 * nothing and leaves the error state alone. */
#include "rio.h"

static int valid_id(RIO_BUFFERID id) { return id != NULL && id != RIO_INVALID_BUFFERID; }

TEST(rio_buffers_range_matrix)
{
    NEED_RIO(t);
    /* 0x10000 committed bytes followed by reserved-only space, so "past the end" never runs into a neighbour */
    char *buf = VirtualAlloc(NULL, 0x30000, MEM_RESERVE, PAGE_NOACCESS);
    char *res = VirtualAlloc(NULL, 0x4000, MEM_RESERVE, PAGE_NOACCESS);
    char *ro = VirtualAlloc(NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    char *half = VirtualAlloc(NULL, 0x3000, MEM_RESERVE, PAGE_NOACCESS);
    char *gap = VirtualAlloc(NULL, 0x3000, MEM_RESERVE, PAGE_NOACCESS);
    char loc[16];
    struct { const char *n; char *p; DWORD len; int err; } m[16];   /* err 0 == success */
    int n = 0;
    if (!buf || !res || !ro || !half || !gap) { t_skip("VirtualAlloc"); return; }
    VirtualAlloc(buf, 0x10000, MEM_COMMIT, PAGE_READWRITE);
    VirtualAlloc(half, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    VirtualAlloc(gap, 0x1000, MEM_COMMIT, PAGE_READWRITE); VirtualAlloc(gap + 0x2000, 0x1000, MEM_COMMIT, PAGE_READWRITE);
#define ROW(nm, ptr, l, e) do { m[n].n = nm; m[n].p = ptr; m[n].len = l; m[n].err = e; n++; } while (0)
    ROW("zero length", buf, 0, WSAEINVAL);
    ROW("null, zero length", NULL, 0, WSAEINVAL);
    ROW("null, length 1", NULL, 1, WSAEFAULT);
    ROW("one byte", buf, 1, 0);
    ROW("unaligned five bytes", buf + 1, 5, 0);
    ROW("exactly one page", buf, 0x1000, 0);
    ROW("whole allocation", buf, 0x10000, 0);
    ROW("one byte past the allocation", buf, 0x10001, WSAEFAULT);
    ROW("twice the allocation", buf, 0x20000, WSAEFAULT);
    ROW("reserved only", res, 0x1000, WSAEFAULT);
    ROW("read-only page", ro, 0x1000, WSAEFAULT);
    ROW("committed page then reserved", half, 0x2000, WSAEFAULT);
    ROW("committed page only", half, 0x1000, 0);
    ROW("hole in the middle", gap, 0x3000, WSAEFAULT);
    ROW("length 0xffffffff", buf, 0xffffffff, WSAEFAULT);
    ROW("stack buffer", loc, sizeof loc, 0);
#undef ROW
    for (int i = 0; i < n; i++) {
        RIO_BUFFERID id;
        WSASetLastError(0);
        id = t->RegisterBuffer(m[i].p, m[i].len);
        if (m[i].err == 0) {
            CHECKF(valid_id(id), "%s: not registered (err %d)", m[i].n, WSAGetLastError());
            if (valid_id(id)) t->DeregisterBuffer(id);
        } else {
            CHECKF(id == RIO_INVALID_BUFFERID, "%s: id %p", m[i].n, (void *)id);
            CHECKF(WSAGetLastError() == m[i].err, "%s: err %d want %d", m[i].n, WSAGetLastError(), m[i].err);
        }
    }
    VirtualFree(buf, 0, MEM_RELEASE); VirtualFree(res, 0, MEM_RELEASE); VirtualFree(ro, 0, MEM_RELEASE);
    VirtualFree(half, 0, MEM_RELEASE); VirtualFree(gap, 0, MEM_RELEASE);
}
TEST(rio_buffers_failure_value_is_all_ones_not_null)
{
    NEED_RIO(t);
    char b[8]; RIO_BUFFERID id;
    WSASetLastError(0);
    id = t->RegisterBuffer(b, 0);
    EXPECT_EQ((ULONG_PTR)id, 0xFFFFFFFFUL);
    CHECK(id != NULL);
}
TEST(rio_buffers_same_range_gives_distinct_ids)
{
    NEED_RIO(t);
    char *buf = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    RIO_BUFFERID a = t->RegisterBuffer(buf, 100), b = t->RegisterBuffer(buf, 100), c = t->RegisterBuffer(buf + 50, 100);
    CHECK(valid_id(a) && valid_id(b) && valid_id(c));
    CHECK(a != b); CHECK(a != c); CHECK(b != c);
    t->DeregisterBuffer(a); t->DeregisterBuffer(b); t->DeregisterBuffer(c);
    VirtualFree(buf, 0, MEM_RELEASE);
}
TEST(rio_buffers_register_many_and_release)
{
    NEED_RIO(t);
    char *buf = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    RIO_BUFFERID ids[256]; int n;
    for (n = 0; n < 256; n++) { ids[n] = t->RegisterBuffer(buf, 0x1000); if (!valid_id(ids[n])) break; }
    EXPECT_EQ(n, 256);
    for (int i = 0; i < n; i++) for (int j = i + 1; j < n; j += 17) if (ids[i] == ids[j]) { CHECK(ids[i] != ids[j]); }
    for (int i = 0; i < n; i++) t->DeregisterBuffer(ids[i]);
    VirtualFree(buf, 0, MEM_RELEASE);
}
TEST(rio_buffers_reregister_after_deregister)
{
    NEED_RIO(t);
    char *buf = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    for (int i = 0; i < 8; i++) {
        RIO_BUFFERID id = t->RegisterBuffer(buf, 0x800);
        CHECK(valid_id(id));
        t->DeregisterBuffer(id);
    }
    VirtualFree(buf, 0, MEM_RELEASE);
}
TEST(rio_buffers_deregister_leaves_error_state_alone)
{
    NEED_RIO(t);
    char *buf = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    RIO_BUFFERID id = t->RegisterBuffer(buf, 16);
    WSASetLastError(0x1234); t->DeregisterBuffer(id); EXPECT_EQ(WSAGetLastError(), 0x1234);
    WSASetLastError(0x1234); t->DeregisterBuffer(RIO_INVALID_BUFFERID); EXPECT_EQ(WSAGetLastError(), 0x1234);
    WSASetLastError(0x1234); t->DeregisterBuffer(NULL); EXPECT_EQ(WSAGetLastError(), 0x1234);
    VirtualFree(buf, 0, MEM_RELEASE);
}
TEST(rio_buffers_success_leaves_error_state_alone)
{
    NEED_RIO(t);
    char *buf = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    RIO_BUFFERID id;
    WSASetLastError(0x1234); id = t->RegisterBuffer(buf, 16);
    CHECK(valid_id(id)); EXPECT_EQ(WSAGetLastError(), 0x1234);
    t->DeregisterBuffer(id);
    VirtualFree(buf, 0, MEM_RELEASE);
}
TEST(rio_buffers_register_without_winsock_sockets_needs_no_socket)
{
    /* Registration is independent of any socket: the table alone is enough. */
    NEED_RIO(t);
    char b[64]; RIO_BUFFERID id = t->RegisterBuffer(b, sizeof b);
    CHECK(valid_id(id));
    t->DeregisterBuffer(id);
}
TEST(rio_buffers_registration_aliases_caller_memory)
{
    /* The registered range is the caller's memory, not a copy: data written after registration is what a send transmits. */
    RIORES rr[2];
    NEED_PAIR(p, t, 4);
    memcpy(p.mem + PR_SEND, "before", 6);
    CHECK(pair_recv(&p, PR_RECV, 16, RQV(1), 0));
    memcpy(p.mem + PR_SEND, "after!", 6);
    CHECK(pair_send(&p, PR_SEND, 6, RQV(2), 0));
    EXPECT_EQ(rio_wait(t, p.cqb, rr, 2, 1), 1);
    CHECK(!memcmp(p.mem + PR_RECV, "after!", 6));
    pair_close(&p);
}
