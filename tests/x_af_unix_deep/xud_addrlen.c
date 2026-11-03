/* AF_UNIX address-length rules for bind() and connect(): how the length argument selects the part of the
 * sockaddr_un that is read, where the name ends (at the first NUL or at the length, whichever comes first),
 * which lengths fail and with what code, and the length getsockname reports afterwards.
 * All names are short relative names resolved in the scratch directory, so truncated names stay inside it. */
#include "xud.h"

#define LEAF "uxpfx"
#define LEAF_N 5

/* Address buffer larger than the structure so oversize lengths never read past the object. */
struct big { SOCKADDR_UN a; char pad[512]; };
static void big_addr(struct big *b, const char *path)
{
    memset(b, 0, sizeof *b);
    x_addr(&b->a, path);
}

static void cleanup(void) { x_cd_restore(); }

/* Bind a fresh socket with the given length; returns the socket (caller closes) and fills r/e/gsn. */
static SOCKET bind_with_len(const char *path, int len, int *r, int *e, int *gsn_len, char *gsn_path)
{
    struct big b;
    SOCKADDR_UN g;
    int gl = (int)sizeof g;
    SOCKET s = x_sock();
    if (s == INVALID_SOCKET) return s;
    big_addr(&b, path);
    *r = U(bind)(s, (struct sockaddr *)&b.a, len);
    *e = *r ? x_err() : 0;
    *gsn_len = -1;
    if (gsn_path) gsn_path[0] = 0;
    if (*r == 0) {
        memset(&g, 0x55, sizeof g);
        if (U(getsockname)(s, (struct sockaddr *)&g, &gl) == 0) {
            *gsn_len = gl;
            if (gsn_path) { memcpy(gsn_path, g.sun_path, sizeof g.sun_path); gsn_path[sizeof g.sun_path] = 0; }
        }
    }
    return s;
}

/* Lengths that cannot cover the family field: WSAEFAULT. */
static void fault_len(int len)
{
    int r, e, gl;
    char gp[128];
    SOCKET s;
    UP();
    x_cd_scratch();
    s = bind_with_len(LEAF, len, &r, &e, &gl, gp);
    if (s == INVALID_SOCKET) { x_cd_restore(); return; }
    XEQ(r, -1);
    XEQ(e, WSAEFAULT);
    CHECK(!x_exists(LEAF));
    /* the socket stays unbound and usable */
    {
        SOCKADDR_UN a;
        x_addr(&a, LEAF);
        XEQ(x_bind(s, &a), 0);
    }
    U(closesocket)(s);
    DeleteFileA(LEAF);
    x_cd_restore();
}
TEST(xud_len_bind_zero_is_fault) { fault_len(0); }
TEST(xud_len_bind_one_is_fault) { fault_len(1); }
TEST(xud_len_bind_minus_one_is_fault) { fault_len(-1); }
TEST(xud_len_bind_int_min_is_fault) { fault_len((int)0x80000000); }

/* A length that covers exactly the first k characters of the name binds the k-character prefix. */
static void prefix_len(int k)
{
    int r, e, gl;
    char gp[128], pre[16];
    SOCKET s;
    UP();
    x_cd_scratch();
    s = bind_with_len(LEAF, X_ADDR_BASE + k, &r, &e, &gl, gp);
    if (s == INVALID_SOCKET) { x_cd_restore(); return; }
    memcpy(pre, LEAF, k); pre[k] = 0;
    XEQ(r, 0);
    XEQ(gl, X_ADDR_BASE + k + 1);          /* reported length counts the NUL after the prefix */
    EXPECT_STR(gp, pre);
    CHECK(x_exists(pre));                  /* the prefix names the file that was created */
    if (k < LEAF_N) CHECK(!x_exists(LEAF));
    U(closesocket)(s);
    DeleteFileA(pre);
    x_cd_restore();
}
TEST(xud_len_bind_prefix_1) { prefix_len(1); }
TEST(xud_len_bind_prefix_2) { prefix_len(2); }
TEST(xud_len_bind_prefix_3) { prefix_len(3); }
TEST(xud_len_bind_prefix_4) { prefix_len(4); }
TEST(xud_len_bind_prefix_full_without_nul) { prefix_len(LEAF_N); }

/* Length at or beyond the terminator: the name ends at the NUL, the rest of the length is ignored. */
static void beyond_len(int len)
{
    int r, e, gl;
    char gp[128];
    SOCKET s;
    UP();
    x_cd_scratch();
    s = bind_with_len(LEAF, len, &r, &e, &gl, gp);
    if (s == INVALID_SOCKET) { x_cd_restore(); return; }
    XEQ(r, 0);
    XEQ(gl, X_ADDR_BASE + LEAF_N + 1);
    EXPECT_STR(gp, LEAF);
    CHECK(x_exists(LEAF));
    U(closesocket)(s);
    DeleteFileA(LEAF);
    x_cd_restore();
}
TEST(xud_len_bind_with_nul) { beyond_len(X_ADDR_BASE + LEAF_N + 1); }
TEST(xud_len_bind_one_past_nul) { beyond_len(X_ADDR_BASE + LEAF_N + 2); }
TEST(xud_len_bind_exact_struct) { beyond_len(110); }
TEST(xud_len_bind_struct_plus_one) { beyond_len(111); }
TEST(xud_len_bind_struct_plus_two) { beyond_len(112); }
TEST(xud_len_bind_128) { beyond_len(128); }
TEST(xud_len_bind_256) { beyond_len(256); }

/* Two lengths naming the same file collide. */
TEST(xud_len_bind_prefix_then_full_name_is_addrinuse)
{
    int r, e, gl;
    char gp[128];
    SOCKET a, b;
    UP();
    x_cd_scratch();
    a = bind_with_len(LEAF, X_ADDR_BASE + LEAF_N, &r, &e, &gl, gp);
    if (a == INVALID_SOCKET) { x_cd_restore(); return; }
    XEQ(r, 0);
    b = bind_with_len(LEAF, X_ADDR_BASE + LEAF_N + 1, &r, &e, &gl, gp);
    XEQ(r, -1);
    XEQ(e, WSAEADDRINUSE);
    U(closesocket)(b);
    U(closesocket)(a);
    DeleteFileA(LEAF);
    x_cd_restore();
}
TEST(xud_len_bind_prefix_different_file_does_not_collide)
{
    int r, e, gl;
    char gp[128];
    SOCKET a, b;
    UP();
    x_cd_scratch();
    a = bind_with_len(LEAF, X_ADDR_BASE + LEAF_N, &r, &e, &gl, gp);
    if (a == INVALID_SOCKET) { x_cd_restore(); return; }
    b = bind_with_len(LEAF, X_ADDR_BASE + LEAF_N - 1, &r, &e, &gl, gp);
    XEQ(r, 0);
    CHECK(x_exists("uxpf"));
    U(closesocket)(b);
    U(closesocket)(a);
    DeleteFileA(LEAF);
    DeleteFileA("uxpf");
    x_cd_restore();
}

/* ---- connect(): which lengths reach the listener ---- */
struct conn_row { int len; int want_err; int reaches; const char *what; };
#define FULL (-1000)   /* marks "name length plus terminator" computed at run time */

static void conn_len(int len, int want_err, int reaches)
{
    SOCKADDR_UN la;
    struct big b;
    SOCKET lis, c;
    int r, e, acc = 0;
    UP();
    x_cd_scratch();
    lis = x_sock();
    if (lis == INVALID_SOCKET) { x_cd_restore(); return; }
    x_addr(&la, LEAF);
    if (x_bind(lis, &la) || U(listen)(lis, 4)) { t_skip("cannot create listener"); U(closesocket)(lis); DeleteFileA(LEAF); x_cd_restore(); return; }
    c = x_sock();
    x_blocking(c, FALSE);
    big_addr(&b, LEAF);
    r = U(connect)(c, (struct sockaddr *)&b.a, len);
    e = r ? x_err() : 0;
    if (reaches) {
        XEQ(r, -1);
        XEQ(e, WSAEWOULDBLOCK);          /* nonblocking connect to a listener is always in progress */
        acc = x_readable(lis, 3000);
        CHECK(acc);
        if (acc) { SOCKET s = U(accept)(lis, NULL, NULL); CHECK(s != INVALID_SOCKET); if (s != INVALID_SOCKET) U(closesocket)(s); }
    } else {
        XEQ(r, -1);
        XEQ(e, want_err);
        CHECK(!x_readable(lis, 200));
    }
    U(closesocket)(c);
    U(closesocket)(lis);
    DeleteFileA(LEAF);
    x_cd_restore();
}
TEST(xud_len_connect_zero_is_fault) { conn_len(0, WSAEFAULT, 0); }
TEST(xud_len_connect_one_is_fault) { conn_len(1, WSAEFAULT, 0); }
TEST(xud_len_connect_minus_one_is_fault) { conn_len(-1, WSAEFAULT, 0); }
TEST(xud_len_connect_family_only_is_inval) { conn_len(2, WSAEINVAL, 0); }
TEST(xud_len_connect_one_char_prefix_is_refused) { conn_len(3, WSAECONNREFUSED, 0); }
TEST(xud_len_connect_two_char_prefix_is_refused) { conn_len(4, WSAECONNREFUSED, 0); }
TEST(xud_len_connect_prefix_missing_last_char_is_refused) { conn_len(X_ADDR_BASE + LEAF_N - 1, WSAECONNREFUSED, 0); }
TEST(xud_len_connect_exact_name_reaches_listener) { conn_len(X_ADDR_BASE + LEAF_N, 0, 1); }
TEST(xud_len_connect_name_with_nul_reaches_listener) { conn_len(X_ADDR_BASE + LEAF_N + 1, 0, 1); }
TEST(xud_len_connect_one_past_nul_reaches_listener) { conn_len(X_ADDR_BASE + LEAF_N + 2, 0, 1); }
TEST(xud_len_connect_struct_size_reaches_listener) { conn_len(110, 0, 1); }
TEST(xud_len_connect_larger_than_struct_reaches_listener) { conn_len(256, 0, 1); }

/* The one-character prefix would be a different file: when a listener owns that file it is the one reached. */
TEST(xud_len_connect_prefix_reaches_listener_bound_with_same_prefix)
{
    SOCKADDR_UN la;
    SOCKET lis;
    int e;
    UP();
    x_cd_scratch();
    lis = x_sock();
    if (lis == INVALID_SOCKET) { x_cd_restore(); return; }
    x_addr(&la, "uxp");
    if (x_bind(lis, &la) || U(listen)(lis, 2)) { t_skip("cannot create listener"); U(closesocket)(lis); x_cd_restore(); return; }
    /* full-length sockaddr of "uxpfx" does not reach "uxp", but a 3-character length of the longer name does */
    CHECK(!x_try_connect(lis, LEAF, &e));
    XEQ(e, WSAECONNREFUSED);
    {
        struct big b;
        SOCKET c = x_sock();
        int r;
        big_addr(&b, LEAF);
        x_blocking(c, FALSE);
        r = U(connect)(c, (struct sockaddr *)&b.a, X_ADDR_BASE + 3);
        XEQ(r, -1);
        XEQ(x_err(), WSAEWOULDBLOCK);
        CHECK(x_readable(lis, 3000));
        U(closesocket)(c);
    }
    U(closesocket)(lis);
    DeleteFileA("uxp");
    x_cd_restore();
}
