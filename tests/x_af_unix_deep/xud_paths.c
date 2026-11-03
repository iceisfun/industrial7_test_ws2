/* AF_UNIX name spelling rules: which spellings of a file name bind, which are rejected and with what code, how
 * the kernel normalises accepted spellings, and that getsockname returns the spelling as given. Rows are
 * relative names resolved in the scratch directory (the test changes into it and back). */
#include "xud.h"

/* ---- spellings that must be rejected, with the exact error ---- */
struct rej { const char *name; const char *spelling; int err; };
static const struct rej rejects[] = {
    { "question_mark",   "q?.sock",        WSAEINVAL },
    { "star",            "s*.sock",        WSAEINVAL },
    { "less_than",       "lt<.sock",       WSAEINVAL },
    { "greater_than",    "gt>.sock",       WSAEINVAL },
    { "pipe",            "p|p.sock",       WSAEINVAL },
    { "double_quote",    "q\".sock",       WSAEINVAL },
    { "control_char_1",  "c\x01.sock",     WSAEINVAL },
    { "control_char_31", "c\x1f.sock",     WSAEINVAL },
    { "trailing_backslash", "dirx.sock\\", WSAEINVAL },
    { "trailing_slash",  "dirx.sock/",     WSAEINVAL },
    { "colon_inside",    ".\\a:b.sock",   WSAEADDRNOTAVAIL },
    { "stream_suffix",   "ads.sock:stream", WSAEADDRNOTAVAIL },
    { "data_stream",     "ads.sock::$DATA", WSAEADDRNOTAVAIL },
    { "missing_dir",     "nodir\\x.sock",  WSAENETDOWN },
    { "missing_dir_fwd", "nodir/x.sock",   WSAENETDOWN },
    { "missing_two_deep", "nod1\\nod2\\x.sock", WSAENETDOWN },
    { "file_as_dir",     "plain.txt\\x.sock", WSAENETDOWN },
    { "file_as_dir_fwd", "plain.txt/x.sock", WSAENETDOWN },
    { "existing_dir",    "adir",           WSAEINVAL },
    { "existing_dir_slash", "adir\\",      WSAEINVAL },
    { "existing_dir_fwd", "adir/",         WSAEINVAL },
};

static void prepare_dirs(void)
{
    HANDLE h;
    CreateDirectoryA("adir", NULL);
    CreateDirectoryA("sub", NULL);
    h = CreateFileA("plain.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
}
static void drop_dirs(void)
{
    DeleteFileA("plain.txt");
    RemoveDirectoryA("adir");
    RemoveDirectoryA("sub");
}

static void reject_row(const struct rej *r)
{
    SOCKADDR_UN a;
    SOCKET s;
    int rc;
    UP();
    x_cd_scratch();
    prepare_dirs();
    s = x_sock();
    if (s != INVALID_SOCKET) {
        x_addr(&a, r->spelling);
        rc = x_bind(s, &a);
        XEQ(rc, -1);
        XEQ(x_err(), r->err);
        {   /* the socket is still unbound: getsockname has no name to give */
            SOCKADDR_UN g; int gl = (int)sizeof g;
            XEQ(U(getsockname)(s, (struct sockaddr *)&g, &gl), -1);
        }
        /* the same spelling fails to connect as well (code may differ from bind) */
        {
            SOCKET c = x_sock();
            XEQ(x_connect(c, &a), -1);
            CHECK(x_err() != 0);
            U(closesocket)(c);
        }
        U(closesocket)(s);
    }
    drop_dirs();
    x_cd_restore();
}
#define REJ(i, nm) TEST(xud_path_reject_##nm) { reject_row(&rejects[i]); }
REJ(0, question_mark) REJ(1, star) REJ(2, less_than) REJ(3, greater_than) REJ(4, pipe) REJ(5, double_quote)
REJ(6, control_char_1) REJ(7, control_char_31) REJ(8, trailing_backslash) REJ(9, trailing_slash)
REJ(10, colon_inside) REJ(11, stream_suffix) REJ(12, data_stream)
REJ(13, missing_dir) REJ(14, missing_dir_fwd) REJ(15, missing_two_deep)
REJ(16, file_as_dir) REJ(17, file_as_dir_fwd)
REJ(18, existing_dir) REJ(19, existing_dir_slash) REJ(20, existing_dir_fwd)

/* ---- spellings that bind: the file lands at the normalised location, getsockname echoes the spelling ---- */
struct acc { const char *spelling; const char *canon; };
static const struct acc accepts[] = {
    { "pa1.sock",             "pa1.sock" },
    { ".\\pa2.sock",          "pa2.sock" },
    { "sub\\..\\pa3.sock",    "pa3.sock" },
    { "sub/pa4.sock",         "sub\\pa4.sock" },
    { "sub\\\\pa5.sock",      "sub\\pa5.sock" },
    { "sub\\.\\pa6.sock",     "sub\\pa6.sock" },
    { ".\\sub\\.\\..\\pa7.sock", "pa7.sock" },
    { "pa 8 spaced.sock",     "pa 8 spaced.sock" },
    { "PA9.SOCK",             "pa9.sock" },
    { "pa10~tilde.sock",      "pa10~tilde.sock" },
};

static void accept_row(int i)
{
    const struct acc *r = &accepts[i];
    SOCKADDR_UN a, g;
    SOCKET s;
    int gl = (int)sizeof g, e;
    char canon_abs[MAX_PATH];
    UP();
    x_cd_scratch();
    prepare_dirs();
    s = x_sock();
    if (s == INVALID_SOCKET) { drop_dirs(); x_cd_restore(); return; }
    x_addr(&a, r->spelling);
    XEQ(x_bind(s, &a), 0);
    CHECK(x_exists(r->canon));
    memset(&g, 0x55, sizeof g);
    XEQ(U(getsockname)(s, (struct sockaddr *)&g, &gl), 0);
    XEQ(gl, X_ADDR_BASE + (int)strlen(r->spelling) + 1);
    EXPECT_STR(g.sun_path, r->spelling);        /* verbatim, not normalised */
    XEQ(U(listen)(s, 2), 0);
    CHECK(x_try_connect(s, r->spelling, &e));    /* the spelling it was bound with */
    CHECK(x_try_connect(s, r->canon, &e));       /* and the normalised one */
    snprintf(canon_abs, sizeof canon_abs, "%s%s", t_tmpdir(), r->canon);
    CHECK(x_try_connect(s, canon_abs, &e));      /* and the absolute one */
    U(closesocket)(s);
    DeleteFileA(r->canon);
    CHECK(!x_exists(r->canon));
    drop_dirs();
    x_cd_restore();
}
#define ACC(i, nm) TEST(xud_path_accept_##nm) { accept_row(i); }
ACC(0, plain) ACC(1, dot_component) ACC(2, dotdot_after_dir) ACC(3, forward_slash) ACC(4, doubled_separator)
ACC(5, dot_inside_dir) ACC(6, mixed_dots) ACC(7, spaces_inside) ACC(8, upper_case_folds) ACC(9, tilde)

/* Case folding: the upper-case spelling and the lower-case spelling are the same file. */
TEST(xud_path_case_variants_are_one_file)
{
    SOCKADDR_UN a, b;
    SOCKET s1, s2;
    UP();
    x_cd_scratch();
    s1 = x_sock(); s2 = x_sock();
    if (s1 == INVALID_SOCKET || s2 == INVALID_SOCKET) { x_cd_restore(); return; }
    x_addr(&a, "CaseMix.Sock"); x_addr(&b, "casemix.sock");
    XEQ(x_bind(s1, &a), 0);
    XEQ(x_bind(s2, &b), -1);
    XEQ(x_err(), WSAEADDRINUSE);
    U(closesocket)(s2); U(closesocket)(s1);
    DeleteFileA("casemix.sock");
    x_cd_restore();
}

/* Equivalent spellings collide on a second bind. */
static void collide(const char *first, const char *second)
{
    SOCKADDR_UN a, b;
    SOCKET s1, s2;
    UP();
    x_cd_scratch();
    prepare_dirs();
    s1 = x_sock(); s2 = x_sock();
    if (s1 == INVALID_SOCKET || s2 == INVALID_SOCKET) { drop_dirs(); x_cd_restore(); return; }
    x_addr(&a, first); x_addr(&b, second);
    XEQ(x_bind(s1, &a), 0);
    XEQ(x_bind(s2, &b), -1);
    XEQ(x_err(), WSAEADDRINUSE);
    U(closesocket)(s2); U(closesocket)(s1);
    DeleteFileA(first);
    drop_dirs();
    x_cd_restore();
}
TEST(xud_path_collide_trailing_dot) { collide("co6.sock", "co6.sock."); }
TEST(xud_path_collide_trailing_dots) { collide("co7.sock", "co7.sock..."); }
TEST(xud_path_collide_trailing_space) { collide("co8.sock", "co8.sock "); }
TEST(xud_path_collide_upper_case) { collide("co9.sock", "CO9.SOCK"); }
TEST(xud_path_collide_dot_prefix) { collide("co1.sock", ".\\co1.sock"); }
TEST(xud_path_collide_dotdot_detour) { collide("co2.sock", "sub\\..\\co2.sock"); }
TEST(xud_path_collide_absolute_vs_relative)
{
    char abs_[MAX_PATH];
    snprintf(abs_, sizeof abs_, "%sco3.sock", t_tmpdir());
    collide("co3.sock", abs_);
}
TEST(xud_path_collide_forward_slash_dir) { collide("sub\\co4.sock", "sub/co4.sock"); }
TEST(xud_path_collide_doubled_separator) { collide("sub\\co5.sock", "sub\\\\co5.sock"); }

/* A name whose directory part resolves through the parent of the working directory. */
TEST(xud_path_parent_directory_escape)
{
    SOCKADDR_UN a, g;
    SOCKET s;
    char sp[MAX_PATH], leaf[64], abs_[MAX_PATH];
    char *cut;
    int gl = (int)sizeof g, e;
    UP();
    /* scratch dir is <parent>\<name>\ ; reach the parent file through the working directory + ".." */
    snprintf(sp, sizeof sp, "%s", t_tmpdir());
    sp[strlen(sp) - 1] = 0;
    cut = strrchr(sp, '\\');
    if (!cut) { t_skip("odd scratch path"); return; }
    snprintf(leaf, sizeof leaf, "xud_parent_%lu.sock", GetCurrentProcessId());
    x_cd_scratch();
    s = x_sock();
    if (s == INVALID_SOCKET) { x_cd_restore(); return; }
    {
        char rel[96];
        snprintf(rel, sizeof rel, "..\\%s", leaf);
        x_addr(&a, rel);
        XEQ(x_bind(s, &a), 0);
        snprintf(abs_, sizeof abs_, "%.*s\\%s", (int)(cut - sp), sp, leaf);
        CHECK(x_exists(abs_));
        XEQ(U(getsockname)(s, (struct sockaddr *)&g, &gl), 0);
        EXPECT_STR(g.sun_path, rel);
        XEQ(U(listen)(s, 1), 0);
        CHECK(x_try_connect(s, abs_, &e));
    }
    U(closesocket)(s);
    DeleteFileA(abs_);
    x_cd_restore();
}

/* A trailing dot or space is dropped on the way to the file system, so the spelling reaches the listener. */
static void alias_reaches(const char *bound, const char *alias)
{
    SOCKADDR_UN a;
    SOCKET s;
    int e;
    UP();
    x_cd_scratch();
    s = x_sock();
    if (s == INVALID_SOCKET) { x_cd_restore(); return; }
    x_addr(&a, bound);
    XEQ(x_bind(s, &a), 0);
    XEQ(U(listen)(s, 2), 0);
    CHECK(x_try_connect(s, alias, &e));
    XEQ(e, WSAEWOULDBLOCK);
    U(closesocket)(s);
    DeleteFileA(bound);
    x_cd_restore();
}
TEST(xud_path_alias_trailing_dot_reaches_listener) { alias_reaches("al1.sock", "al1.sock."); }
TEST(xud_path_alias_trailing_space_reaches_listener) { alias_reaches("al2.sock", "al2.sock "); }
TEST(xud_path_alias_upper_case_reaches_listener) { alias_reaches("al3.sock", "AL3.SOCK"); }
TEST(xud_path_alias_dot_dir_reaches_listener) { alias_reaches("al4.sock", ".\\al4.sock"); }
TEST(xud_path_alias_trailing_backslash_is_inval)
{
    SOCKADDR_UN a;
    SOCKET s, lis;
    int e;
    UP();
    x_cd_scratch();
    lis = x_sock();
    if (lis == INVALID_SOCKET) { x_cd_restore(); return; }
    x_addr(&a, "al5.sock");
    XEQ(x_bind(lis, &a), 0);
    XEQ(U(listen)(lis, 2), 0);
    CHECK(!x_try_connect(lis, "al5.sock\\", &e));
    XEQ(e, WSAEINVAL);
    s = x_sock();
    (void)s;
    U(closesocket)(s);
    U(closesocket)(lis);
    DeleteFileA("al5.sock");
    x_cd_restore();
}
