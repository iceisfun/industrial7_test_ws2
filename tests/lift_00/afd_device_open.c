/* Opening the AFD device directly through ntdll and the attributes of a socket handle.
 * Measures: \Device\Afd accepts any trailing path component for a control-only open, and a freshly
 * created TCP socket is an inheritable handle with a fixed granted-access mask. */
#include "afd_common.h"

static void open_ok(const wchar_t *path)
{
    HANDLE h = open_afd(path);
    CHECK(h != NULL);
    if (h) CloseHandle(h);
}

TEST(afdd_open_device_plain)        { NEED_AFD(); open_ok(L"\\Device\\Afd"); }
TEST(afdd_open_device_trailing_sep) { NEED_AFD(); open_ok(L"\\Device\\Afd\\"); }
TEST(afdd_open_device_named_leaf)   { NEED_AFD(); open_ok(L"\\Device\\Afd\\ctlhandle"); }
TEST(afdd_open_device_two_handles_independent)
{
    HANDLE a, b;
    NEED_AFD();
    a = open_afd(L"\\Device\\Afd\\one");
    b = open_afd(L"\\Device\\Afd\\one");
    CHECK(a && b && a != b);
    if (a) CloseHandle(a);
    if (b) CloseHandle(b);
}

/* OBJECT_BASIC_INFORMATION (class 0): only the first two fields are used. */
typedef struct { ULONG Attributes; ACCESS_MASK GrantedAccess; ULONG rest[12]; } objbasic_t; /* the call insists on this exact size (0x38) */

static void sock_object_info(objbasic_t *oi, LONG *st)
{
    SOCKET s = mk_tcp();
    memset(oi, 0, sizeof(*oi));
    *st = F.NtQueryObject((HANDLE)s, 0, oi, sizeof(*oi), NULL);
    sock_close(s);
}

TEST(afdd_socket_handle_attributes_inherit)
{
    objbasic_t oi; LONG st;
    NEED_AFD();
    sock_object_info(&oi, &st);
    CHECKF(st == 0, "status 0x%08lx", (unsigned long)st);
    /* sockets are created inheritable */
    EXPECT_EQ(oi.Attributes, OBJ_INHERIT);
}
TEST(afdd_socket_handle_granted_access)
{
    objbasic_t oi; LONG st;
    NEED_AFD();
    sock_object_info(&oi, &st);
    CHECKF(st == 0, "status 0x%08lx", (unsigned long)st);
    EXPECT_EQ(oi.GrantedAccess, FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC);
}
TEST(afdd_socket_handle_is_not_afd_device_open)
{
    /* a bare control open requested SYNCHRONIZE only, so that right is in the granted mask */
    objbasic_t oi; LONG st; HANDLE h;
    NEED_AFD();
    h = open_afd(L"\\Device\\Afd");
    if (!h) return;
    memset(&oi, 0, sizeof(oi));
    st = F.NtQueryObject(h, 0, &oi, sizeof(oi), NULL);
    CHECKF(st == 0, "status 0x%08lx", (unsigned long)st);
    EXPECT_EQ(oi.GrantedAccess & SYNCHRONIZE, SYNCHRONIZE);
    CloseHandle(h);
}
