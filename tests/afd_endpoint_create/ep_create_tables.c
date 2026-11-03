/* NtCreateFile parameters other than the open packet.
 *
 * Measures the status of the open (and the access mask granted) for desired access values and object
 * attribute flags, the first extended-attribute entry's own flags byte, and the declared EA length.
 * The packet is the stock TCP/IPv4 one throughout. Share-access and create-option value tables are
 * deliberately absent: they are not part of the open-packet contract and a table of share values was
 * observed to wedge a guest, so only the rows that run cleanly are kept. */
#include "aec.h"

/* ---- desired access: what a device open grants -------------------------------------- */
/* The granted mask is the request with generic rights mapped to the file rights; an empty request is refused,
 * and the system-security right needs a privilege the test token does not have enabled. */
static LONG open_access(ACCESS_MASK a, ACCESS_MASK *granted)
{
    ep_t e; HANDLE h; IO_STATUS_BLOCK io; LONG st;
    ep_tcp4(&e); e.access = a;
    st = ep_open(&e, &h, &io);
    *granted = 0xDEADBEEF;
    if (st == 0 && h) {
        objbasic_t b; memset(&b, 0, sizeof(b));
        N.NtQueryObject(h, 0, &b, sizeof(b), NULL);
        *granted = b.GrantedAccess;
        N.NtClose(h);
    }
    return st;
}
#define ACC_ROW(n, req, want) TEST(aect_access_##n) { ACCESS_MASK g; NEED(); \
    EXPECT_NT(open_access(req, &g), ST_SUCCESS); EXPECT_EQ(g, (want)); }
ACC_ROW(synchronize,   SYNCHRONIZE,   0x00100000u)
ACC_ROW(read_control,  READ_CONTROL,  0x00020000u)
ACC_ROW(write_dac,     WRITE_DAC,     0x00040000u)
ACC_ROW(write_owner,   WRITE_OWNER,   0x00080000u)
ACC_ROW(delete,        DELETE,        0x00010000u)
ACC_ROW(generic_all,   GENERIC_ALL,   0x001F01FFu)
ACC_ROW(generic_execute, GENERIC_EXECUTE, 0x001200A0u)
ACC_ROW(generic_read,  GENERIC_READ,  0x00120089u)
ACC_ROW(generic_write, GENERIC_WRITE, 0x00120116u)
ACC_ROW(maximum_allowed, MAXIMUM_ALLOWED, 0x001F01FFu)
ACC_ROW(maximum_allowed_bit_alone, 0x02000000u, 0x001F01FFu)
ACC_ROW(file_read_data, FILE_READ_DATA, 0x00000001u)
ACC_ROW(file_write_data, FILE_WRITE_DATA, 0x00000002u)
ACC_ROW(file_append_data, FILE_APPEND_DATA, 0x00000004u)
ACC_ROW(file_execute, FILE_EXECUTE, 0x00000020u)
ACC_ROW(file_read_attributes, FILE_READ_ATTRIBUTES, 0x00000080u)
ACC_ROW(file_write_attributes, FILE_WRITE_ATTRIBUTES, 0x00000100u)
ACC_ROW(file_all_access, FILE_ALL_ACCESS, 0x001F01FFu)
ACC_ROW(generic_read_plus_synchronize, GENERIC_READ | SYNCHRONIZE, 0x00120089u)
TEST(aect_access_empty_request_denied)
{
    ACCESS_MASK g; NEED();
    EXPECT_NT(open_access(0, &g), ST_ACCESS_DENIED);
}
TEST(aect_access_system_security_needs_privilege)
{
    ACCESS_MASK g; NEED();
    EXPECT_NT(open_access(ACCESS_SYSTEM_SECURITY, &g), (LONG)0xC0000061);     /* STATUS_PRIVILEGE_NOT_HELD */
}
TEST(aect_access_reserved_high_bits_need_privilege)
{
    ACCESS_MASK g; NEED();
    EXPECT_NT(open_access(0x0F000000u, &g), (LONG)0xC0000061);
}

/* ---- object attribute flags ------------------------------------------------------------- */
#define ATTR_ROW(n, a, want) EP_ROW(aect_attr_##n, ep_tcp4(&e), e.attrs = (a), want)
ATTR_ROW(none, 0, ST_SUCCESS)
ATTR_ROW(case_insensitive, OBJ_CASE_INSENSITIVE, ST_SUCCESS)
ATTR_ROW(inherit, OBJ_INHERIT, ST_SUCCESS)
ATTR_ROW(openif, OBJ_OPENIF, ST_SUCCESS)
ATTR_ROW(force_access_check, 0x400 | OBJ_CASE_INSENSITIVE, ST_SUCCESS)
ATTR_ROW(ignore_impersonated_devicemap, 0x800 | OBJ_CASE_INSENSITIVE, ST_SUCCESS)
ATTR_ROW(dont_reparse, 0x1000 | OBJ_CASE_INSENSITIVE, ST_SUCCESS)
ATTR_ROW(openlink, OBJ_OPENLINK | OBJ_CASE_INSENSITIVE, ST_INVALID_PARAMETER)

/* The flags byte of the EA entry is not interpreted by the driver or the I/O manager for this device. */
static LONG open_with_entry_flags(unsigned char fl)
{
    ep_t e; aop_t pk; unsigned char buf[256]; ULONG len; UNICODE_STRING us; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h = NULL; LONG st;
    static const wchar_t path[] = L"\\Device\\Afd\\Endpoint";
    ep_tcp4(&e); pk = e.pkt;
    len = ea_one(buf, sizeof(buf), "AfdOpenPacketXX", -1, &pk, AOP_HDR + 24);
    buf[4] = fl;
    us.Buffer = (PWSTR)path; us.Length = sizeof(path) - 2; us.MaximumLength = sizeof(path);
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    st = N.NtCreateFile(&h, 0xC0140000u, &oa, &io, NULL, 0, 3, 3, 0, buf, len);
    if (h) N.NtClose(h);
    return st;
}
#define EAFLAG_OK(n, v) TEST(aect_ea_entry_flags_##n) { NEED(); EXPECT_NT(open_with_entry_flags(v), ST_SUCCESS); }
EAFLAG_OK(00, 0x00) EAFLAG_OK(01, 0x01) EAFLAG_OK(80, 0x80) EAFLAG_OK(81, 0x81) EAFLAG_OK(ff, 0xFF)

/* EaLength is checked against the entry by the I/O manager before the driver sees anything:
 * shorter than the entry is STATUS_EA_LIST_INCONSISTENT, longer (trailing zero bytes) is accepted. */
#define EALEN_ROW(n, adj, want) EP_ROW(aect_ealength_##n, ep_tcp4(&e), e.ea_total_adjust = (adj), want)
EALEN_ROW(minus7, -7, ST_EA_LIST_INCONSISTENT)
EALEN_ROW(minus4, -4, ST_EA_LIST_INCONSISTENT)
EALEN_ROW(minus1, -1, ST_EA_LIST_INCONSISTENT)
EALEN_ROW(exact, 0, ST_SUCCESS)
EALEN_ROW(plus1, 1, ST_SUCCESS)
EALEN_ROW(plus3, 3, ST_SUCCESS)
EALEN_ROW(plus4, 4, ST_SUCCESS)
EALEN_ROW(plus8, 8, ST_SUCCESS)
EALEN_ROW(plus64, 64, ST_SUCCESS)
