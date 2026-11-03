/* AFD open-packet validation: exact NTSTATUS for malformed AfdOpenPacketXX extended attributes.
 *
 * Measures the checks the driver applies in its create handler, in the order it applies them:
 *   1. the EA name decides which kind of endpoint is requested (the open packet, the helper packet and
 *      the registration-domain packet are the only accepted names; anything else is
 *      STATUS_INVALID_PARAMETER);
 *   2. the declared value length must cover the 24-byte fixed part plus the transport name rounded up
 *      to an even size plus a terminator slot, and be at least 28 bytes; failing that the create
 *      completes with STATUS_ACCESS_VIOLATION (an NTSTATUS, not an exception);
 *   3. reserved flag bits (every bit outside 0x11111111) and an odd transport-name length are
 *      STATUS_INVALID_PARAMETER;
 *   4. without a transport name the family/type/protocol triple is checked (family < 0x23, type and
 *      protocol < 0x10000, message-oriented requires connectionless) and then looked up among the
 *      registered transports (STATUS_NO_SUCH_FILE when none matches);
 *   5. the group id must be 0, one of the two "new group" selectors, or an existing group.
 * Every case only opens and closes a handle; nothing is sent. */
#include "aec.h"

#define TCP4  ep_tcp4(&e)
#define UDP4  ep_udp4(&e)
#define TCP6  ep_tcp6(&e)
#define NONAME(base) do { base; e.pkt.TdnLen = 0; e.pkt.Name[0] = 0; } while (0)

/* ---- 1. EA name --------------------------------------------------------------- */
EP_ROW(aecerr_name_last_char_differs,  TCP4, e.ea_name = "AfdOpenPacketXY", ST_INVALID_PARAMETER)
EP_ROW(aecerr_name_one_char_short,     TCP4, e.ea_name = "AfdOpenPacketX", ST_INVALID_PARAMETER)
EP_ROW(aecerr_name_prefix_only,        TCP4, e.ea_name = "AfdOpenPacket", ST_INVALID_PARAMETER)
EP_ROW(aecerr_name_one_char_long,      TCP4, e.ea_name = "AfdOpenPacketXXX", ST_INVALID_PARAMETER)
EP_ROW(aecerr_name_first_char_differs, TCP4, e.ea_name = "BfdOpenPacketXX", ST_INVALID_PARAMETER)
EP_ROW(aecerr_name_single_char,        TCP4, e.ea_name = "A", ST_INVALID_PARAMETER)
EP_ROW(aecerr_name_unrelated,          TCP4, e.ea_name = "SocketPacket", ST_INVALID_PARAMETER)
EP_ROW(aecerr_name_digit_suffix,       TCP4, e.ea_name = "AfdOpenPacket01", ST_INVALID_PARAMETER)
EP_ROW(aecerr_name_helper_prefix_only, TCP4, e.ea_name = "AfdSwOpenPacke", ST_INVALID_PARAMETER)
EP_ROW(aecerr_name_rio_prefix_only,    TCP4, e.ea_name = "AfdRioRDOpenPacke", ST_INVALID_PARAMETER)
EP_ROW(aecerr_name_rio_suffix_extra,   TCP4, e.ea_name = "AfdRioRDOpenPacketX", ST_INVALID_PARAMETER)

/* ---- 2. value length ------------------------------------------------------------ */
/* Everything below the 28-byte minimum is rejected before any field is read. */
EP_ROW(aecerr_vlen_0,   TCP4, e.value_len = 0,  ST_ACCESS_VIOLATION)
EP_ROW(aecerr_vlen_1,   TCP4, e.value_len = 1,  ST_ACCESS_VIOLATION)
EP_ROW(aecerr_vlen_4,   TCP4, e.value_len = 4,  ST_ACCESS_VIOLATION)
EP_ROW(aecerr_vlen_8,   TCP4, e.value_len = 8,  ST_ACCESS_VIOLATION)
EP_ROW(aecerr_vlen_12,  TCP4, e.value_len = 12, ST_ACCESS_VIOLATION)
EP_ROW(aecerr_vlen_16,  TCP4, e.value_len = 16, ST_ACCESS_VIOLATION)
EP_ROW(aecerr_vlen_20,  TCP4, e.value_len = 20, ST_ACCESS_VIOLATION)
EP_ROW(aecerr_vlen_23,  TCP4, e.value_len = 23, ST_ACCESS_VIOLATION)
EP_ROW(aecerr_vlen_24,  TCP4, e.value_len = 24, ST_ACCESS_VIOLATION)
EP_ROW(aecerr_vlen_25,  TCP4, e.value_len = 25, ST_ACCESS_VIOLATION)
EP_ROW(aecerr_vlen_26,  TCP4, e.value_len = 26, ST_ACCESS_VIOLATION)
EP_ROW(aecerr_vlen_27,  TCP4, e.value_len = 27, ST_ACCESS_VIOLATION)
/* the same shortfall without a transport name: 28 is the first length that passes the minimum */
TEST(aecerr_vlen_28_no_transport_name_ok)
{
    ep_t e; NEED(); NONAME(TCP4); e.value_len = 28;
    EXPECT_NT(ep_try(&e), ST_SUCCESS);
}
TEST(aecerr_vlen_27_no_transport_name)
{
    ep_t e; NEED(); NONAME(TCP4); e.value_len = 27;
    EXPECT_NT(ep_try(&e), ST_ACCESS_VIOLATION);
}
TEST(aecerr_vlen_larger_than_needed_no_transport_name_ok)
{
    ep_t e; NEED(); NONAME(UDP4); e.value_len = 120;
    EXPECT_NT(ep_try(&e), ST_SUCCESS);
}
/* With a transport name the needed length is 24 + ((tdnl + 2) & ~1) = tdnl + 26 for even tdnl. */
TEST(aecerr_vlen_exact_for_tcp_name_ok)       { ep_t e; NEED(); TCP4; e.value_len = 22 + 26; EXPECT_NT(ep_try(&e), ST_SUCCESS); }
TEST(aecerr_vlen_one_short_for_tcp_name)      { ep_t e; NEED(); TCP4; e.value_len = 22 + 26 - 1; EXPECT_NT(ep_try(&e), ST_ACCESS_VIOLATION); }
TEST(aecerr_vlen_two_short_for_tcp_name)      { ep_t e; NEED(); TCP4; e.value_len = 22 + 26 - 2; EXPECT_NT(ep_try(&e), ST_ACCESS_VIOLATION); }
TEST(aecerr_vlen_eight_short_for_tcp_name)    { ep_t e; NEED(); TCP4; e.value_len = 22 + 26 - 8; EXPECT_NT(ep_try(&e), ST_ACCESS_VIOLATION); }
TEST(aecerr_vlen_helper_layout_30_extra_ok)   { ep_t e; NEED(); TCP4; e.value_len = 22 + 30; EXPECT_NT(ep_try(&e), ST_SUCCESS); }
TEST(aecerr_vlen_exact_for_udp_name_ok)       { ep_t e; NEED(); UDP4; e.value_len = 22 + 26; EXPECT_NT(ep_try(&e), ST_SUCCESS); }
TEST(aecerr_vlen_one_short_for_udp_name)      { ep_t e; NEED(); UDP4; e.value_len = 22 + 26 - 1; EXPECT_NT(ep_try(&e), ST_ACCESS_VIOLATION); }
TEST(aecerr_vlen_exact_for_tcp6_name_ok)      { ep_t e; NEED(); TCP6; e.value_len = 24 + 26; EXPECT_NT(ep_try(&e), ST_SUCCESS); }
TEST(aecerr_vlen_one_short_for_tcp6_name)     { ep_t e; NEED(); TCP6; e.value_len = 24 + 26 - 1; EXPECT_NT(ep_try(&e), ST_ACCESS_VIOLATION); }
/* the minimum binds even for the shortest name: tdnl 2 needs 28 which equals the minimum */
TEST(aecerr_vlen_one_char_name_27)
{
    ep_t e; NEED(); TCP4; wcscpy(e.pkt.Name, L"x"); e.pkt.TdnLen = 2; e.value_len = 27;
    EXPECT_NT(ep_try(&e), ST_ACCESS_VIOLATION);
}
TEST(aecerr_vlen_one_char_name_28_passes_length_rule)
{
    /* The length rule is satisfied; whatever the lookup of the name then says, it is not the length status. */
    ep_t e; NEED(); TCP4; wcscpy(e.pkt.Name, L"x"); e.pkt.TdnLen = 2; e.value_len = 28;
    LONG st = ep_try(&e);
    CHECKF(st != ST_ACCESS_VIOLATION, "got %#lx", (unsigned long)st);
}

/* ---- transport-name length field ----------------------------------------------- */
/* Odd lengths are rejected once the value is long enough to be read. */
#define ODD_TDNL(n, v) TEST(aecerr_tdnl_odd_##n) { ep_t e; NEED(); TCP4; e.pkt.TdnLen = (v); e.value_len = 100; \
    EXPECT_NT(ep_try(&e), ST_INVALID_PARAMETER); }
ODD_TDNL(1, 1)
ODD_TDNL(3, 3)
ODD_TDNL(5, 5)
ODD_TDNL(21, 21)
ODD_TDNL(23, 23)
ODD_TDNL(45, 45)
/* A length so large that rounding it up leaves the 16-bit range, or wraps, is the length status. */
#define HUGE_TDNL(n, v) TEST(aecerr_tdnl_huge_##n) { ep_t e; NEED(); TCP4; e.pkt.TdnLen = (v); e.value_len = 100; \
    EXPECT_NT(ep_try(&e), ST_ACCESS_VIOLATION); }
HUGE_TDNL(fffe, 0xFFFEu)
HUGE_TDNL(ffff, 0xFFFFu)
HUGE_TDNL(10000, 0x10000u)
HUGE_TDNL(7fffffff, 0x7FFFFFFFu)
HUGE_TDNL(fffffffe, 0xFFFFFFFEu)
HUGE_TDNL(ffffffff, 0xFFFFFFFFu)
HUGE_TDNL(fffd, 0xFFFDu)
/* A declared name longer than the declared value is the length status, not a lookup failure. */
TEST(aecerr_tdnl_longer_than_value_by_two)  { ep_t e; NEED(); TCP4; e.pkt.TdnLen = 24; e.value_len = 24 + 24; EXPECT_NT(ep_try(&e), ST_ACCESS_VIOLATION); }
TEST(aecerr_tdnl_longer_than_value_by_many) { ep_t e; NEED(); TCP4; e.pkt.TdnLen = 64; e.value_len = 48; EXPECT_NT(ep_try(&e), ST_ACCESS_VIOLATION); }
TEST(aecerr_tdnl_with_minimum_value)        { ep_t e; NEED(); TCP4; e.pkt.TdnLen = 22; e.value_len = 28; EXPECT_NT(ep_try(&e), ST_ACCESS_VIOLATION); }

/* ---- 3. flag bits ------------------------------------------------------------- */
/* Only bit 0 of every nibble is defined; setting any other bit is rejected before the lookup. */
#define BADFLAG_T(n, v) EP_ROW(aecerr_flags_tcp_##n, TCP4, e.pkt.Flags = (v), ST_INVALID_PARAMETER)
#define BADFLAG_N(n, v) EP_ROW(aecerr_flags_noname_##n, NONAME(TCP4), e.pkt.Flags = (v), ST_INVALID_PARAMETER)
BADFLAG_T(b1, 0x2u)      BADFLAG_N(b1, 0x2u)
BADFLAG_T(b2, 0x4u)      BADFLAG_N(b2, 0x4u)
BADFLAG_T(b3, 0x8u)      BADFLAG_N(b3, 0x8u)
BADFLAG_T(b5, 0x20u)     BADFLAG_N(b5, 0x20u)
BADFLAG_T(b6, 0x40u)     BADFLAG_N(b6, 0x40u)
BADFLAG_T(b7, 0x80u)     BADFLAG_N(b7, 0x80u)
BADFLAG_T(b9, 0x200u)    BADFLAG_N(b9, 0x200u)
BADFLAG_T(b10, 0x400u)   BADFLAG_N(b10, 0x400u)
BADFLAG_T(b11, 0x800u)   BADFLAG_N(b11, 0x800u)
BADFLAG_T(b13, 0x2000u)  BADFLAG_N(b13, 0x2000u)
BADFLAG_T(b14, 0x4000u)  BADFLAG_N(b14, 0x4000u)
BADFLAG_T(b15, 0x8000u)  BADFLAG_N(b15, 0x8000u)
BADFLAG_T(b17, 0x20000u) BADFLAG_N(b17, 0x20000u)
BADFLAG_T(b18, 0x40000u) BADFLAG_N(b18, 0x40000u)
BADFLAG_T(b19, 0x80000u) BADFLAG_N(b19, 0x80000u)
BADFLAG_T(b21, 0x200000u) BADFLAG_N(b21, 0x200000u)
BADFLAG_T(b22, 0x400000u) BADFLAG_N(b22, 0x400000u)
BADFLAG_T(b23, 0x800000u) BADFLAG_N(b23, 0x800000u)
BADFLAG_T(b25, 0x2000000u) BADFLAG_N(b25, 0x2000000u)
BADFLAG_T(b26, 0x4000000u) BADFLAG_N(b26, 0x4000000u)
BADFLAG_T(b27, 0x8000000u) BADFLAG_N(b27, 0x8000000u)
BADFLAG_T(b29, 0x20000000u) BADFLAG_N(b29, 0x20000000u)
BADFLAG_T(b30, 0x40000000u) BADFLAG_N(b30, 0x40000000u)
BADFLAG_T(b31, 0x80000000u) BADFLAG_N(b31, 0x80000000u)
BADFLAG_T(all_reserved, 0xEEEEEEEEu)
BADFLAG_N(all_reserved, 0xEEEEEEEEu)
BADFLAG_T(all_ones, 0xFFFFFFFFu)
BADFLAG_T(valid_plus_reserved, 0x00000003u)
BADFLAG_T(valid_connectionless_plus_b3, 0x00000009u)
EP_ROW(aecerr_flags_udp_with_reserved, UDP4, e.pkt.Flags |= 0x2, ST_INVALID_PARAMETER)
EP_ROW(aecerr_flags_udp_with_high_reserved, UDP4, e.pkt.Flags |= 0x80000000u, ST_INVALID_PARAMETER)

/* ---- 4. no transport name: triple validation and lookup ---------------------------- */
EP_ROW(aecerr_noname_family_ffffffff, NONAME(TCP4), e.pkt.Family = 0xFFFFFFFFu, ST_INVALID_PARAMETER)
EP_ROW(aecerr_noname_family_23h,      NONAME(TCP4), e.pkt.Family = 0x23, ST_INVALID_PARAMETER)
EP_ROW(aecerr_noname_family_24h,      NONAME(TCP4), e.pkt.Family = 0x24, ST_INVALID_PARAMETER)
EP_ROW(aecerr_noname_family_100h,     NONAME(TCP4), e.pkt.Family = 0x100, ST_INVALID_PARAMETER)
EP_ROW(aecerr_noname_family_ffff,     NONAME(TCP4), e.pkt.Family = 0xFFFF, ST_INVALID_PARAMETER)
EP_ROW(aecerr_noname_family_80000002, NONAME(TCP4), e.pkt.Family = 0x80000002u, ST_INVALID_PARAMETER)
EP_ROW(aecerr_noname_type_10000h,     NONAME(TCP4), e.pkt.Type = 0x10000, ST_INVALID_PARAMETER)
EP_ROW(aecerr_noname_type_ffffffff,   NONAME(TCP4), e.pkt.Type = 0xFFFFFFFFu, ST_INVALID_PARAMETER)
EP_ROW(aecerr_noname_type_80000001,   NONAME(TCP4), e.pkt.Type = 0x80000001u, ST_INVALID_PARAMETER)
EP_ROW(aecerr_noname_proto_10000h,    NONAME(TCP4), e.pkt.Protocol = 0x10000, ST_INVALID_PARAMETER)
EP_ROW(aecerr_noname_proto_ffffffff,  NONAME(TCP4), e.pkt.Protocol = 0xFFFFFFFFu, ST_INVALID_PARAMETER)
EP_ROW(aecerr_noname_proto_80000006,  NONAME(TCP4), e.pkt.Protocol = 0x80000006u, ST_INVALID_PARAMETER)
/* message-oriented without connectionless is not a combination the driver builds */
EP_ROW(aecerr_noname_msg_without_connless,       NONAME(TCP4), e.pkt.Flags = AOP_MSG_ORIENTED, ST_INVALID_PARAMETER)
EP_ROW(aecerr_noname_msg_raw_without_connless,   NONAME(TCP4), e.pkt.Flags = AOP_MSG_ORIENTED | AOP_RAW, ST_INVALID_PARAMETER)
EP_ROW(aecerr_noname_msg_mpoint_without_connless, NONAME(TCP4), e.pkt.Flags = AOP_MSG_ORIENTED | AOP_MULTIPOINT, ST_INVALID_PARAMETER)
EP_ROW(aecerr_noname_msg_with_connless_ok,       NONAME(UDP4), e.pkt.Flags = AOP_MSG_ORIENTED | AOP_CONNECTIONLESS, ST_SUCCESS)
/* a triple nobody serves: STATUS_NO_SUCH_FILE when the family is known but the type/protocol is not,
 * and a transport-specific status (0xC000A013) when the family itself has no provider */
EP_ROW(aecerr_noname_family_21h_unserved, NONAME(TCP4), e.pkt.Family = 0x21, ST_AFD_UNSERVED)
EP_ROW(aecerr_noname_family_22h_unserved, NONAME(TCP4), e.pkt.Family = 0x22, ST_AFD_UNSERVED)
EP_ROW(aecerr_noname_family_22h_dgram_unserved, NONAME(UDP4), e.pkt.Family = 0x22, ST_AFD_UNSERVED)
EP_ROW(aecerr_noname_family_22h_raw_unserved, NONAME(TCP4), (e.pkt.Family = 0x22, e.pkt.Type = 3, e.pkt.Flags = AOP_CONNECTIONLESS | AOP_MSG_ORIENTED | AOP_RAW), ST_AFD_UNSERVED)
EP_ROW(aecerr_noname_type_ffff_unserved, NONAME(TCP4), e.pkt.Type = 0xFFFF, ST_NO_SUCH_FILE)
EP_ROW(aecerr_noname_type_0_unserved, NONAME(TCP4), e.pkt.Type = 0, ST_NO_SUCH_FILE)
EP_ROW(aecerr_noname_type_9_unserved, NONAME(TCP4), e.pkt.Type = 9, ST_NO_SUCH_FILE)
EP_ROW(aecerr_noname_tcp6_proto_ffff_unserved, NONAME(TCP6), e.pkt.Protocol = 0xFFFF, ST_NO_SUCH_FILE)

/* ---- 5. group identifiers ---------------------------------------------------- */
EP_ROW(aecerr_group_unknown_7ffffff0,  TCP4, e.pkt.GroupID = 0x7FFFFFF0u, ST_INVALID_PARAMETER)
EP_ROW(aecerr_group_unknown_ffffffff,  TCP4, e.pkt.GroupID = 0xFFFFFFFFu, ST_INVALID_PARAMETER)
EP_ROW(aecerr_group_unknown_80000000,  TCP4, e.pkt.GroupID = 0x80000000u, ST_INVALID_PARAMETER)
EP_ROW(aecerr_group_unknown_0fffffff,  UDP4, e.pkt.GroupID = 0x0FFFFFFFu, ST_INVALID_PARAMETER)
EP_ROW(aecerr_group_unknown_noname,    NONAME(TCP4), e.pkt.GroupID = 0x7FFFFFF0u, ST_INVALID_PARAMETER)
EP_ROW(aecerr_group_unknown_tcp6,      TCP6, e.pkt.GroupID = 0x7FFFFFF0u, ST_INVALID_PARAMETER)
EP_ROW(aecerr_group_unknown_raw,       ep_raw4(&e, 255), e.pkt.GroupID = 0x7FFFFFF0u, ST_INVALID_PARAMETER)
/* selectors 1 and 2 create a fresh group and succeed */
EP_ROW(aecerr_group_new_unconstrained, TCP4, e.pkt.GroupID = 1, ST_SUCCESS)
EP_ROW(aecerr_group_new_constrained,   TCP4, e.pkt.GroupID = 2, ST_SUCCESS)
EP_ROW(aecerr_group_new_unconstrained_udp, UDP4, e.pkt.GroupID = 1, ST_SUCCESS)
EP_ROW(aecerr_group_new_constrained_udp,   UDP4, e.pkt.GroupID = 2, ST_SUCCESS)
EP_ROW(aecerr_group_none, TCP4, e.pkt.GroupID = 0, ST_SUCCESS)

/* An unknown family together with an unknown group reports the group. */
EP_ROW(aecerr_order_group_before_unknown_family, NONAME(TCP4), (e.pkt.Family = 0x22, e.pkt.GroupID = 0x7FFFFFF0u), ST_INVALID_PARAMETER)
/* flags are checked before the group */
EP_ROW(aecerr_order_flags_before_group, TCP4, (e.pkt.Flags = 0x2, e.pkt.GroupID = 0x7FFFFFF0u), ST_INVALID_PARAMETER)
/* length before flags */
EP_ROW(aecerr_order_length_before_flags, TCP4, (e.pkt.Flags = 0x2, e.value_len = 20), ST_ACCESS_VIOLATION)
/* name before length */
EP_ROW(aecerr_order_name_before_length, TCP4, (e.ea_name = "NotAfd", e.value_len = 0), ST_INVALID_PARAMETER)

/* ---- helper / registration-domain packets -------------------------------------- */
TEST(aecerr_helper_packet_not_supported_on_client)
{
    ep_t e; NEED(); TCP4; e.ea_name = "AfdSwOpenPacket";
    if (!aec_is_client_sku()) { t_skip("server SKU: the helper endpoint may be available"); return; }
    /* The helper endpoint is only offered by server SKUs: a workstation answers STATUS_NOT_SUPPORTED. */
    EXPECT_NT(ep_try(&e), ST_NOT_SUPPORTED);
}
TEST(aecerr_helper_packet_short_value_not_supported_on_client)
{
    ep_t e; NEED(); TCP4; e.ea_name = "AfdSwOpenPacket"; e.value_len = 0;
    if (!aec_is_client_sku()) { t_skip("server SKU"); return; }
    /* the SKU test runs before the value is looked at */
    EXPECT_NT(ep_try(&e), ST_NOT_SUPPORTED);
}
TEST(aecerr_registration_domain_packet_opens)
{
    ep_t e; HANDLE h; IO_STATUS_BLOCK io; LONG st; NEED();
    TCP4; e.ea_name = "AfdRioRDOpenPacket"; e.value_len = 0;
    st = ep_open(&e, &h, &io);
    EXPECT_NT(st, ST_SUCCESS);
    if (h) N.NtClose(h);
}
TEST(aecerr_registration_domain_packet_ignores_value)
{
    ep_t e; NEED(); TCP4; e.ea_name = "AfdRioRDOpenPacket"; e.value_len = 4; e.pkt.Flags = 0xFFFFFFFFu;
    EXPECT_NT(ep_try(&e), ST_SUCCESS);
}
TEST(aecerr_registration_domain_packet_two_handles)
{
    ep_t e; HANDLE a, b; IO_STATUS_BLOCK io; NEED();
    TCP4; e.ea_name = "AfdRioRDOpenPacket"; e.value_len = 0;
    EXPECT_NT(ep_open(&e, &a, &io), ST_SUCCESS);
    EXPECT_NT(ep_open(&e, &b, &io), ST_SUCCESS);
    CHECK(a && b && a != b);
    if (a) N.NtClose(a);
    if (b) N.NtClose(b);
}

/* ---- more than one EA entry --------------------------------------------------- */
/* Only the first entry is examined: a valid packet followed by another attribute is accepted,
 * a foreign attribute followed by the packet is rejected on the first name. */
static ULONG two_entries(unsigned char *buf, size_t cap, const char *n1, const aop_t *pk, int vl1, const char *n2)
{
    ULONG first = ea_one(buf, cap, n1, -1, pk, vl1);
    ULONG padded = (first + 3) & ~3u;
    ULONG second;
    memset(buf + first, 0, padded - first);
    *(ULONG *)buf = padded;
    second = ea_one(buf + padded, cap - padded, n2, -1, NULL, 0);
    return padded + second;
}
static LONG open_with_ea(const unsigned char *ea, ULONG ealen)
{
    UNICODE_STRING us; OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; HANDLE h = NULL; LONG st;
    static const wchar_t path[] = L"\\Device\\Afd\\Endpoint";
    us.Buffer = (PWSTR)path; us.Length = sizeof(path) - 2; us.MaximumLength = sizeof(path);
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    st = N.NtCreateFile(&h, 0xC0140000u, &oa, &io, NULL, 0, 3, 3, 0, (void *)ea, ealen);
    if (st >= 0 && h) N.NtClose(h);
    return st;
}
TEST(aecerr_second_entry_ignored)
{
    ep_t e; unsigned char buf[512]; ULONG len; NEED(); TCP4;
    len = two_entries(buf, sizeof(buf), "AfdOpenPacketXX", &e.pkt, AOP_HDR + 24, "TrailingAttr");
    EXPECT_NT(open_with_ea(buf, len), ST_SUCCESS);
}
TEST(aecerr_second_entry_is_also_a_packet_ignored)
{
    ep_t e, f; unsigned char buf[512]; ULONG len; NEED(); TCP4; ep_udp4(&f);
    len = two_entries(buf, sizeof(buf), "AfdOpenPacketXX", &e.pkt, AOP_HDR + 24, "AfdOpenPacketXY");
    EXPECT_NT(open_with_ea(buf, len), ST_SUCCESS);
}
TEST(aecerr_first_entry_foreign_second_is_packet)
{
    ep_t e; unsigned char buf[512]; ULONG len, first; NEED(); TCP4;
    /* build: [Foreign][AfdOpenPacketXX] */
    first = ea_one(buf, sizeof(buf), "Foreign", -1, NULL, 0);
    {
        ULONG padded = (first + 3) & ~3u;
        ULONG second;
        memset(buf + first, 0, padded - first);
        *(ULONG *)buf = padded;
        second = ea_one(buf + padded, sizeof(buf) - padded, "AfdOpenPacketXX", -1, &e.pkt, AOP_HDR + 24);
        len = padded + second;
    }
    EXPECT_NT(open_with_ea(buf, len), ST_INVALID_PARAMETER);
}
