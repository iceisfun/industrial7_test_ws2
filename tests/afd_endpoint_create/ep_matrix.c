/* AFD endpoint creation: the success matrix.
 *
 * Measures which open packets produce an endpoint. The combinations are the ones the Winsock helper
 * layer sends for ordinary sockets: IPv4/IPv6 stream (TCP), datagram (UDP) and raw, each with the
 * stock transport device name, and the same triples opened without a transport name (the driver
 * resolves the transport itself). Also: the layout the helper layer really uses (value length 4 bytes
 * past the minimum), group selectors, repeated opens, and the path component after the device name.
 * Every row opens and closes; nothing is sent. */
#include "aec.h"

#define OPEN_OK(tname, base, mut) EP_ROW(tname, base, mut, ST_SUCCESS)
#define TCP4  ep_tcp4(&e)
#define UDP4  ep_udp4(&e)
#define TCP6  ep_tcp6(&e)
#define UDP6  ep_udp6(&e)
#define NONAME(base) do { base; e.pkt.TdnLen = 0; e.pkt.Name[0] = 0; } while (0)
#define NOP (void)0

/* Raw rows other than ICMP/ICMPv6 and the bare device path need an elevated token; an unelevated one is refused
   with access denied. */
/* ---- named transport, overlapped-style open (no synchronous bit) --------------------- */
OPEN_OK(aecm_tcp4_named,  TCP4, NOP)
OPEN_OK(aecm_udp4_named,  UDP4, NOP)
OPEN_OK(aecm_tcp6_named,  TCP6, NOP)
OPEN_OK(aecm_udp6_named,  UDP6, NOP)
EP_ROW_ADMIN(aecm_raw4_proto0_named,   ep_raw4(&e, 0), NOP)
OPEN_OK(aecm_raw4_icmp_named,     ep_raw4(&e, 1), NOP)
EP_ROW_ADMIN(aecm_raw4_igmp_named,     ep_raw4(&e, 2), NOP)
EP_ROW_ADMIN(aecm_raw4_tcp_named,      ep_raw4(&e, 6), NOP)
EP_ROW_ADMIN(aecm_raw4_udp_named,      ep_raw4(&e, 17), NOP)
EP_ROW_ADMIN(aecm_raw4_255_named,      ep_raw4(&e, 255), NOP)
EP_ROW_ADMIN(aecm_raw6_proto0_named,   ep_raw6(&e, 0), NOP)
OPEN_OK(aecm_raw6_icmp6_named,    ep_raw6(&e, 58), NOP)
EP_ROW_ADMIN(aecm_raw6_tcp_named,      ep_raw6(&e, 6), NOP)
EP_ROW_ADMIN(aecm_raw6_udp_named,      ep_raw6(&e, 17), NOP)
EP_ROW_ADMIN(aecm_raw6_255_named,      ep_raw6(&e, 255), NOP)

/* the bare device name (no protocol suffix) is also accepted for the raw triple */
OPEN_OK(aecm_raw4_bare_name_icmp,  ep_raw4_bare(&e, 1), NOP)
EP_ROW_ADMIN(aecm_raw4_bare_name_255,   ep_raw4_bare(&e, 255), NOP)
OPEN_OK(aecm_raw6_bare_name_icmp6, ep_raw6_bare(&e, 58), NOP)
EP_ROW_ADMIN(aecm_raw6_bare_name_255,   ep_raw6_bare(&e, 255), NOP)

/* ---- the same with the synchronous create option --------------------------------------- */
OPEN_OK(aecm_tcp4_named_sync,  TCP4, e.options = 0x20)
OPEN_OK(aecm_udp4_named_sync,  UDP4, e.options = 0x20)
OPEN_OK(aecm_tcp6_named_sync,  TCP6, e.options = 0x20)
OPEN_OK(aecm_udp6_named_sync,  UDP6, e.options = 0x20)
OPEN_OK(aecm_raw4_named_sync,  ep_raw4(&e, 1), e.options = 0x20)
OPEN_OK(aecm_raw6_named_sync,  ep_raw6(&e, 58), e.options = 0x20)

/* ---- no transport name: the driver finds the provider by family/type/protocol ---------- */
OPEN_OK(aecm_tcp4_noname,  NONAME(TCP4), NOP)
OPEN_OK(aecm_udp4_noname,  NONAME(UDP4), NOP)
OPEN_OK(aecm_tcp6_noname,  NONAME(TCP6), NOP)
OPEN_OK(aecm_udp6_noname,  NONAME(UDP6), NOP)
OPEN_OK(aecm_raw4_icmp_noname,  NONAME(ep_raw4(&e, 1)), NOP)
EP_ROW_ADMIN(aecm_raw4_255_noname,   NONAME(ep_raw4(&e, 255)), NOP)
OPEN_OK(aecm_raw6_icmp6_noname, NONAME(ep_raw6(&e, 58)), NOP)
EP_ROW_ADMIN(aecm_raw6_255_noname,   NONAME(ep_raw6(&e, 255)), NOP)
OPEN_OK(aecm_tcp4_noname_sync,  NONAME(TCP4), e.options = 0x20)
OPEN_OK(aecm_udp4_noname_sync,  NONAME(UDP4), e.options = 0x20)
/* the raw rows work for any protocol number on the raw triple */
EP_ROW_ADMIN(aecm_raw4_noname_proto_47,  NONAME(ep_raw4(&e, 47)), NOP)
EP_ROW_ADMIN(aecm_raw4_noname_proto_0,   NONAME(ep_raw4(&e, 0)), NOP)
EP_ROW_ADMIN(aecm_raw6_noname_proto_44,  NONAME(ep_raw6(&e, 44)), NOP)

/* ---- the helper layer's real value length (transport name length + 30) ---------------- */
OPEN_OK(aecm_tcp4_helper_layout,  TCP4, e.value_len = (int)e.pkt.TdnLen + 30)
OPEN_OK(aecm_udp4_helper_layout,  UDP4, e.value_len = (int)e.pkt.TdnLen + 30)
OPEN_OK(aecm_tcp6_helper_layout,  TCP6, e.value_len = (int)e.pkt.TdnLen + 30)
OPEN_OK(aecm_udp6_helper_layout,  UDP6, e.value_len = (int)e.pkt.TdnLen + 30)
OPEN_OK(aecm_raw4_helper_layout,  ep_raw4(&e, 1), e.value_len = (int)e.pkt.TdnLen + 30)
OPEN_OK(aecm_raw6_helper_layout,  ep_raw6(&e, 58), e.value_len = (int)e.pkt.TdnLen + 30)

/* ---- the value may be longer than needed: trailing bytes are not interpreted ----------- */
OPEN_OK(aecm_tcp4_value_padded_8,   TCP4, e.value_len = 22 + 26 + 8)
OPEN_OK(aecm_tcp4_value_padded_64,  TCP4, e.value_len = 22 + 26 + 64)
OPEN_OK(aecm_udp4_value_padded_8,   UDP4, e.value_len = 22 + 26 + 8)

/* ---- group selectors with every family -------------------------------------------------- */
OPEN_OK(aecm_tcp4_group_unconstrained, TCP4, e.pkt.GroupID = 1)
OPEN_OK(aecm_tcp4_group_constrained,   TCP4, e.pkt.GroupID = 2)
OPEN_OK(aecm_tcp6_group_unconstrained, TCP6, e.pkt.GroupID = 1)
OPEN_OK(aecm_raw4_group_constrained,   ep_raw4(&e, 1), e.pkt.GroupID = 2)
OPEN_OK(aecm_tcp4_noname_group_constrained, NONAME(TCP4), e.pkt.GroupID = 2)

/* ---- defined flag bits on the stock rows ------------------------------------------------ */
/* The no-filter bit (0x01000000) and the registered-I/O bit (0x10000000) are accepted flag bits. */
OPEN_OK(aecm_tcp4_flag_nofilter,  TCP4, e.pkt.Flags |= AOP_NO_FILTER)
OPEN_OK(aecm_udp4_flag_nofilter,  UDP4, e.pkt.Flags |= AOP_NO_FILTER)
OPEN_OK(aecm_tcp6_flag_nofilter,  TCP6, e.pkt.Flags |= AOP_NO_FILTER)
OPEN_OK(aecm_raw4_flag_nofilter,  ep_raw4(&e, 1), e.pkt.Flags |= AOP_NO_FILTER)
OPEN_OK(aecm_tcp4_noname_flag_nofilter, NONAME(TCP4), e.pkt.Flags |= AOP_NO_FILTER)
OPEN_OK(aecm_tcp4_flag_rio,  TCP4, e.pkt.Flags |= AOP_RIO)
OPEN_OK(aecm_udp4_flag_rio,  UDP4, e.pkt.Flags |= AOP_RIO)
OPEN_OK(aecm_tcp6_flag_rio,  TCP6, e.pkt.Flags |= AOP_RIO)
OPEN_OK(aecm_udp6_flag_rio,  UDP6, e.pkt.Flags |= AOP_RIO)
/* The multipoint flags need a transport that supports multipoint; the TCP/UDP transports are
 * asked, whatever they answer is recorded rather than asserted. */
#define NOTE_ROW(tname, base, mut, label) TEST(tname) { ep_t e; LONG st; NEED(); base; mut; st = ep_try(&e); \
    t_note(label " -> %s", st_name(st)); }
OPEN_OK(aecm_tcp4_flag_multipoint, TCP4, e.pkt.Flags |= AOP_MULTIPOINT)
OPEN_OK(aecm_udp4_flag_multipoint, UDP4, e.pkt.Flags |= AOP_MULTIPOINT)
OPEN_OK(aecm_udp4_c_root, UDP4, e.pkt.Flags |= AOP_MULTIPOINT | AOP_C_ROOT)
OPEN_OK(aecm_udp4_d_root, UDP4, e.pkt.Flags |= AOP_MULTIPOINT | AOP_D_ROOT)
OPEN_OK(aecm_tcp4_connectionless_flag, TCP4, e.pkt.Flags = AOP_CONNECTIONLESS)
OPEN_OK(aecm_udp4_stream_flags, UDP4, e.pkt.Flags = 0)
OPEN_OK(aecm_tcp4_message_oriented_only_named, TCP4, e.pkt.Flags = AOP_MSG_ORIENTED)
OPEN_OK(aecm_udp4_raw_flag, UDP4, e.pkt.Flags |= AOP_RAW)
OPEN_OK(aecm_tcp4_raw_flag, TCP4, e.pkt.Flags |= AOP_RAW)
OPEN_OK(aecm_name_case_lower, TCP4, (wcscpy(e.pkt.Name, L"\\device\\tcp")))
OPEN_OK(aecm_name_case_upper, TCP4, (wcscpy(e.pkt.Name, L"\\DEVICE\\TCP")))
OPEN_OK(aecm_tcp4_triple_udp_name, TCP4, (wcscpy(e.pkt.Name, L"\\Device\\Udp"), e.pkt.TdnLen = 22))
OPEN_OK(aecm_udp4_triple_tcp_name, UDP4, (wcscpy(e.pkt.Name, L"\\Device\\Tcp"), e.pkt.TdnLen = 22))
OPEN_OK(aecm_tcp4_triple_tcp6_name, TCP4, (wcscpy(e.pkt.Name, L"\\Device\\Tcp6"), e.pkt.TdnLen = 24))
OPEN_OK(aecm_unknown_device_name, TCP4, (wcscpy(e.pkt.Name, L"\\Device\\NoSuchTransport0"), e.pkt.TdnLen = 48))
EP_ROW(aecm_relative_transport_name, TCP4, (wcscpy(e.pkt.Name, L"Tcp"), e.pkt.TdnLen = 6), ST_PATH_SYNTAX_BAD)
EP_ROW(aecm_afd_device_as_transport_name, TCP4, (wcscpy(e.pkt.Name, L"\\Device\\Afd"), e.pkt.TdnLen = 22), ST_INVALID_DEVICE_REQUEST)
EP_ROW(aecm_noname_dgram_with_tcp_protocol, NONAME(UDP4), e.pkt.Protocol = 6, ST_NO_SUCH_FILE)
EP_ROW(aecm_noname_stream_protocol_zero, NONAME(TCP4), e.pkt.Protocol = 0, ST_NO_SUCH_FILE)
EP_ROW(aecm_noname_dgram_protocol_zero, NONAME(UDP4), e.pkt.Protocol = 0, ST_NO_SUCH_FILE)
EP_ROW(aecm_noname_af_unix_stream, NONAME(TCP4), (e.pkt.Family = 1, e.pkt.Protocol = 0), ST_SUCCESS)
EP_ROW(aecm_noname_family_unspec, NONAME(TCP4), e.pkt.Family = 0, ST_AFD_UNSERVED)

/* ---- repeated and concurrent opens ------------------------------------------------------- */
TEST(aecm_two_opens_distinct_handles)
{
    ep_t e; HANDLE a, b; IO_STATUS_BLOCK io; NEED(); TCP4;
    EXPECT_NT(ep_open(&e, &a, &io), ST_SUCCESS);
    EXPECT_NT(ep_open(&e, &b, &io), ST_SUCCESS);
    CHECK(a && b && a != b);
    if (a) N.NtClose(a);
    if (b) N.NtClose(b);
}
TEST(aecm_open_close_100_times)
{
    ep_t e; int i, ok = 0; NEED(); TCP4;
    for (i = 0; i < 100; i++) if (ep_try(&e) == ST_SUCCESS) ok++;
    EXPECT_EQ(ok, 100);
}
TEST(aecm_hold_64_endpoints_then_close)
{
    ep_t e; HANDLE h[64]; IO_STATUS_BLOCK io; int i, ok = 0; NEED(); TCP4;
    for (i = 0; i < 64; i++) { h[i] = NULL; if (ep_open(&e, &h[i], &io) == ST_SUCCESS) ok++; }
    EXPECT_EQ(ok, 64);
    for (i = 0; i < 64; i++) { int j; for (j = 0; j < i; j++) if (h[i] && h[i] == h[j]) CHECK(!"duplicate handle value"); }
    for (i = 0; i < 64; i++) if (h[i]) EXPECT_NT(N.NtClose(h[i]), ST_SUCCESS);
}
TEST(aecm_mixed_kinds_together)
{
    ep_t e; HANDLE h[6]; IO_STATUS_BLOCK io; int i, ok = 0; NEED();
    ep_tcp4(&e); if (ep_open(&e, &h[0], &io) == 0) ok++;
    ep_udp4(&e); if (ep_open(&e, &h[1], &io) == 0) ok++;
    ep_tcp6(&e); if (ep_open(&e, &h[2], &io) == 0) ok++;
    ep_udp6(&e); if (ep_open(&e, &h[3], &io) == 0) ok++;
    ep_raw4(&e, 1); if (ep_open(&e, &h[4], &io) == 0) ok++;
    ep_raw6(&e, 58); if (ep_open(&e, &h[5], &io) == 0) ok++;
    EXPECT_EQ(ok, 6);
    for (i = 0; i < 6; i++) if (h[i]) N.NtClose(h[i]);
}
/* a device ignores the creation disposition: every defined value opens it */
#define DISP_OK(n) EP_ROW(aecm_disposition_##n, TCP4, e.disp = n, ST_SUCCESS)
DISP_OK(0) DISP_OK(1) DISP_OK(2) DISP_OK(3) DISP_OK(4) DISP_OK(5)
TEST(aecm_disposition_beyond_range_rejected_by_io_manager)
{
    ep_t e; NEED(); TCP4; e.disp = 6;
    EXPECT_NT(ep_try(&e), ST_INVALID_PARAMETER);
}

/* ---- the path component after \Device\Afd --------------------------------------------------- */
/* The create handler never looks at the file name, so a packet is accepted behind any leaf. */
#define LEAF_OK(tname, p) EP_ROW(tname, TCP4, e.path = p, ST_SUCCESS)
LEAF_OK(aecm_leaf_endpoint,        L"\\Device\\Afd\\Endpoint")
LEAF_OK(aecm_leaf_endpoint_lower,  L"\\Device\\Afd\\endpoint")
LEAF_OK(aecm_leaf_endpoint_upper,  L"\\Device\\Afd\\ENDPOINT")
LEAF_OK(aecm_leaf_arbitrary,       L"\\Device\\Afd\\Whatever")
LEAF_OK(aecm_leaf_single_char,     L"\\Device\\Afd\\x")
LEAF_OK(aecm_leaf_long,            L"\\Device\\Afd\\AVeryLongLeafNameThatMeansNothingToTheDriver0123456789")
EP_ROW_ADMIN(aecm_leaf_device_only, TCP4, e.path = L"\\Device\\Afd")
LEAF_OK(aecm_leaf_device_trailing_slash, L"\\Device\\Afd\\")
LEAF_OK(aecm_device_name_lower,    L"\\device\\afd\\endpoint")
LEAF_OK(aecm_device_name_upper,    L"\\DEVICE\\AFD\\ENDPOINT")
/* no packet: a control endpoint, behind any leaf */
#define CTL_OK(tname, p) EP_ROW(tname, TCP4, (e.no_ea = 1, e.path = p), ST_SUCCESS)
CTL_OK(aecm_ctl_endpoint,        L"\\Device\\Afd\\Endpoint")
EP_ROW_ADMIN(aecm_ctl_device_only, TCP4, (e.no_ea = 1, e.path = L"\\Device\\Afd"))
CTL_OK(aecm_ctl_trailing_slash,  L"\\Device\\Afd\\")
CTL_OK(aecm_ctl_arbitrary_leaf,  L"\\Device\\Afd\\SomethingElse")
TEST(aecm_ctl_two_handles_distinct)
{
    ep_t e; HANDLE a, b; IO_STATUS_BLOCK io; NEED(); TCP4; e.no_ea = 1;
    EXPECT_NT(ep_open(&e, &a, &io), ST_SUCCESS);
    EXPECT_NT(ep_open(&e, &b, &io), ST_SUCCESS);
    CHECK(a && b && a != b);
    if (a) N.NtClose(a);
    if (b) N.NtClose(b);
}
TEST(aecm_ctl_ignores_packet_when_no_ea_given_with_garbage_flags)
{
    /* with no attribute at all the packet is not consulted: contrast with aecerr_flags_* */
    ep_t e; NEED(); TCP4; e.no_ea = 1; e.pkt.Flags = 0xFFFFFFFFu;
    EXPECT_NT(ep_try(&e), ST_SUCCESS);
}
TEST(aecm_nonexistent_sibling_device_fails)
{
    ep_t e; LONG st; NEED(); TCP4; e.path = L"\\Device\\Afd2\\Endpoint";
    st = ep_try(&e);
    CHECKF(st == ST_OBJECT_NAME_NOT_FOUND || st == ST_OBJECT_PATH_NOT_FOUND, "got %#lx", (unsigned long)st);
}
TEST(aecm_misspelled_device_object_name_not_found)
{
    ep_t e; NEED(); TCP4; e.path = L"\\Device\\Afdx";
    EXPECT_NT(ep_try(&e), ST_OBJECT_NAME_NOT_FOUND);
}
