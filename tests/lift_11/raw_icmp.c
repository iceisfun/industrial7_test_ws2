/* Raw ICMP and ICMPv6 echo on loopback: the reply layout delivered to a raw socket (IPv4 includes the IP
 * header, IPv6 does not), checksum correctness, message-size truncation error. Skipped when the process
 * may not open raw sockets. Only the loopback address is ever pinged. */
#include "lift11.h"

#pragma pack(push, 1)
struct l11_icmp { BYTE type, code; UINT16 sum; UINT16 id, seq; };
struct l11_ip4 { BYTE vhl, tos; UINT16 tot, id, frag; BYTE ttl, proto; UINT16 sum; ULONG src, dst; };
struct l11_pseudo6 { BYTE src[16], dst[16]; UINT32 len; BYTE zero[3], next; };
#pragma pack(pop)

/* One's-complement sum over 16-bit words (little-endian host, bytes summed as stored). */
static unsigned short l11_csum(const BYTE *p, unsigned n)
{
    unsigned long sum = 0;
    while (n > 1) { sum += *(const unsigned short *)p; p += 2; n -= 2; }
    if (n) sum += *p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (unsigned short)~sum;
}

static SOCKET l11_raw(int af, int proto)
{
    SOCKET s;
    s = U(WSASocketA)(af, SOCK_RAW, proto, NULL, 0, 0);
    if (s == INVALID_SOCKET) {
        if (l11_err() == WSAEACCES) t_skip("raw sockets not permitted");
        else t_skip("raw socket unavailable, error %d", l11_err());
        return INVALID_SOCKET;
    }
    l11_rcvtimeo(s, 3000);
    return s;
}

#define RAW_OR_RETURN(var, af, proto) do { UP(); var = l11_raw(af, proto); if (var == INVALID_SOCKET) return; } while (0)

static void l11_make_echo4(BYTE *buf, UINT16 seq)
{
    struct l11_icmp *h = (struct l11_icmp *)buf;
    h->type = 8; h->code = 0; h->sum = 0; h->id = 0xbeaf; h->seq = seq;
    *(unsigned *)(h + 1) = 0xdeadbeef;
    h->sum = l11_csum(buf, sizeof(*h) + 4);
}

static int l11_ping4(SOCKET s, UINT16 seq)
{
    BYTE buf[sizeof(struct l11_icmp) + 4];
    struct sockaddr_in sa;
    l11_loopback(&sa);
    l11_make_echo4(buf, seq);
    return U(sendto)(s, (char *)buf, sizeof(buf), 0, (struct sockaddr *)&sa, sizeof(sa));
}

TEST(rawicmp4_small_buffer_gives_msgsize)
{
    SOCKET s;
    BYTE rb[256];
    RAW_OR_RETURN(s, AF_INET, IPPROTO_ICMP);
    L_EQ(l11_ping4(s, 1), (int)(sizeof(struct l11_icmp) + 4));
    /* One byte short of IP header + ICMP message. */
    L_EQ(U(recv)(s, (char *)rb, sizeof(struct l11_ip4) + sizeof(struct l11_icmp) + 4 - 1, 0), -1);
    L_EQ(l11_err(), WSAEMSGSIZE);
    U(closesocket)(s);
}

TEST(rawicmp4_echo_reply_includes_ip_header)
{
    SOCKET s;
    BYTE rb[256];
    int n;
    struct l11_ip4 *ip = (struct l11_ip4 *)rb;
    struct sockaddr_in lo;
    RAW_OR_RETURN(s, AF_INET, IPPROTO_ICMP);
    l11_loopback(&lo);
    L_EQ(l11_ping4(s, 2), (int)(sizeof(struct l11_icmp) + 4));
    memset(rb, 0xcc, sizeof(rb));
    n = U(recv)(s, (char *)rb, sizeof(rb), 0);
    L_EQ(n, (int)(sizeof(struct l11_ip4) + sizeof(struct l11_icmp) + 4));
    if (n <= 0) { U(closesocket)(s); return; }
    L_EQ(ip->vhl, 0x45);
    L_EQ(l11_h16(ip->tot), sizeof(struct l11_ip4) + sizeof(struct l11_icmp) + 4);
    L_EQ(ip->frag, 0);
    L_EQ(ip->src, lo.sin_addr.s_addr);
    CHECK(ip->dst != 0);
    L_EQ(ip->proto, 1);
    U(closesocket)(s);
}

TEST(rawicmp4_echo_reply_icmp_fields_and_checksums)
{
    SOCKET s;
    BYTE rb[256];
    int n;
    struct l11_ip4 *ip = (struct l11_ip4 *)rb;
    struct l11_icmp *ic = (struct l11_icmp *)(ip + 1);
    UINT16 got, want;
    RAW_OR_RETURN(s, AF_INET, IPPROTO_ICMP);
    L_EQ(l11_ping4(s, 2), (int)(sizeof(struct l11_icmp) + 4));
    n = U(recv)(s, (char *)rb, sizeof(rb), 0);
    L_EQ(n, (int)(sizeof(struct l11_ip4) + sizeof(struct l11_icmp) + 4));
    if (n <= 0) { U(closesocket)(s); return; }
    L_EQ(ic->type, 0);       /* echo reply */
    L_EQ(ic->code, 0);
    L_EQ(ic->id, 0xbeaf);
    L_EQ(ic->seq, 2);
    L_EQ(*(unsigned *)(ic + 1), 0xdeadbeef);
    got = ic->sum; ic->sum = 0;
    want = l11_csum((BYTE *)ic, sizeof(*ic) + 4);
    L_EQ(got, want);
    /* Loopback replies carry a zero IP header checksum; accept a correct one as well. */
    got = ip->sum; ip->sum = 0;
    want = l11_csum((BYTE *)ip, sizeof(*ip));
    CHECKF(got == want || got == 0, "ip checksum %#x want %#x or 0", got, want);
    U(closesocket)(s);
}

TEST(rawicmp6_echo_reply_has_no_ip_header)
{
    SOCKET s;
    BYTE sb[sizeof(struct l11_icmp) + 4], rb[256], cb[256];
    struct sockaddr_in6 sa;
    struct l11_icmp *ic = (struct l11_icmp *)sb;
    struct l11_pseudo6 ps;
    UINT16 got, want;
    int n;
    RAW_OR_RETURN(s, AF_INET6, IPPROTO_ICMPV6);
    memset(&sa, 0, sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_addr.s6_addr[15] = 1;   /* ::1 */
    ic->type = 128; ic->code = 0; ic->sum = 0; ic->id = 0xbeaf; ic->seq = 2;
    *(unsigned *)(ic + 1) = 0xdeadbeef;
    n = U(sendto)(s, (char *)sb, sizeof(sb), 0, (struct sockaddr *)&sa, sizeof(sa));
    if (n < 0) { t_skip("IPv6 loopback ping not possible, error %d", l11_err()); U(closesocket)(s); return; }
    memset(rb, 0xcc, sizeof(rb));
    n = U(recv)(s, (char *)rb, sizeof(rb), 0);
    L_EQ(n, (int)sizeof(sb));
    if (n != (int)sizeof(sb)) { U(closesocket)(s); return; }
    ic = (struct l11_icmp *)rb;
    L_EQ(ic->type, 129);     /* echo reply */
    L_EQ(ic->code, 0);
    L_EQ(ic->id, 0xbeaf);
    L_EQ(ic->seq, 2);
    L_EQ(*(unsigned *)(ic + 1), 0xdeadbeef);
    /* The stack fills in the ICMPv6 checksum over the pseudo header (::1 -> ::1). */
    got = ic->sum; ic->sum = 0;
    memset(&ps, 0, sizeof(ps));
    ps.src[15] = 1; ps.dst[15] = 1;
    ps.len = l11_h32(sizeof(sb));
    ps.next = IPPROTO_ICMPV6;
    memcpy(cb, &ps, sizeof(ps));
    memcpy(cb + sizeof(ps), rb, sizeof(sb));
    want = l11_csum(cb, sizeof(ps) + sizeof(sb));
    L_EQ(got, want);
    U(closesocket)(s);
}
