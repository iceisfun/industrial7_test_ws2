/* Namespace-provider enumeration (WSAEnumNameSpaceProviders A/W), WSCGetApplicationCategory,
 * WSCGetProviderInfo and WSCGetProviderPath: size-query protocol and parameter validation. */
#include "lift03.h"

#define NEED_P() do { if (l3_up()) { t_skip("WSAStartup failed"); return; } } while (0)

/* ---- WSAEnumNameSpaceProviders ---------------------------------------------------------------------- */
TEST(nsenum_a_zero_length_probe_fails_efault)
{
    REQUIRE(U(WSAEnumNameSpaceProvidersA));
    NEED_P();
    DWORD len = 0;
    SETWSERR(0x1234);
    EXPECT_EQ(U(WSAEnumNameSpaceProvidersA)(&len, NULL), SOCKET_ERROR);
    EXPECT_EQ(WSERR(), WSAEFAULT);
    CHECK(len > 0); /* required size is reported */
    l3_down();
}

TEST(nsenum_a_full_buffer_returns_providers)
{
    REQUIRE(U(WSAEnumNameSpaceProvidersA));
    NEED_P();
    DWORD len = 0;
    U(WSAEnumNameSpaceProvidersA)(&len, NULL);
    LPWSANAMESPACE_INFOA buf = len ? (LPWSANAMESPACE_INFOA)HeapAlloc(GetProcessHeap(), 0, len) : NULL;
    CHECK(buf != NULL);
    if (buf) {
        int n = U(WSAEnumNameSpaceProvidersA)(&len, buf);
        CHECK(n > 0);
        HeapFree(GetProcessHeap(), 0, buf);
    }
    l3_down();
}

TEST(nsenum_w_zero_length_probe_fails_efault)
{
    REQUIRE(U(WSAEnumNameSpaceProvidersW));
    NEED_P();
    DWORD len = 0;
    SETWSERR(0x1234);
    EXPECT_EQ(U(WSAEnumNameSpaceProvidersW)(&len, NULL), SOCKET_ERROR);
    EXPECT_EQ(WSERR(), WSAEFAULT);
    CHECK(len > 0);
    l3_down();
}

TEST(nsenum_w_full_buffer_returns_providers)
{
    REQUIRE(U(WSAEnumNameSpaceProvidersW));
    NEED_P();
    DWORD len = 0;
    U(WSAEnumNameSpaceProvidersW)(&len, NULL);
    LPWSANAMESPACE_INFOW buf = len ? (LPWSANAMESPACE_INFOW)HeapAlloc(GetProcessHeap(), 0, len) : NULL;
    CHECK(buf != NULL);
    if (buf) {
        int n = U(WSAEnumNameSpaceProvidersW)(&len, buf);
        CHECK(n > 0);
        /* the DNS provider is always present; list what the catalogue holds as notes */
        int dns = 0;
        for (int i = 0; i < n; i++) if (buf[i].dwNameSpace == NS_DNS) dns++;
        t_note("namespace catalogue has a DNS entry: %s", dns ? "yes" : "no");
        HeapFree(GetProcessHeap(), 0, buf);
    }
    l3_down();
}

/* ---- WSCGetApplicationCategory --------------------------------------------------------------------- */
TEST(appcat_all_null_is_einval)
{
    REQUIRE(UN(WSCGetApplicationCategory));
    NEED_P();
    int err = 0x1234;
    EXPECT_EQ(UN(WSCGetApplicationCategory)(NULL, 0, NULL, 0, NULL, &err), SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVAL);
    l3_down();
}

TEST(appcat_empty_path_no_out_is_einval)
{
    REQUIRE(UN(WSCGetApplicationCategory));
    NEED_P();
    int err = 0x1234;
    EXPECT_EQ(UN(WSCGetApplicationCategory)(L"", 0, NULL, 0, NULL, &err), SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVAL);
    l3_down();
}

TEST(appcat_empty_path_empty_extra_no_out_is_einval)
{
    REQUIRE(UN(WSCGetApplicationCategory));
    NEED_P();
    int err = 0x1234;
    EXPECT_EQ(UN(WSCGetApplicationCategory)(L"", 0, L"", 0, NULL, &err), SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVAL);
    l3_down();
}

TEST(appcat_empty_path_with_out_is_einval)
{
    REQUIRE(UN(WSCGetApplicationCategory));
    NEED_P();
    int err = 0x1234;
    DWORD cat = 0;
    EXPECT_EQ(UN(WSCGetApplicationCategory)(L"", 0, NULL, 0, &cat, &err), SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVAL);
    l3_down();
}

TEST(appcat_empty_path_empty_extra_with_out_is_einval)
{
    REQUIRE(UN(WSCGetApplicationCategory));
    NEED_P();
    int err = 0x1234;
    DWORD cat = 0;
    EXPECT_EQ(UN(WSCGetApplicationCategory)(L"", 0, L"", 0, &cat, &err), SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVAL);
    l3_down();
}

/* The provider-path, provider-info and namespace-enumeration entry points dereference their required
 * pointer arguments without checking them: a NULL there raises an access violation instead of an error
 * code, so those cases are not testable and are not exercised here. */
/* ---- WSCGetProviderInfo ---------------------------------------------------------------------------- */
TEST(provinfo_bad_info_type_is_norecovery)
{
    REQUIRE(UN(WSCGetProviderInfo));
    NEED_P();
    GUID g = {0};
    BYTE info[1];
    size_t len = 0;
    int err = 0x1234;
    EXPECT_EQ(UN(WSCGetProviderInfo)(&g, -1, info, &len, 0, &err), SOCKET_ERROR);
    EXPECT_EQ(err, WSANO_RECOVERY);
    l3_down();
}

TEST(provinfo_null_info_buffer_is_norecovery)
{
    REQUIRE(UN(WSCGetProviderInfo));
    NEED_P();
    GUID g = {0};
    size_t len = 0;
    int err = 0x1234;
    EXPECT_EQ(UN(WSCGetProviderInfo)(&g, 0, NULL, &len, 0, &err), SOCKET_ERROR);
    EXPECT_EQ(err, WSANO_RECOVERY);
    l3_down();
}

TEST(provinfo_null_size_is_norecovery)
{
    REQUIRE(UN(WSCGetProviderInfo));
    NEED_P();
    GUID g = {0};
    BYTE info[1];
    int err = 0x1234;
    EXPECT_EQ(UN(WSCGetProviderInfo)(&g, 0, info, NULL, 0, &err), SOCKET_ERROR);
    EXPECT_EQ(err, WSANO_RECOVERY);
    l3_down();
}

TEST(provinfo_unknown_guid_is_norecovery)
{
    REQUIRE(UN(WSCGetProviderInfo));
    NEED_P();
    GUID g = {0};
    BYTE info[1];
    size_t len = 0;
    int err = 0x1234;
    EXPECT_EQ(UN(WSCGetProviderInfo)(&g, 0, info, &len, 0, &err), SOCKET_ERROR);
    EXPECT_EQ(err, WSANO_RECOVERY);
    l3_down();
}

/* ---- WSCGetProviderPath ---------------------------------------------------------------------------- */
TEST(provpath_negative_length_errno_is_einval)
{
    REQUIRE(UN(WSCGetProviderPath));
    NEED_P();
    GUID g = {0};
    INT err = 0, len = -1;
    EXPECT_EQ(UN(WSCGetProviderPath)(&g, NULL, &len, &err), SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVAL);
    EXPECT_EQ(len, -1);
    l3_down();
}

/* An all-zero GUID names no provider: fails with WSAEINVAL and the length is left alone, with or without
 * an output buffer. */
TEST(provpath_zero_guid_no_buffer_is_einval)
{
    REQUIRE(UN(WSCGetProviderPath));
    NEED_P();
    GUID g = {0};
    INT err = 0, len = 256;
    EXPECT_EQ(UN(WSCGetProviderPath)(&g, NULL, &len, &err), SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVAL);
    EXPECT_EQ(len, 256);
    l3_down();
}

TEST(provpath_zero_guid_with_buffer_is_einval)
{
    REQUIRE(UN(WSCGetProviderPath));
    NEED_P();
    GUID g = {0};
    WCHAR buf[256];
    INT err = 0, len = 256;
    EXPECT_EQ(UN(WSCGetProviderPath)(&g, buf, &len, &err), SOCKET_ERROR);
    EXPECT_EQ(err, WSAEINVAL);
    EXPECT_EQ(len, 256);
    l3_down();
}
