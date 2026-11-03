/* WSAGetServiceClassNameByClassId{A,W} reached through the lookup-independent paths.
 * Measures: that the calls need WSAStartup (WSANOTINITIALISED, return SOCKET_ERROR) and that both forms are
 * exported by ws2_32. A call with a started Winsock walks the registered namespace providers, whose handling
 * of unregistered classes is not exercised here. */
#include "lns.h"

static const GUID k_class = { 0x3f2a6b11, 0x1234, 0x4abc, { 0x9d, 0x01, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 } };

TEST(svcclass_a_before_startup_not_initialised)
{
    char buf[64]; DWORD len = sizeof buf; GUID g = k_class;
    REQUIRE(U(WSAGetServiceClassNameByClassIdA)); REQUIRE(U(WSACleanup)); REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError));
    lns_force_down();
    LNS_SETERR(0);
    EXPECT_EQ(U(WSAGetServiceClassNameByClassIdA)(&g, buf, &len), SOCKET_ERROR);
    EXPECT_EQ(LNS_ERR(), LNS_E_NOTINIT);
}
TEST(svcclass_w_before_startup_not_initialised)
{
    WCHAR buf[64]; DWORD len = sizeof buf; GUID g = k_class;
    REQUIRE(U(WSAGetServiceClassNameByClassIdW)); REQUIRE(U(WSACleanup)); REQUIRE(U(WSAGetLastError)); REQUIRE(U(WSASetLastError));
    lns_force_down();
    LNS_SETERR(0);
    EXPECT_EQ(U(WSAGetServiceClassNameByClassIdW)(&g, buf, &len), SOCKET_ERROR);
    EXPECT_EQ(LNS_ERR(), LNS_E_NOTINIT);
}
TEST(svcclass_a_after_cleanup_not_initialised)
{
    char buf[64]; DWORD len = sizeof buf; GUID g = k_class;
    LNS_NEED(WSAGetServiceClassNameByClassIdA);
    LNS_DONE();
    lns_force_down();
    LNS_SETERR(0);
    EXPECT_EQ(U(WSAGetServiceClassNameByClassIdA)(&g, buf, &len), SOCKET_ERROR);
    EXPECT_EQ(LNS_ERR(), LNS_E_NOTINIT);
}
TEST(svcclass_w_after_cleanup_not_initialised)
{
    WCHAR buf[64]; DWORD len = sizeof buf; GUID g = k_class;
    LNS_NEED(WSAGetServiceClassNameByClassIdW);
    LNS_DONE();
    lns_force_down();
    LNS_SETERR(0);
    EXPECT_EQ(U(WSAGetServiceClassNameByClassIdW)(&g, buf, &len), SOCKET_ERROR);
    EXPECT_EQ(LNS_ERR(), LNS_E_NOTINIT);
}
TEST(svcclass_both_forms_exported)
{
    CHECK(t_proc_in("ws2_32.dll", "WSAGetServiceClassNameByClassIdA") != NULL);
    CHECK(t_proc_in("ws2_32.dll", "WSAGetServiceClassNameByClassIdW") != NULL);
    CHECK(t_proc_in("ws2_32.dll", "WSAGetServiceClassNameByClassIdA") != t_proc_in("ws2_32.dll", "WSAGetServiceClassNameByClassIdW"));
}
TEST(svcclass_not_in_wsock32)
{
    REQUIRE(t_proc_in("ws2_32.dll", "WSAGetServiceClassNameByClassIdA"));
    CHECK(t_proc_in("wsock32.dll", "WSAGetServiceClassNameByClassIdA") == NULL);
    CHECK(t_proc_in("wsock32.dll", "WSAGetServiceClassNameByClassIdW") == NULL);
}
