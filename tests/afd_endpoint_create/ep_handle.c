/* Properties of a freshly opened AFD endpoint handle.
 *
 * Measures what the I/O manager and the object manager report for a handle made by the open-packet
 * protocol: object type, granted access, handle attributes, synchronous versus overlapped mode,
 * file type as seen by kernel32, device type, duplication and close. The status of operations the
 * driver itself answers (information classes it handles) is recorded as notes. */
#include "aec.h"

typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; WCHAR text[64]; } objname_t;

#define SYNC_OPT 0x20u
#define GENERIC_RW_DAC 0xC0140000u
/* what a generic read+write+write_dac request maps to on a file object */
#define MAPPED_RW_DAC (FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC)

static HANDLE open_with(const ep_t *e) { return ep_ok(e); }

/* ---- object manager view -------------------------------------------------------------- */
TEST(aech_object_type_is_file)
{
    ep_t e; HANDLE h; objname_t t; ULONG rl = 0; NEED(); ep_tcp4(&e);
    h = open_with(&e); if (!h) return;
    memset(&t, 0, sizeof(t));
    EXPECT_NT(N.NtQueryObject(h, 2, &t, sizeof(t), &rl), ST_SUCCESS);
    CHECK(t.Length == 8 && t.Buffer && !wcsncmp(t.Buffer, L"File", 4));
    N.NtClose(h);
}
TEST(aech_object_type_is_file_for_control_handle)
{
    ep_t e; HANDLE h; objname_t t; NEED(); ep_tcp4(&e); e.no_ea = 1;
    h = open_with(&e); if (!h) return;
    memset(&t, 0, sizeof(t));
    EXPECT_NT(N.NtQueryObject(h, 2, &t, sizeof(t), NULL), ST_SUCCESS);
    CHECK(t.Length == 8 && t.Buffer && !wcsncmp(t.Buffer, L"File", 4));
    N.NtClose(h);
}
TEST(aech_granted_access_generic_rw_dac)
{
    ep_t e; HANDLE h; objbasic_t b; NEED(); ep_tcp4(&e); e.access = GENERIC_RW_DAC;
    h = open_with(&e); if (!h) return;
    memset(&b, 0, sizeof(b));
    EXPECT_NT(N.NtQueryObject(h, 0, &b, sizeof(b), NULL), ST_SUCCESS);
    EXPECT_EQ(b.GrantedAccess, MAPPED_RW_DAC);
    N.NtClose(h);
}
TEST(aech_granted_access_matches_udp)
{
    ep_t e; HANDLE h; objbasic_t b; NEED(); ep_udp4(&e);
    h = open_with(&e); if (!h) return;
    memset(&b, 0, sizeof(b));
    EXPECT_NT(N.NtQueryObject(h, 0, &b, sizeof(b), NULL), ST_SUCCESS);
    EXPECT_EQ(b.GrantedAccess, MAPPED_RW_DAC);
    N.NtClose(h);
}
TEST(aech_granted_access_matches_raw)
{
    ep_t e; HANDLE h; objbasic_t b; NEED(); ep_raw4(&e, 1);
    h = open_with(&e); if (!h) return;
    memset(&b, 0, sizeof(b));
    EXPECT_NT(N.NtQueryObject(h, 0, &b, sizeof(b), NULL), ST_SUCCESS);
    EXPECT_EQ(b.GrantedAccess, MAPPED_RW_DAC);
    N.NtClose(h);
}
#define ACCESS_CONTAINS(tname, acc) TEST(tname) { ep_t e; HANDLE h; objbasic_t b; NEED(); ep_tcp4(&e); e.access = (acc); \
    h = open_with(&e); if (!h) return; memset(&b, 0, sizeof(b)); \
    EXPECT_NT(N.NtQueryObject(h, 0, &b, sizeof(b), NULL), ST_SUCCESS); \
    EXPECT_EQ(b.GrantedAccess & (acc), (acc)); N.NtClose(h); }
ACCESS_CONTAINS(aech_granted_contains_synchronize, SYNCHRONIZE)
ACCESS_CONTAINS(aech_granted_contains_write_dac_sync, WRITE_DAC | SYNCHRONIZE)
ACCESS_CONTAINS(aech_granted_contains_read_control_sync, READ_CONTROL | SYNCHRONIZE)
ACCESS_CONTAINS(aech_granted_contains_file_read_data_sync, FILE_READ_DATA | SYNCHRONIZE)
ACCESS_CONTAINS(aech_granted_contains_file_write_data_sync, FILE_WRITE_DATA | SYNCHRONIZE)
ACCESS_CONTAINS(aech_granted_contains_file_all_data_bits_sync, FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | SYNCHRONIZE)
TEST(aech_granted_access_mapped_from_generic_read_only)
{
    ep_t e; HANDLE h; objbasic_t b; NEED(); ep_tcp4(&e); e.access = GENERIC_READ | SYNCHRONIZE;
    h = open_with(&e); if (!h) return;
    memset(&b, 0, sizeof(b));
    EXPECT_NT(N.NtQueryObject(h, 0, &b, sizeof(b), NULL), ST_SUCCESS);
    EXPECT_EQ(b.GrantedAccess & FILE_GENERIC_READ, FILE_GENERIC_READ);
    EXPECT_EQ(b.GrantedAccess & GENERIC_READ, 0);
    N.NtClose(h);
}
TEST(aech_granted_access_never_contains_generic_bits)
{
    ep_t e; HANDLE h; objbasic_t b; NEED(); ep_tcp4(&e); e.access = GENERIC_RW_DAC;
    h = open_with(&e); if (!h) return;
    memset(&b, 0, sizeof(b));
    EXPECT_NT(N.NtQueryObject(h, 0, &b, sizeof(b), NULL), ST_SUCCESS);
    EXPECT_EQ(b.GrantedAccess & (GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL), 0);
    N.NtClose(h);
}
TEST(aech_attributes_inherit_requested)
{
    ep_t e; HANDLE h; objbasic_t b; NEED(); ep_tcp4(&e); e.attrs = OBJ_CASE_INSENSITIVE | OBJ_INHERIT;
    h = open_with(&e); if (!h) return;
    memset(&b, 0, sizeof(b));
    EXPECT_NT(N.NtQueryObject(h, 0, &b, sizeof(b), NULL), ST_SUCCESS);
    EXPECT_EQ(b.Attributes & OBJ_INHERIT, OBJ_INHERIT);
    N.NtClose(h);
}
TEST(aech_attributes_inherit_not_requested)
{
    ep_t e; HANDLE h; objbasic_t b; NEED(); ep_tcp4(&e); e.attrs = OBJ_CASE_INSENSITIVE;
    h = open_with(&e); if (!h) return;
    memset(&b, 0, sizeof(b));
    EXPECT_NT(N.NtQueryObject(h, 0, &b, sizeof(b), NULL), ST_SUCCESS);
    EXPECT_EQ(b.Attributes & OBJ_INHERIT, 0);
    N.NtClose(h);
}
TEST(aech_win32_inherit_flag_follows_attribute)
{
    ep_t e; HANDLE a, b; DWORD fa = 0, fb = 0; NEED();
    ep_tcp4(&e); e.attrs = OBJ_CASE_INSENSITIVE | OBJ_INHERIT; a = open_with(&e);
    ep_tcp4(&e); e.attrs = OBJ_CASE_INSENSITIVE; b = open_with(&e);
    if (a && b) {
        CHECK(GetHandleInformation(a, &fa)); CHECK(GetHandleInformation(b, &fb));
        EXPECT_EQ(fa & HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        EXPECT_EQ(fb & HANDLE_FLAG_INHERIT, 0);
    }
    if (a) N.NtClose(a);
    if (b) N.NtClose(b);
}
TEST(aech_query_basic_length_zero_mismatch)
{
    ep_t e; HANDLE h; ULONG rl = 0; NEED(); ep_tcp4(&e);
    h = open_with(&e); if (!h) return;
    EXPECT_NT(N.NtQueryObject(h, 0, NULL, 0, &rl), ST_INFO_LENGTH_MISMATCH);
    N.NtClose(h);
}
TEST(aech_query_basic_larger_buffer_mismatch)
{
    /* the basic-information class wants exactly 0x38 bytes: a bigger buffer is a mismatch too */
    ep_t e; HANDLE h; unsigned char b[0x50]; NEED(); ep_tcp4(&e);
    h = open_with(&e); if (!h) return;
    EXPECT_NT(N.NtQueryObject(h, 0, b, 0x40, NULL), ST_INFO_LENGTH_MISMATCH);
    EXPECT_NT(N.NtQueryObject(h, 0, b, 0x50, NULL), ST_INFO_LENGTH_MISMATCH);
    EXPECT_NT(N.NtQueryObject(h, 0, b, 0x37, NULL), ST_INFO_LENGTH_MISMATCH);
    EXPECT_NT(N.NtQueryObject(h, 0, b, 0x38, NULL), ST_SUCCESS);
    N.NtClose(h);
}
TEST(aech_query_basic_returns_required_size)
{
    ep_t e; HANDLE h; ULONG rl = 0; unsigned char b[4]; NEED(); ep_tcp4(&e);
    h = open_with(&e); if (!h) return;
    EXPECT_NT(N.NtQueryObject(h, 0, b, sizeof(b), &rl), ST_INFO_LENGTH_MISMATCH);
    t_note("basic-information too-small call reports required size %s", rl == 0x38 ? "0x38" : "other");
    N.NtClose(h);
}

/* ---- I/O manager view: mode, access, file type, device type -------------------------- */
static ULONG file_mode(HANDLE h, LONG *st)
{
    IO_STATUS_BLOCK io; ULONG m = 0xDEAD;
    *st = N.NtQueryInformationFile(h, &io, &m, sizeof(m), FileModeInformation_);
    return m;
}
TEST(aech_mode_overlapped_open_has_no_sync_bits)
{
    ep_t e; HANDLE h; LONG st; ULONG m; NEED(); ep_tcp4(&e); e.options = 0;
    h = open_with(&e); if (!h) return;
    m = file_mode(h, &st);
    EXPECT_NT(st, ST_SUCCESS);
    EXPECT_EQ(m, 0);
    N.NtClose(h);
}
TEST(aech_mode_sync_nonalert_open)
{
    ep_t e; HANDLE h; LONG st; ULONG m; NEED(); ep_tcp4(&e); e.options = SYNC_OPT;
    h = open_with(&e); if (!h) return;
    m = file_mode(h, &st);
    EXPECT_NT(st, ST_SUCCESS);
    EXPECT_EQ(m, FILE_SYNCHRONOUS_IO_NONALERT);
    N.NtClose(h);
}
TEST(aech_mode_sync_alert_open)
{
    ep_t e; HANDLE h; LONG st; ULONG m; NEED(); ep_tcp4(&e); e.options = FILE_SYNCHRONOUS_IO_ALERT;
    h = open_with(&e); if (!h) return;
    m = file_mode(h, &st);
    EXPECT_NT(st, ST_SUCCESS);
    EXPECT_EQ(m, FILE_SYNCHRONOUS_IO_ALERT);
    N.NtClose(h);
}
TEST(aech_mode_udp_sync)
{
    ep_t e; HANDLE h; LONG st; ULONG m; NEED(); ep_udp4(&e); e.options = SYNC_OPT;
    h = open_with(&e); if (!h) return;
    m = file_mode(h, &st);
    EXPECT_NT(st, ST_SUCCESS); EXPECT_EQ(m, FILE_SYNCHRONOUS_IO_NONALERT);
    N.NtClose(h);
}
TEST(aech_mode_raw_overlapped)
{
    ep_t e; HANDLE h; LONG st; ULONG m; NEED(); ep_raw4(&e, 1);
    h = open_with(&e); if (!h) return;
    m = file_mode(h, &st);
    EXPECT_NT(st, ST_SUCCESS); EXPECT_EQ(m, 0);
    N.NtClose(h);
}
TEST(aech_mode_tcp6_sync)
{
    ep_t e; HANDLE h; LONG st; ULONG m; NEED(); ep_tcp6(&e); e.options = SYNC_OPT;
    h = open_with(&e); if (!h) return;
    m = file_mode(h, &st);
    EXPECT_NT(st, ST_SUCCESS); EXPECT_EQ(m, FILE_SYNCHRONOUS_IO_NONALERT);
    N.NtClose(h);
}
TEST(aech_mode_control_handle_overlapped)
{
    ep_t e; HANDLE h; LONG st; ULONG m; NEED(); ep_tcp4(&e); e.no_ea = 1;
    h = open_with(&e); if (!h) return;
    m = file_mode(h, &st);
    EXPECT_NT(st, ST_SUCCESS); EXPECT_EQ(m, 0);
    N.NtClose(h);
}
TEST(aech_mode_control_handle_sync)
{
    ep_t e; HANDLE h; LONG st; ULONG m; NEED(); ep_tcp4(&e); e.no_ea = 1; e.options = SYNC_OPT;
    h = open_with(&e); if (!h) return;
    m = file_mode(h, &st);
    EXPECT_NT(st, ST_SUCCESS); EXPECT_EQ(m, FILE_SYNCHRONOUS_IO_NONALERT);
    N.NtClose(h);
}
TEST(aech_mode_not_changed_by_noncompatible_create_options)
{
    /* options that mean nothing to a device are not reflected in the mode */
    ep_t e; HANDLE h; LONG st; ULONG m; NEED(); ep_tcp4(&e); e.options = FILE_NO_INTERMEDIATE_BUFFERING | SYNC_OPT;
    h = open_with(&e); if (!h) return;
    m = file_mode(h, &st);
    EXPECT_NT(st, ST_SUCCESS);
    EXPECT_EQ(m & FILE_SYNCHRONOUS_IO_NONALERT, FILE_SYNCHRONOUS_IO_NONALERT);
    N.NtClose(h);
}
TEST(aech_access_information_equals_granted_access)
{
    ep_t e; HANDLE h; IO_STATUS_BLOCK io; ULONG acc = 0xDEAD; objbasic_t b; NEED(); ep_tcp4(&e);
    h = open_with(&e); if (!h) return;
    EXPECT_NT(N.NtQueryInformationFile(h, &io, &acc, sizeof(acc), FileAccessInformation_), ST_SUCCESS);
    memset(&b, 0, sizeof(b));
    EXPECT_NT(N.NtQueryObject(h, 0, &b, sizeof(b), NULL), ST_SUCCESS);
    EXPECT_EQ(acc, b.GrantedAccess);
    N.NtClose(h);
}
TEST(aech_access_information_length_mismatch)
{
    ep_t e; HANDLE h; IO_STATUS_BLOCK io; ULONG acc = 0; NEED(); ep_tcp4(&e);
    h = open_with(&e); if (!h) return;
    EXPECT_NT(N.NtQueryInformationFile(h, &io, &acc, 2, FileAccessInformation_), ST_INFO_LENGTH_MISMATCH);
    N.NtClose(h);
}
TEST(aech_mode_information_length_mismatch)
{
    ep_t e; HANDLE h; IO_STATUS_BLOCK io; ULONG m = 0; NEED(); ep_tcp4(&e);
    h = open_with(&e); if (!h) return;
    EXPECT_NT(N.NtQueryInformationFile(h, &io, &m, 3, FileModeInformation_), ST_INFO_LENGTH_MISMATCH);
    N.NtClose(h);
}
TEST(aech_file_type_is_pipe)
{
    /* kernel32 classifies network-device files like pipes; sockets are known for this */
    ep_t e; HANDLE h; NEED(); ep_tcp4(&e);
    h = open_with(&e); if (!h) return;
    EXPECT_EQ(GetFileType(h), FILE_TYPE_PIPE);
    N.NtClose(h);
}
TEST(aech_file_type_is_pipe_for_control_handle)
{
    ep_t e; HANDLE h; NEED(); ep_tcp4(&e); e.no_ea = 1;
    h = open_with(&e); if (!h) return;
    EXPECT_EQ(GetFileType(h), FILE_TYPE_PIPE);
    N.NtClose(h);
}
TEST(aech_file_type_is_pipe_for_udp_sync)
{
    ep_t e; HANDLE h; NEED(); ep_udp4(&e); e.options = SYNC_OPT;
    h = open_with(&e); if (!h) return;
    EXPECT_EQ(GetFileType(h), FILE_TYPE_PIPE);
    N.NtClose(h);
}
typedef struct { ULONG DeviceType, Characteristics; } fsdev_t;
TEST(aech_device_type_is_named_pipe_class)
{
    ep_t e; HANDLE h; IO_STATUS_BLOCK io; fsdev_t d; NEED(); ep_tcp4(&e);
    h = open_with(&e); if (!h) return;
    memset(&d, 0, sizeof(d));
    EXPECT_NT(N.NtQueryVolumeInformationFile(h, &io, &d, sizeof(d), FSDEVICE_INFO), ST_SUCCESS);
    EXPECT_EQ(d.DeviceType, 0x11);       /* FILE_DEVICE_NAMED_PIPE: the endpoint device is created with the pipe device type */
    EXPECT_EQ(io.Information, sizeof(d));
    N.NtClose(h);
}
TEST(aech_device_type_same_for_control_handle)
{
    ep_t e; HANDLE h; IO_STATUS_BLOCK io; fsdev_t d; NEED(); ep_tcp4(&e); e.no_ea = 1;
    h = open_with(&e); if (!h) return;
    memset(&d, 0, sizeof(d));
    EXPECT_NT(N.NtQueryVolumeInformationFile(h, &io, &d, sizeof(d), FSDEVICE_INFO), ST_SUCCESS);
    EXPECT_EQ(d.DeviceType, 0x11);
    N.NtClose(h);
}
TEST(aech_device_info_length_mismatch)
{
    ep_t e; HANDLE h; IO_STATUS_BLOCK io; ULONG d = 0; NEED(); ep_tcp4(&e);
    h = open_with(&e); if (!h) return;
    EXPECT_NT(N.NtQueryVolumeInformationFile(h, &io, &d, 4, FSDEVICE_INFO), ST_INFO_LENGTH_MISMATCH);
    N.NtClose(h);
}

/* ---- information classes the driver answers: recorded, not asserted -------------------- */
#define NOTE_CLASS(tname, cls, label) TEST(tname) { ep_t e; HANDLE h; IO_STATUS_BLOCK io; unsigned char buf[128]; LONG st; \
    NEED(); ep_tcp4(&e); h = open_with(&e); if (!h) return; memset(buf, 0, sizeof(buf)); \
    st = N.NtQueryInformationFile(h, &io, buf, sizeof(buf), cls); \
    t_note("endpoint " label " -> %s", st_name(st)); N.NtClose(h); }
NOTE_CLASS(aech_note_query_basic, FileBasicInformation_, "FileBasicInformation")
NOTE_CLASS(aech_note_query_standard, FileStandardInformation_, "FileStandardInformation")
NOTE_CLASS(aech_note_query_internal, FileInternalInformation_, "FileInternalInformation")
NOTE_CLASS(aech_note_query_ea, FileEaInformation_, "FileEaInformation")
NOTE_CLASS(aech_note_query_name, FileNameInformation_, "FileNameInformation")
NOTE_CLASS(aech_note_query_position, FilePositionInformation_, "FilePositionInformation")
NOTE_CLASS(aech_note_query_alignment, FileAlignmentInformation_, "FileAlignmentInformation")
NOTE_CLASS(aech_note_query_all, FileAllInformation_, "FileAllInformation")
NOTE_CLASS(aech_note_query_network_open, FileNetworkOpenInformation_, "FileNetworkOpenInformation")
NOTE_CLASS(aech_note_query_attribute_tag, FileAttributeTagInformation_, "FileAttributeTagInformation")
TEST(aech_open_information_field_is_zero)
{
    ep_t e; HANDLE h; IO_STATUS_BLOCK io; LONG st; NEED(); ep_tcp4(&e);
    st = ep_open(&e, &h, &io);
    EXPECT_NT(st, ST_SUCCESS);
    /* a device open reports Information 0 (FILE_SUPERSEDED), not FILE_OPENED, whatever the disposition says */
    EXPECT_EQ(io.Information, FILE_SUPERSEDED);
    if (h) N.NtClose(h);
}
TEST(aech_object_name_is_the_device_name)
{
    /* the leaf of the open path is not part of the name the handle reports */
    ep_t e; HANDLE h; objname_t n; ULONG rl = 0; NEED(); ep_tcp4(&e);
    h = open_with(&e); if (!h) return;
    memset(&n, 0, sizeof(n));
    EXPECT_NT(N.NtQueryObject(h, 1, &n, sizeof(n), &rl), ST_SUCCESS);
    CHECK(n.Length == 22 && n.Buffer && !wcsncmp(n.Buffer, L"\\Device\\Afd", 11));
    N.NtClose(h);
}
TEST(aech_object_name_same_for_other_leaf)
{
    ep_t e; HANDLE h; objname_t n; ULONG rl = 0; NEED(); ep_tcp4(&e); e.path = L"\\Device\\Afd\\SomethingElse";
    h = open_with(&e); if (!h) return;
    memset(&n, 0, sizeof(n));
    EXPECT_NT(N.NtQueryObject(h, 1, &n, sizeof(n), &rl), ST_SUCCESS);
    CHECK(n.Length == 22 && n.Buffer && !wcsncmp(n.Buffer, L"\\Device\\Afd", 11));
    N.NtClose(h);
}

/* ---- duplication and close --------------------------------------------------------------- */
TEST(aech_close_twice_invalid_handle)
{
    ep_t e; HANDLE h; NEED(); ep_tcp4(&e);
    h = open_with(&e); if (!h) return;
    EXPECT_NT(N.NtClose(h), ST_SUCCESS);
    EXPECT_NT(N.NtClose(h), ST_INVALID_HANDLE);
}
TEST(aech_query_after_close_invalid_handle)
{
    ep_t e; HANDLE h; IO_STATUS_BLOCK io; ULONG m; NEED(); ep_tcp4(&e);
    h = open_with(&e); if (!h) return;
    N.NtClose(h);
    EXPECT_NT(N.NtQueryInformationFile(h, &io, &m, sizeof(m), FileModeInformation_), ST_INVALID_HANDLE);
}
TEST(aech_duplicate_same_access_keeps_endpoint_alive)
{
    ep_t e; HANDLE h, d = NULL; LONG st; ULONG m; NEED(); ep_tcp4(&e); e.options = SYNC_OPT;
    h = open_with(&e); if (!h) return;
    EXPECT_NT(N.NtDuplicateObject((HANDLE)-1, h, (HANDLE)-1, &d, 0, 0, 2 /* DUPLICATE_SAME_ACCESS */), ST_SUCCESS);
    CHECK(d != NULL && d != h);
    EXPECT_NT(N.NtClose(h), ST_SUCCESS);
    if (d) {
        m = file_mode(d, &st);
        EXPECT_NT(st, ST_SUCCESS);
        EXPECT_EQ(m, FILE_SYNCHRONOUS_IO_NONALERT);
        EXPECT_NT(N.NtClose(d), ST_SUCCESS);
    }
}
TEST(aech_duplicate_close_source_object_basic_still_works)
{
    ep_t e; HANDLE h, d = NULL; objbasic_t b; NEED(); ep_tcp4(&e);
    h = open_with(&e); if (!h) return;
    EXPECT_NT(N.NtDuplicateObject((HANDLE)-1, h, (HANDLE)-1, &d, 0, 0, 2), ST_SUCCESS);
    N.NtClose(h);
    if (d) {
        memset(&b, 0, sizeof(b));
        EXPECT_NT(N.NtQueryObject(d, 0, &b, sizeof(b), NULL), ST_SUCCESS);
        EXPECT_EQ(b.GrantedAccess, MAPPED_RW_DAC);
        N.NtClose(d);
    }
}
TEST(aech_duplicate_reduced_access)
{
    ep_t e; HANDLE h, d = NULL; objbasic_t b; NEED(); ep_tcp4(&e);
    h = open_with(&e); if (!h) return;
    EXPECT_NT(N.NtDuplicateObject((HANDLE)-1, h, (HANDLE)-1, &d, SYNCHRONIZE, 0, 0), ST_SUCCESS);
    if (d) {
        memset(&b, 0, sizeof(b));
        EXPECT_NT(N.NtQueryObject(d, 0, &b, sizeof(b), NULL), ST_SUCCESS);
        EXPECT_EQ(b.GrantedAccess, SYNCHRONIZE);
        N.NtClose(d);
    }
    N.NtClose(h);
}
TEST(aech_duplicate_win32_both_handles_independent_values)
{
    ep_t e; HANDLE h, d = NULL; NEED(); ep_tcp4(&e);
    h = open_with(&e); if (!h) return;
    CHECK(DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &d, 0, FALSE, DUPLICATE_SAME_ACCESS));
    CHECK(d != NULL && d != h);
    CHECK(CloseHandle(h));
    if (d) CHECK(CloseHandle(d));
}
TEST(aech_win32_close_handle_works)
{
    ep_t e; HANDLE h; NEED(); ep_tcp4(&e);
    h = open_with(&e); if (!h) return;
    CHECK(CloseHandle(h));
    SetLastError(0);
    CHECK(!CloseHandle(h)); EXPECT_ERR(ERROR_INVALID_HANDLE);
}
TEST(aech_cross_process_inherit_reaches_child)
{
    /* an inheritable endpoint handle is visible by value in a child that is told its value */
    ep_t e; HANDLE h; char arg[32]; DWORD rc; NEED(); ep_tcp4(&e); e.attrs = OBJ_CASE_INSENSITIVE | OBJ_INHERIT;
    h = open_with(&e); if (!h) return;
    snprintf(arg, sizeof(arg), "%llu", (unsigned long long)(ULONG_PTR)h);
    {
        PROCESS_INFORMATION pi; HANDLE p = t_spawn_child("aech_inherit_probe", arg, 0, NULL, NULL, NULL, TRUE, NULL, &pi);
        if (!p) { t_skip("cannot spawn child"); N.NtClose(h); return; }
        if (WaitForSingleObject(p, 20000) != WAIT_OBJECT_0) { TerminateProcess(p, 99); rc = 99; }
        else GetExitCodeProcess(p, &rc);
        CloseHandle(pi.hThread); CloseHandle(p);
    }
    EXPECT_EQ(rc, 0);
    N.NtClose(h);
}
CHILD(aech_inherit_probe)
{
    HANDLE h; IO_STATUS_BLOCK io; ULONG m = 0; LONG st;
    if (argc < 2 || !aec_ready()) return 2;
    h = (HANDLE)(ULONG_PTR)strtoull(argv[1], NULL, 10);
    st = N.NtQueryInformationFile(h, &io, &m, sizeof(m), FileModeInformation_);
    return st == 0 ? 0 : 1;
}
/* ---- create-option and parameter checks owned by the I/O manager ------------------------- */
/* Synchronous opens need SYNCHRONIZE access and exactly one synchronous option. */
TEST(aech_both_sync_options_rejected)
{
    ep_t e; NEED(); ep_tcp4(&e); e.options = FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT;
    EXPECT_NT(ep_try(&e), ST_INVALID_PARAMETER);
}
TEST(aech_sync_option_requires_synchronize_access)
{
    ep_t e; NEED(); ep_tcp4(&e); e.options = SYNC_OPT; e.access = GENERIC_READ | GENERIC_WRITE;
    EXPECT_NT(ep_try(&e), ST_INVALID_PARAMETER);
}
TEST(aech_sync_alert_requires_synchronize_access)
{
    ep_t e; NEED(); ep_tcp4(&e); e.options = FILE_SYNCHRONOUS_IO_ALERT; e.access = GENERIC_READ | GENERIC_WRITE;
    EXPECT_NT(ep_try(&e), ST_INVALID_PARAMETER);
}
TEST(aech_sync_option_with_synchronize_access_ok)
{
    ep_t e; NEED(); ep_tcp4(&e); e.options = SYNC_OPT; e.access = GENERIC_READ | SYNCHRONIZE;
    EXPECT_NT(ep_try(&e), ST_SUCCESS);
}
TEST(aech_directory_file_option_accepted_on_device)
{
    ep_t e; NEED(); ep_tcp4(&e); e.options = FILE_DIRECTORY_FILE;
    EXPECT_NT(ep_try(&e), ST_SUCCESS);
}
TEST(aech_overlapped_open_without_synchronize_access)
{
    ep_t e; LONG st; NEED(); ep_tcp4(&e); e.options = 0; e.access = GENERIC_READ | GENERIC_WRITE;
    st = ep_try(&e);
    EXPECT_NT(st, ST_SUCCESS);
}
