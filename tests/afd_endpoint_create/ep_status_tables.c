/* Status tables for the operations an endpoint handle answers right after creation.
 *
 * Measures, per information class, what NtQueryInformationFile / NtQueryVolumeInformationFile /
 * NtSetInformationFile / NtQueryObject return on a freshly created endpoint (overlapped open, never
 * bound or connected) and on a control handle, and what NtReadFile / NtWriteFile /
 * NtDeviceIoControlFile say about an endpoint that has no connection. The expected tables were taken
 * from the target OS and are the reference an alternative implementation compares against.
 * Operations that could block run in a child process with a bounded wait. */
#include "aec.h"

typedef struct { int cls; const char *name; } cls_t;

static const cls_t FILE_CLASSES[] = {
    {2, "FileFullDirectory"}, {3, "FileBothDirectory"}, {4, "FileBasic"}, {5, "FileStandard"}, {6, "FileInternal"},
    {7, "FileEa"}, {8, "FileAccess"}, {9, "FileName"}, {10, "FileRename"}, {11, "FileLink"}, {12, "FileNames"},
    {13, "FileDisposition"}, {14, "FilePosition"}, {15, "FileFullEa"}, {16, "FileMode"}, {17, "FileAlignment"},
    {18, "FileAll"}, {19, "FileAllocation"}, {20, "FileEndOfFile"}, {21, "FileAlternateName"}, {22, "FileStream"},
    {23, "FilePipe"}, {24, "FilePipeLocal"}, {25, "FilePipeRemote"}, {26, "FileMailslotQuery"}, {27, "FileMailslotSet"},
    {28, "FileCompression"}, {29, "FileObjectId"}, {30, "FileCompletion"}, {31, "FileMoveCluster"}, {32, "FileQuota"},
    {33, "FileReparsePoint"}, {34, "FileNetworkOpen"}, {35, "FileAttributeTag"}, {36, "FileTracking"},
    {37, "FileIdBothDirectory"}, {38, "FileIdFullDirectory"}, {39, "FileValidDataLength"}, {40, "FileShortName"},
    {41, "FileIoCompletionNotification"}, {42, "FileIoStatusBlockRange"}, {43, "FileIoPriorityHint"},
    {44, "FileSfioReserve"}, {45, "FileSfioVolume"}, {46, "FileHardLink"}, {47, "FileProcessIdsUsingFile"},
    {48, "FileNormalizedName"}, {49, "FileNetworkPhysicalName"}, {50, "FileIdGlobalTxDirectory"},
    {51, "FileIsRemoteDevice"}, {52, "FileUnusedInfo"}, {53, "FileNumaNode"}, {54, "FileStandardLink"},
    {55, "FileRemoteProtocol"}, {56, "FileRenameBypassAccessCheck"}, {57, "FileLinkBypassAccessCheck"},
    {58, "FileVolumeName"}, {59, "FileId"}, {60, "FileIdExtdDirectory"}, {61, "FileReplaceCompletion"},
    {62, "FileHardLinkFullId"}, {63, "FileIdExtdBothDirectory"}, {64, "FileDispositionEx"}, {65, "FileRenameEx"},
    {66, "FileRenameExBypassAccessCheck"}, {67, "FileDesiredStorageClass"}, {68, "FileStatInformation"},
    {69, "FileMemoryPartition"}, {70, "FileStatLxInformation"}, {71, "FileCaseSensitive"}, {72, "FileLinkEx"}
};
#define NFILE ((int)(sizeof(FILE_CLASSES) / sizeof(FILE_CLASSES[0])))

/* Expected answers observed on the target OS. Classes the I/O manager owns (mode, access, alignment,
 * volume name, ...) succeed, everything the driver would have to implement is STATUS_NOT_IMPLEMENTED
 * and classes the system does not know are STATUS_INVALID_INFO_CLASS. */
static const LONG EXP_QUERY[] = {
    ST_INVALID_INFO_CLASS, /* 2 FileFullDirectory */
    ST_INVALID_INFO_CLASS, /* 3 FileBothDirectory */
    ST_NOT_IMPLEMENTED, /* 4 FileBasic */
    ST_NOT_IMPLEMENTED, /* 5 FileStandard */
    ST_NOT_IMPLEMENTED, /* 6 FileInternal */
    ST_NOT_IMPLEMENTED, /* 7 FileEa */
    ST_SUCCESS, /* 8 FileAccess */
    ST_NOT_IMPLEMENTED, /* 9 FileName */
    ST_INVALID_INFO_CLASS, /* 10 FileRename */
    ST_INVALID_INFO_CLASS, /* 11 FileLink */
    ST_INVALID_INFO_CLASS, /* 12 FileNames */
    ST_INVALID_INFO_CLASS, /* 13 FileDisposition */
    ST_NOT_IMPLEMENTED, /* 14 FilePosition */
    ST_INVALID_INFO_CLASS, /* 15 FileFullEa */
    ST_SUCCESS, /* 16 FileMode */
    ST_SUCCESS, /* 17 FileAlignment */
    ST_NOT_IMPLEMENTED, /* 18 FileAll */
    ST_INVALID_INFO_CLASS, /* 19 FileAllocation */
    ST_INVALID_INFO_CLASS, /* 20 FileEndOfFile */
    ST_NOT_IMPLEMENTED, /* 21 FileAlternateName */
    ST_NOT_IMPLEMENTED, /* 22 FileStream */
    ST_NOT_IMPLEMENTED, /* 23 FilePipe */
    ST_NOT_IMPLEMENTED, /* 24 FilePipeLocal */
    ST_NOT_IMPLEMENTED, /* 25 FilePipeRemote */
    ST_NOT_IMPLEMENTED, /* 26 FileMailslotQuery */
    ST_INVALID_INFO_CLASS, /* 27 FileMailslotSet */
    ST_NOT_IMPLEMENTED, /* 28 FileCompression */
    ST_NOT_IMPLEMENTED, /* 29 FileObjectId */
    ST_INVALID_INFO_CLASS, /* 30 FileCompletion */
    ST_INVALID_INFO_CLASS, /* 31 FileMoveCluster */
    ST_NOT_IMPLEMENTED, /* 32 FileQuota */
    ST_NOT_IMPLEMENTED, /* 33 FileReparsePoint */
    ST_NOT_IMPLEMENTED, /* 34 FileNetworkOpen */
    ST_NOT_IMPLEMENTED, /* 35 FileAttributeTag */
    ST_INVALID_INFO_CLASS, /* 36 FileTracking */
    ST_INVALID_INFO_CLASS, /* 37 FileIdBothDirectory */
    ST_INVALID_INFO_CLASS, /* 38 FileIdFullDirectory */
    ST_INVALID_INFO_CLASS, /* 39 FileValidDataLength */
    ST_INVALID_INFO_CLASS, /* 40 FileShortName */
    ST_SUCCESS, /* 41 FileIoCompletionNotification */
    ST_INVALID_INFO_CLASS, /* 42 FileIoStatusBlockRange */
    ST_SUCCESS, /* 43 FileIoPriorityHint */
    ST_NOT_IMPLEMENTED, /* 44 FileSfioReserve */
    ST_NOT_IMPLEMENTED, /* 45 FileSfioVolume */
    ST_NOT_IMPLEMENTED, /* 46 FileHardLink */
    ST_SUCCESS, /* 47 FileProcessIdsUsingFile */
    ST_NOT_IMPLEMENTED, /* 48 FileNormalizedName */
    ST_NOT_IMPLEMENTED, /* 49 FileNetworkPhysicalName */
    ST_INVALID_INFO_CLASS, /* 50 FileIdGlobalTxDirectory */
    ST_SUCCESS, /* 51 FileIsRemoteDevice */
    ST_INVALID_INFO_CLASS, /* 52 FileUnusedInfo */
    ST_NO_SUCH_DEVICE, /* 53 FileNumaNode */
    ST_NOT_IMPLEMENTED, /* 54 FileStandardLink */
    ST_NOT_IMPLEMENTED, /* 55 FileRemoteProtocol */
    ST_INVALID_INFO_CLASS, /* 56 FileRenameBypassAccessCheck */
    ST_INVALID_INFO_CLASS, /* 57 FileLinkBypassAccessCheck */
    ST_SUCCESS, /* 58 FileVolumeName */
    ST_NOT_IMPLEMENTED, /* 59 FileId */
    ST_INVALID_INFO_CLASS, /* 60 FileIdExtdDirectory */
    ST_INVALID_INFO_CLASS, /* 61 FileReplaceCompletion */
    ST_NOT_IMPLEMENTED, /* 62 FileHardLinkFullId */
    ST_INVALID_INFO_CLASS, /* 63 FileIdExtdBothDirectory */
    ST_INVALID_INFO_CLASS, /* 64 FileDispositionEx */
    ST_INVALID_INFO_CLASS, /* 65 FileRenameEx */
    ST_INVALID_INFO_CLASS, /* 66 FileRenameExBypassAccessCheck */
    ST_NOT_IMPLEMENTED, /* 67 FileDesiredStorageClass */
    ST_NOT_IMPLEMENTED, /* 68 FileStatInformation */
    ST_INVALID_INFO_CLASS, /* 69 FileMemoryPartition */
    ST_NOT_IMPLEMENTED, /* 70 FileStatLxInformation */
    ST_NOT_IMPLEMENTED, /* 71 FileCaseSensitive */
    ST_INVALID_INFO_CLASS, /* 72 FileLinkEx */
};
static const LONG EXP_SET[] = {
    ST_NOT_IMPLEMENTED, /* FileBasic */
    ST_ACCESS_DENIED, /* FileRename */
    ST_INVALID_PARAMETER, /* FileLink */
    ST_ACCESS_DENIED, /* FileDisposition */
    ST_NOT_IMPLEMENTED, /* FilePosition */
    ST_SUCCESS, /* FileMode */
    ST_NOT_IMPLEMENTED, /* FileAllocation */
    ST_NOT_IMPLEMENTED, /* FileEndOfFile */
    ST_NOT_IMPLEMENTED, /* FilePipe */
    ST_INVALID_HANDLE, /* FileCompletion */
    ST_NOT_IMPLEMENTED, /* FileValidDataLength */
    ST_SUCCESS, /* FileIoCompletionNotification */
    ST_SUCCESS, /* FileIoPriorityHint */
    ST_ACCESS_DENIED, /* FileDispositionEx */
};
static const LONG EXP_VOLUME[] = {
    ST_NOT_IMPLEMENTED, /* class 1 */
    ST_INVALID_INFO_CLASS, /* class 2 */
    ST_NOT_IMPLEMENTED, /* class 3 */
    ST_SUCCESS, /* class 4 */
    ST_NOT_IMPLEMENTED, /* class 5 */
    ST_NOT_IMPLEMENTED, /* class 6 */
    ST_NOT_IMPLEMENTED, /* class 7 */
    ST_NOT_IMPLEMENTED, /* class 8 */
    ST_OBJECT_NAME_INVALID, /* class 9 */
    ST_NOT_IMPLEMENTED, /* class 10 */
    ST_NOT_IMPLEMENTED, /* class 11 */
    ST_NOT_IMPLEMENTED, /* class 12 */
};
static const LONG EXP_OBJECT[] = {
    ST_SUCCESS, /* class 0 */
    ST_SUCCESS, /* class 1 */
    ST_SUCCESS, /* class 2 */
    ST_INFO_LENGTH_MISMATCH, /* class 3 */
    ST_SUCCESS, /* class 4 */
    ST_INVALID_INFO_CLASS, /* class 5 */
    ST_INVALID_INFO_CLASS, /* class 6 */
    ST_INVALID_INFO_CLASS, /* class 7 */
    ST_INVALID_INFO_CLASS, /* class 8 */
    ST_INVALID_INFO_CLASS, /* class 9 */
};

static void check_row(const char *tag, const char *what, LONG got, LONG want)
{
    CHECKF(got == want, "%s %s got %s want %s", tag, what, st_name(got), st_name(want));
}
static void file_class_table(const char *tag, ep_t *e, int sync)
{
    HANDLE h = ep_ok(e); int i;
    if (!h) return;
    for (i = 0; i < NFILE; i++) {
        unsigned char buf[512]; IO_STATUS_BLOCK io; LONG st, want = EXP_QUERY[i];
        memset(buf, 0, sizeof(buf));
        st = N.NtQueryInformationFile(h, &io, buf, sizeof(buf), FILE_CLASSES[i].cls);
        if (FILE_CLASSES[i].cls == 14 && sync) want = ST_SUCCESS;   /* the position exists only for synchronous handles */
        check_row(tag, FILE_CLASSES[i].name, st, want);
    }
    N.NtClose(h);
}
TEST(aecx_query_file_classes_overlapped_endpoint) { ep_t e; NEED(); ep_tcp4(&e); file_class_table("endpoint", &e, 0); }
TEST(aecx_query_file_classes_sync_endpoint)       { ep_t e; NEED(); ep_tcp4(&e); e.options = 0x20; file_class_table("sync endpoint", &e, 1); }
TEST(aecx_query_file_classes_control_handle)      { ep_t e; NEED(); ep_tcp4(&e); e.no_ea = 1; file_class_table("control", &e, 0); }
TEST(aecx_query_file_classes_udp_endpoint)        { ep_t e; NEED(); ep_udp4(&e); file_class_table("udp endpoint", &e, 0); }
TEST(aecx_query_file_classes_raw_endpoint)        { ep_t e; NEED(); ep_raw4(&e, 1); file_class_table("raw endpoint", &e, 0); }

static void set_class_table(const char *tag, ep_t *e)
{
    HANDLE h = ep_ok(e); int i;
    static const int cls[] = {4, 10, 11, 13, 14, 16, 19, 20, 23, 30, 39, 41, 43, 64};
    if (!h) return;
    for (i = 0; i < (int)(sizeof(cls) / sizeof(cls[0])); i++) {
        unsigned char buf[64]; IO_STATUS_BLOCK io; LONG st; int k;
        memset(buf, 0, sizeof(buf));
        st = N.NtSetInformationFile(h, &io, buf, sizeof(buf), cls[i]);
        for (k = 0; k < NFILE; k++) if (FILE_CLASSES[k].cls == cls[i]) break;
        check_row(tag, k < NFILE ? FILE_CLASSES[k].name : "?", st, EXP_SET[i]);
    }
    N.NtClose(h);
}
TEST(aecx_set_file_classes_endpoint) { ep_t e; NEED(); ep_tcp4(&e); set_class_table("endpoint", &e); }
TEST(aecx_set_file_classes_control)  { ep_t e; NEED(); ep_tcp4(&e); e.no_ea = 1; set_class_table("control", &e); }

static void volume_table(const char *tag, ep_t *e)
{
    HANDLE h = ep_ok(e); int c;
    if (!h) return;
    for (c = 1; c <= 12; c++) {
        unsigned char buf[512]; IO_STATUS_BLOCK io; LONG st;
        char what[24];
        memset(buf, 0, sizeof(buf));
        st = N.NtQueryVolumeInformationFile(h, &io, buf, sizeof(buf), c);
        snprintf(what, sizeof(what), "volume class %d", c);
        check_row(tag, what, st, EXP_VOLUME[c - 1]);
    }
    N.NtClose(h);
}
TEST(aecx_query_volume_classes_endpoint) { ep_t e; NEED(); ep_tcp4(&e); volume_table("endpoint", &e); }
TEST(aecx_query_volume_classes_control)  { ep_t e; NEED(); ep_tcp4(&e); e.no_ea = 1; volume_table("control", &e); }

static void object_table(const char *tag, ep_t *e)
{
    HANDLE h = ep_ok(e); int c;
    if (!h) return;
    for (c = 0; c <= 9; c++) {
        unsigned char buf[1024]; ULONG rl = 0; LONG st; char what[24];
        memset(buf, 0, sizeof(buf));
        st = N.NtQueryObject(h, c, buf, c == 0 ? 0x38 : sizeof(buf), &rl);
        snprintf(what, sizeof(what), "object class %d", c);
        check_row(tag, what, st, EXP_OBJECT[c]);
    }
    N.NtClose(h);
}
TEST(aecx_query_object_classes_endpoint) { ep_t e; NEED(); ep_tcp4(&e); object_table("endpoint", &e); }
TEST(aecx_query_object_classes_control)  { ep_t e; NEED(); ep_tcp4(&e); e.no_ea = 1; object_table("control", &e); }

/* Stable, small assertions drawn from the same information classes */
TEST(aecx_query_mode_class_succeeds_for_every_kind)
{
    ep_t e; HANDLE h; IO_STATUS_BLOCK io; ULONG m; int i; NEED();
    for (i = 0; i < 6; i++) {
        switch (i) { case 0: ep_tcp4(&e); break; case 1: ep_udp4(&e); break; case 2: ep_tcp6(&e); break;
                     case 3: ep_udp6(&e); break; case 4: ep_raw4(&e, 1); break; default: ep_raw6(&e, 58); break; }
        h = ep_ok(&e); if (!h) continue;
        m = 0xDEAD;
        EXPECT_NT(N.NtQueryInformationFile(h, &io, &m, sizeof(m), FileModeInformation_), ST_SUCCESS);
        EXPECT_EQ(m, 0);
        N.NtClose(h);
    }
}
TEST(aecx_query_access_class_succeeds_for_every_kind)
{
    ep_t e; HANDLE h; IO_STATUS_BLOCK io; ULONG a; int i; NEED();
    for (i = 0; i < 6; i++) {
        switch (i) { case 0: ep_tcp4(&e); break; case 1: ep_udp4(&e); break; case 2: ep_tcp6(&e); break;
                     case 3: ep_udp6(&e); break; case 4: ep_raw4(&e, 1); break; default: ep_raw6(&e, 58); break; }
        h = ep_ok(&e); if (!h) continue;
        a = 0xDEAD;
        EXPECT_NT(N.NtQueryInformationFile(h, &io, &a, sizeof(a), FileAccessInformation_), ST_SUCCESS);
        EXPECT_EQ(a, FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC);
        N.NtClose(h);
    }
}
TEST(aecx_object_type_name_info_length_mismatch_zero)
{
    ep_t e; HANDLE h; ULONG rl = 0; NEED(); ep_tcp4(&e);
    h = ep_ok(&e); if (!h) return;
    EXPECT_NT(N.NtQueryObject(h, 2, NULL, 0, &rl), ST_INFO_LENGTH_MISMATCH);
    EXPECT_NT(N.NtQueryObject(h, 1, NULL, 0, &rl), ST_INFO_LENGTH_MISMATCH);
    N.NtClose(h);
}
TEST(aecx_object_name_required_length_covers_device_name)
{
    ep_t e; HANDLE h; ULONG rl = 0; unsigned char b[8]; NEED(); ep_tcp4(&e);
    h = ep_ok(&e); if (!h) return;
    EXPECT_NT(N.NtQueryObject(h, 1, b, sizeof(b), &rl), ST_INFO_LENGTH_MISMATCH);
    CHECKF(rl >= 16 + 24, "required %lu", (unsigned long)rl);   /* header + L"\\Device\\Afd" + terminator */
    N.NtClose(h);
}

/* ---- transfer and control requests on an unconnected endpoint (child process, bounded) --- */
static LONG io_op_on_fresh_endpoint(int which)
{
    ep_t e; HANDLE h; IO_STATUS_BLOCK io; unsigned char b[64]; LONG st; ep_t tmp;
    if (!aec_ready()) return 0x7FFF0001;
    ep_tcp4(&e); tmp = e;
    h = NULL;
    if (ep_open(&tmp, &h, &io) < 0 || !h) return 0x7FFF0002;
    memset(b, 0, sizeof(b)); memset(&io, 0xAB, sizeof(io));
    switch (which) {
    case 0: st = N.NtReadFile(h, NULL, NULL, NULL, &io, b, 16, NULL, NULL); break;
    case 1: st = N.NtWriteFile(h, NULL, NULL, NULL, &io, b, 16, NULL, NULL); break;
    case 2: st = N.NtDeviceIoControlFile(h, NULL, NULL, NULL, &io, 0x0012FFFC, b, 0, b, 0); break;
    case 3: st = N.NtFsControlFile(h, NULL, NULL, NULL, &io, 0x00090000, b, 0, b, 0); break;
    default: st = N.NtDeviceIoControlFile(h, NULL, NULL, NULL, &io, 0x00000000, NULL, 0, NULL, 0); break;
    }
    N.NtClose(h);
    return st;
}
CHILD(aecx_io_read)  { return io_op_on_fresh_endpoint(0); }
CHILD(aecx_io_write) { return io_op_on_fresh_endpoint(1); }
CHILD(aecx_io_ioctl) { return io_op_on_fresh_endpoint(2); }
CHILD(aecx_io_fsctl) { return io_op_on_fresh_endpoint(3); }
CHILD(aecx_io_ioctl0){ return io_op_on_fresh_endpoint(4); }

static void io_child_expect(const char *label, const char *child, LONG want)
{
    DWORD rc = t_run_child(child, "", 15000);
    if (rc == 0xDEAD0000) { t_skip("child could not start"); return; }
    CHECKF(rc != 0xDEAD0001, "%s: did not complete within the bound", label);
    if (rc != 0xDEAD0001) CHECKF((LONG)rc == want, "%s got %s want %s", label, st_name((LONG)rc), st_name(want));
}
TEST(aecx_io_read_unconnected_stream)      { NEED(); io_child_expect("NtReadFile on unconnected tcp endpoint", "aecx_io_read", ST_INVALID_PARAMETER); }
TEST(aecx_io_write_unconnected_stream)     { NEED(); io_child_expect("NtWriteFile on unconnected tcp endpoint", "aecx_io_write", ST_INVALID_PARAMETER); }
TEST(aecx_io_unknown_ioctl)                { NEED(); io_child_expect("NtDeviceIoControlFile unknown code on endpoint", "aecx_io_ioctl", ST_INVALID_DEVICE_REQUEST); }
TEST(aecx_io_zero_ioctl)                   { NEED(); io_child_expect("NtDeviceIoControlFile code 0 on endpoint", "aecx_io_ioctl0", ST_INVALID_DEVICE_REQUEST); }
TEST(aecx_io_foreign_fsctl)                { NEED(); io_child_expect("NtFsControlFile foreign code on endpoint", "aecx_io_fsctl", ST_NOT_IMPLEMENTED); }
