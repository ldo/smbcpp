"""A pure-Python wrapper for libsmbclient <https://www.samba.org> using
ctypes.

Note that all share/directory/file specs are URLs of the form

    smb://[[[«domain»;]«user»[:«password»]@]«server»[:«port»][/«share»[/«path»[/«file»]]]]

(I have omitted the “options” part because libsmbclient doesn’t currently support it.)
"""
#+
# Copyright 2019 Lawrence D'Oliveiro <ldo@geek-central.gen.nz>.
# Licensed under the GNU Lesser General Public License v2.1 or later.
#-

import os
import errno
import time
import ctypes as ct
from weakref import \
    ref as weak_ref, \
    WeakValueDictionary
import threading
import array
from collections import \
    namedtuple
import queue
import enum
import atexit
import asyncio

smbc = ct.cdll.LoadLibrary("libsmbclient.so.0")

class SMBC :
    "useful definitions adapted from libsmbclient.h. You will need to use the" \
    " constants, but apart from that, see the more Pythonic wrappers defined" \
    " outside this class in preference to accessing low-level structures directly."

    # General ctypes gotcha: when passing addresses of ctypes-constructed objects
    # to routine calls, do not construct the objects directly in the call. Otherwise
    # the refcount goes to 0 before the routine is actually entered, and the object
    # can get prematurely disposed. Always store the object reference into a local
    # variable, and pass the value of the variable instead.

    # deduced from /usr/include/x86_64-linux-gnu/bits/typesizes.h
    c_time_t = ct.c_ulong
    c_off_t = ct.c_ulonglong
    c_mode_t = ct.c_uint
    c_dev_t = ct.c_ulong
    c_ino_t = ct.c_ulong
    c_nlink_t = ct.c_ulong
    c_blksize_t = ct.c_long
    c_blkcnt_t = ct.c_long
    c_fsblkcnt_t = ct.c_ulong
    c_fsfilcnt_t = ct.c_ulong
    c_uid_t = ct.c_uint
    c_gid_t = ct.c_uint

    class c_timespec_t(ct.Structure) :
        # from /usr/include/x86_64-linux-gnu/bits/types/struct_timespec.h
        pass
    c_timespec_t._fields_ = \
        [
            ("tv_sec", c_time_t),
            ("tv_nsec", ct.c_long),
        ]
    #end c_timespec_t

    class c_timeval_t(ct.Structure) :
        # from /usr/include/x86_64-linux-gnu/bits/types/struct_timeval.h
        pass
    c_timeval_t._fields_ = \
        [
            ("tv_sec", c_time_t),
            ("tv_usec", ct.c_long),
        ]
    #end c_timeval_t

    class c_utimbuf_t(ct.Structure) :
        pass
    c_utimbuf_t._fields_ = \
        [
            ("actime", c_timeval_t),
            ("modtime", c_timeval_t),
        ]
    #end c_utimbuf_t

    _STAT_VER_LINUX = 3

    class c_stat_t(ct.Structure) :
        # from /usr/include/bits/stat.h
        pass
    c_stat_t._fields_ = \
        (
            [
                ("st_dev", c_dev_t),
            ]
        +
            {
                4 : [("Ṕ__pad1", ct.c_ushort)],
                8 : [],
            }[ct.sizeof(ct.c_void_p)]
        +
            [
                ("st_ino", c_ino_t),
            ]
        +
            {
                4 :
                    [
                        ("st_mode", c_mode_t),
                        ("st_nlink", c_nlink_t),
                    ],
                8 :
                    [
                        ("st_nlink", c_nlink_t),
                        ("st_mode", c_mode_t),
                    ],
            }[ct.sizeof(ct.c_void_p)]
        +
            [
                ("st_uid", c_uid_t),
                ("st_gid", c_gid_t),
            ]
        +
            {
                4 : [],
                8 : [("Ṕ__pad0", ct.c_int)],
            }[ct.sizeof(ct.c_void_p)]
        +
            [
                ("st_rdev", c_dev_t),
            ]
        +
            {
                4 : [("Ṕ__pad2", ct.c_ushort)],
                8 : [],
            }[ct.sizeof(ct.c_void_p)]
        +
            [
                ("st_size", c_off_t),
                ("st_blksize", c_blksize_t),
                ("st_blocks", c_blkcnt_t),
                ("st_atim", c_timespec_t),
                ("st_mtim", c_timespec_t),
                ("st_ctim", c_timespec_t),
                ("Ṕ__glibc_reserved", 3 * ct.c_long),
            ]
        )
    #end c_stat_t

    # masks for c_statvfs_t.f_flag:
    ST_RDONLY = 1
    ST_NOSUID = 2
    ST_NODEV = 4
    ST_NOEXEC = 8
    ST_SYNCHRONOUS = 16
    ST_MANDLOCK = 64
    ST_WRITE = 128
    ST_APPEND = 256
    ST_IMMUTABLE = 512
    ST_NOATIME = 1024
    ST_NODIRATIME = 2048
    ST_RELATIME = 4096
    class c_statvfs_t(ct.Structure) :
        # from /usr/include/bits/statvfs.h
        pass
    c_statvfs_t._fields_ = \
        [
            ("f_bsize", ct.c_ulong),
            ("f_frsize", ct.c_ulong),
            ("f_blocks", c_fsblkcnt_t),
            ("f_bfree", c_fsblkcnt_t),
            ("f_bavail", c_fsblkcnt_t),
            ("f_files", c_fsfilcnt_t),
            ("f_ffree", c_fsfilcnt_t),
            ("f_favail", c_fsfilcnt_t),
            ("f_fsid", ct.c_ulong),
            ("f_flag", ct.c_ulong),
            ("f_namemax", ct.c_ulong),
        ]
    #end c_statvfs_t

    BASE_FD = 10000
      # base for numbering file descriptors managed by compatibility calls.
      # Note these are just libsmbclient-assigned numbers, not real kernel file descriptors!

    # dirent entry types
    WORKGROUP = 1
    SERVER = 2
    FILE_SHARE = 3
    PRINTER_SHARE = 4
    COMMS_SHARE = 5
    IPC_SHARE = 6
    DIR = 7
    FILE = 8
    LINK = 9

    class dirent(ct.Structure) :
        _fields_ = \
            [
                ("smbc_type", ct.c_uint),
                ("dirlen", ct.c_uint),
                ("commentlen", ct.c_uint),
                ("comment", ct.c_void_p),
                ("namelen", ct.c_uint),
                ("name", ct.c_char * 0),
            ]
    #end dirent
    direntsize = {4 : 20, 8 : 28}[ct.sizeof(ct.c_void_p)]
      # exclude padding on end of dirent struct
    NAME_MAX = 255 # from <linux/limits.h>

    class file_info(ct.Structure) :
        pass
    file_info._fields_ = \
        [
            ("size", c_off_t),
            ("attrs", ct.c_ushort), # DOS attributes
            ("uid", c_uid_t),
            ("gid", c_gid_t),
            ("btime_ts", c_timespec_t), # birth/create time
            ("mtime_ts", c_timespec_t), # modified time
            ("atime_ts", c_timespec_t), # access time
            ("ctime_ts", c_timespec_t), # change time
            ("name", ct.c_char_p),
            ("short_name", ct.c_char_p),
        ]
    #end file_info

    debug_callback_fn = ct.CFUNCTYPE(None, ct.c_void_p, ct.c_int, ct.c_char_p)

    XATTR_FLAG_CREATE = 0x1
    XATTR_FLAG_REPLACE = 0x2

    DOS_MODE_READONLY = 0x01
    DOS_MODE_HIDDEN = 0x02
    DOS_MODE_SYSTEM = 0x04
    DOS_MODE_VOLUME_ID = 0x08
    DOS_MODE_DIRECTORY = 0x10
    DOS_MODE_ARCHIVE = 0x20

    share_mode = ct.c_uint
    # values for share_mode
    SHAREMODE_DENY_DOS = 0
    SHAREMODE_DENY_ALL = 1
    SHAREMODE_DENY_WRITE = 2
    SHAREMODE_DENY_READ = 3
    SHAREMODE_DENY_NONE = 4
    SHAREMODE_DENY_FCB = 7

    smb_encrypt_level = ct.c_uint
    # values for smb_encrypt_level
    ENCRYPTLEVEL_NONE = 0
    ENCRYPTLEVEL_REQUEST = 1
    ENCRYPTLEVEL_REQUIRE = 2

    vfs_feature = ct.c_uint
    # values for vfs_feature
    VFS_FEATURE_RDONLY = 1 << 0
    VFS_FEATURE_DFS = 1 << 28
    VFS_FEATURE_CASE_INSENSITIVE = 1 << 29
    VFS_FEATURE_NO_UNIXCIFS = 1 << 30

    bool = ct.c_int

    class print_job_info(ct.Structure) :
        pass
    print_job_info._fields_ = \
        [
            ("id", ct.c_ushort),
            ("priority", ct.c_ushort),
            ("size", ct.c_size_t),
            ("user", ct.c_char * 128),
            ("name", ct.c_char * 128),
            ("t", c_time_t),
        ]
     #end print_job_info

    SRVptr = ct.c_void_p # server handle
    FILEptr = ct.c_void_p # file handle
    CTXptr = ct.c_void_p # context

    CTX_FLAG_USE_KERBEROS = 1 << 0
    CTX_FLAG_FALLBACK_AFTER_KERBEROS = 1 << 1
    CTX_FLAG_NO_AUTO_ANONYMOUS_LOGON = 1 << 2
    CTX_FLAG_USE_CCACHE = 1 << 3

    get_auth_data_fn = ct.CFUNCTYPE(None, ct.c_char_p, ct.c_char_p, ct.POINTER(ct.c_char), ct.c_int, ct.POINTER(ct.c_char), ct.c_int, ct.POINTER(ct.c_char), ct.c_int)
    get_auth_data_with_context_fn = ct.CFUNCTYPE(None, ct.c_char_p, ct.c_char_p, ct.POINTER(ct.c_char), ct.c_int, ct.POINTER(ct.c_char), ct.c_int, ct.POINTER(ct.c_char), ct.c_int)
    list_print_job_fn = ct.CFUNCTYPE(None, ct.POINTER(print_job_info))
    check_server_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, SRVptr)
    remove_unused_server_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, SRVptr)
    add_cached_srv_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, SRVptr, ct.c_char_p, ct.c_char_p, ct.c_char_p, ct.c_char_p)
    get_cached_srv_fn = ct.CFUNCTYPE(SRVptr, CTXptr, ct.c_char_p, ct.c_char_p, ct.c_char_p, ct.c_char_p)
    remove_cached_srv_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, SRVptr)
    purge_cached_fn = ct.CFUNCTYPE(ct.c_int, CTXptr)

    NOTIFY_CHANGE_FILE_NAME = 0x001
    NOTIFY_CHANGE_DIR_NAME = 0x002
    NOTIFY_CHANGE_ATTRIBUTES = 0x004
    NOTIFY_CHANGE_SIZE = 0x008
    NOTIFY_CHANGE_LAST_WRITE = 0x010
    NOTIFY_CHANGE_LAST_ACCESS = 0x020
    NOTIFY_CHANGE_CREATION = 0x040
    NOTIFY_CHANGE_EA = 0x080
    NOTIFY_CHANGE_SECURITY = 0x100
    NOTIFY_CHANGE_STREAM_NAME = 0x200
    NOTIFY_CHANGE_STREAM_SIZE = 0x400
    NOTIFY_CHANGE_STREAM_WRITE = 0x800

    open_fn = ct.CFUNCTYPE(FILEptr, CTXptr, ct.c_char_p, ct.c_int, c_mode_t, use_errno = True)
    creat_fn = ct.CFUNCTYPE(FILEptr, CTXptr, ct.c_char_p, ct.c_int, use_errno = True)
    read_fn = ct.CFUNCTYPE(ct.c_ssize_t, CTXptr, FILEptr, ct.c_void_p, ct.c_size_t, use_errno = True)
    write_fn = ct.CFUNCTYPE(ct.c_ssize_t, CTXptr, FILEptr, ct.c_void_p, ct.c_size_t, use_errno = True)
    splice_cb_fn = ct.CFUNCTYPE(ct.c_int, c_off_t, ct.c_void_p, use_errno = True)
    splice_fn = ct.CFUNCTYPE(c_off_t, CTXptr, FILEptr, FILEptr, c_off_t, splice_cb_fn, ct.c_void_p, use_errno = True)
    unlink_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, ct.c_char_p, use_errno = True)
    rename_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, ct.c_char_p, CTXptr, ct.c_char_p, use_errno = True)
    lseek_fn = ct.CFUNCTYPE(c_off_t, CTXptr, FILEptr, c_off_t, ct.c_int, use_errno = True)
    stat_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, ct.c_char_p, ct.POINTER(c_stat_t), use_errno = True)
    fstat_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, FILEptr, ct.POINTER(c_stat_t), use_errno = True)
    statvfs_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, ct.c_char_p, ct.POINTER(c_statvfs_t), use_errno = True)
    fstatvfs_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, FILEptr, ct.POINTER(c_statvfs_t), use_errno = True)
    ftruncate_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, FILEptr, c_off_t, use_errno = True)
    close_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, FILEptr, use_errno = True)
    opendir_fn = ct.CFUNCTYPE(FILEptr, CTXptr, ct.c_char_p, use_errno = True)
    closedir_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, FILEptr, use_errno = True)
    readdir_fn = ct.CFUNCTYPE(ct.POINTER(dirent), CTXptr, FILEptr, use_errno = True)
    readdirplus_fn = ct.CFUNCTYPE(ct.POINTER(file_info), CTXptr, FILEptr, use_errno = True)
    getdents_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, FILEptr, ct.POINTER(dirent), ct.c_int, use_errno = True)
    mkdir_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, ct.c_char_p, c_mode_t, use_errno = True)
    rmdir_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, ct.c_char_p, use_errno = True)
    telldir_fn = ct.CFUNCTYPE(c_off_t, CTXptr, FILEptr, use_errno = True)
    lseekdir_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, c_off_t, use_errno = True)
    fstatdir_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, FILEptr, ct.POINTER(c_stat_t), use_errno = True)

    NOTIFY_ACTION_ADDED = 1
    NOTIFY_ACTION_REMOVED = 2
    NOTIFY_ACTION_MODIFIED = 3
    NOTIFY_ACTION_OLD_NAME = 4
    NOTIFY_ACTION_NEW_NAME = 5
    NOTIFY_ACTION_ADDED_STREAM = 6
    NOTIFY_ACTION_REMOVED_STREAM = 7
    NOTIFY_ACTION_MODIFIED_STREAM = 8

    class notify_callback_action(ct.Structure) :
        _fields_ = \
            [
                ("action", ct.c_uint),
                ("filename", ct.c_char_p),
            ]
    #end notify_callback_action

    notify_callback_fn = ct.CFUNCTYPE(ct.c_int, ct.POINTER(notify_callback_action), ct.c_size_t, ct.c_void_p)
    notify_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, FILEptr, bool, ct.c_uint, ct.c_uint, notify_callback_fn, ct.c_void_p, use_errno = True)
    chmod_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, ct.c_char_p, c_mode_t, use_errno = True)
    utimes_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, ct.c_char_p, ct.POINTER(c_utimbuf_t), use_errno = True)
    setxattr_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, ct.c_char_p, ct.c_char_p, ct.c_void_p, ct.c_size_t, ct.c_int, use_errno = True)
    getxattr_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, ct.c_char_p, ct.c_char_p, ct.c_void_p, ct.c_size_t, use_errno = True)
    removexattr_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, ct.c_char_p, ct.c_char_p, use_errno = True)
    listxattr_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, ct.c_char_p, ct.c_void_p, ct.c_size_t, use_errno = True)
    print_file_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, ct.c_char_p, CTXptr, ct.c_char_p, use_errno = True)
    open_print_job_fn = ct.CFUNCTYPE(FILEptr, CTXptr, ct.c_char_p, use_errno = True)
    list_print_jobs_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, ct.c_char_p, list_print_job_fn, use_errno = True)
    unlink_print_job_fn = ct.CFUNCTYPE(ct.c_int, CTXptr, ct.c_char_p, ct.c_int, use_errno = True)

    # mutex functions
    create_mutex_fn = ct.CFUNCTYPE(ct.c_int, ct.c_char_p, ct.POINTER(ct.c_void_p), ct.c_char_p)
    destroy_mutex_fn = ct.CFUNCTYPE(None, ct.c_void_p, ct.c_char_p)
    lock_mutex_fn = ct.CFUNCTYPE(ct.c_int, ct.c_void_p, ct.c_int, ct.c_char_p)
    create_tls_fn = ct.CFUNCTYPE(ct.c_int, ct.c_char_p, ct.POINTER(ct.c_void_p), ct.c_char_p)
    destroy_tls_fn = ct.CFUNCTYPE(None, ct.POINTER(ct.c_void_p), ct.c_char_p)
    set_tls_fn = ct.CFUNCTYPE(ct.c_int, ct.c_void_p, ct.c_void_p, ct.c_char_p)
    get_tls_fn = ct.CFUNCTYPE(ct.c_void_p, ct.c_void_p, ct.c_char_p)

#end SMBC

StructStat = namedtuple("StructStat", tuple(f[0] for f in SMBC.c_stat_t._fields_ if not f[0].startswith("Ṕ")))
StructStatVFS = namedtuple("StructStatVFS", tuple(f[0] for f in SMBC.c_statvfs_t._fields_ if not f[0].startswith("Ṕ")))
Dirent = namedtuple("Dirent", ("smbc_type", "comment", "name"))
FileInfo = namedtuple("FileInfo", tuple(f[0] for f in SMBC.file_info._fields_))
PrintJobInfo = namedtuple("PrintJobInfo", tuple(f[0] for f in SMBC.print_job_info._fields_))
NotifyCallbackAction = namedtuple("NotifyCallbackAction", ("action", "filename"))

THOUSAND = 1000
MILLION = THOUSAND * THOUSAND
BILLION = THOUSAND * MILLION

def _wderef(wself, parent_name) :
    self = wself()
    assert self != None, "parent %s has gone away" % parent_name
    return \
        self
#end _wderef

#+
# Routine arg/result types
#-

for name, argtype in \
    (
        (
            ("Debug", ct.c_int),
            ("NetbiosName", ct.c_char_p),
            ("Workgroup", ct.c_char_p),
            ("User", ct.c_char_p),
            ("Timeout", ct.c_int),
            ("Port", ct.c_ushort),
            ("OptionDebugToStderr", SMBC.bool),
            ("OptionFullTimeNames", SMBC.bool),
            ("OptionOpenShareMode", SMBC.share_mode),
            ("OptionUserData", ct.c_void_p),
            ("OptionSmbEncryptionLevel", SMBC.smb_encrypt_level),
            ("OptionCaseSensitive", SMBC.bool),
            ("OptionBrowseMaxLmbCount", ct.c_int),
            ("OptionUrlEncodeReaddirEntries", SMBC.bool),
            ("OptionOneSharePerServer", SMBC.bool),
            ("OptionUseKerberos", SMBC.bool),
            ("OptionFallbackAfterKerberos", SMBC.bool),
            ("OptionNoAutoAnonymousLogin", SMBC.bool),
            ("OptionUseCCache", SMBC.bool),
            ("OptionUseNTHash", SMBC.bool),
            ("FunctionAuthData", SMBC.get_auth_data_fn),
            ("FunctionAuthDataWithContext", SMBC.get_auth_data_with_context_fn),
            ("FunctionCheckServer", SMBC.check_server_fn),
            ("FunctionRemoveUnusedServer", SMBC.remove_unused_server_fn),
            ("FunctionAddCachedServer", SMBC.add_cached_srv_fn),
            ("FunctionGetCachedServer", SMBC.get_cached_srv_fn),
            ("FunctionRemoveCachedServer", SMBC.remove_cached_srv_fn),
            ("FunctionPurgeCachedServers", SMBC.purge_cached_fn),
            ("ServerCacheData", ct.c_void_p),
            ("FunctionOpen", SMBC.open_fn),
            ("FunctionCreat", SMBC.creat_fn),
            ("FunctionRead", SMBC.read_fn),
            ("FunctionWrite", SMBC.write_fn),
            ("FunctionSplice", SMBC.splice_fn),
            ("FunctionUnlink", SMBC.unlink_fn),
            ("FunctionRename", SMBC.rename_fn),
            ("FunctionLseek", SMBC.lseek_fn),
            ("FunctionStat", SMBC.stat_fn),
            ("FunctionFstat", SMBC.fstat_fn),
            ("FunctionStatVFS", SMBC.statvfs_fn),
            ("FunctionFstatVFS", SMBC.fstatvfs_fn),
            ("FunctionFtruncate", SMBC.ftruncate_fn),
            ("FunctionClose", SMBC.close_fn),
            ("FunctionOpendir", SMBC.opendir_fn),
            ("FunctionClosedir", SMBC.closedir_fn),
            ("FunctionReaddir", SMBC.readdir_fn),
            ("FunctionGetdents", SMBC.getdents_fn),
            ("FunctionMkdir", SMBC.mkdir_fn),
            ("FunctionRmdir", SMBC.rmdir_fn),
            ("FunctionTelldir", SMBC.telldir_fn),
            ("FunctionLseekdir", SMBC.lseekdir_fn),
            ("FunctionFstatdir", SMBC.fstatdir_fn),
            ("FunctionNotify", SMBC.notify_fn),
            ("FunctionChmod", SMBC.chmod_fn),
            ("FunctionUtimes", SMBC.utimes_fn),
            ("FunctionSetxattr", SMBC.setxattr_fn),
            ("FunctionGetxattr", SMBC.getxattr_fn),
            ("FunctionRemovexattr", SMBC.removexattr_fn),
            ("FunctionListxattr", SMBC.listxattr_fn),
            ("FunctionPrintFile", SMBC.print_file_fn),
            ("FunctionOpenPrintJob", SMBC.open_print_job_fn),
            ("FunctionListPrintJobs", SMBC.list_print_jobs_fn),
            ("FunctionUnlinkPrintJob", SMBC.unlink_print_job_fn),
        )
    +
        (
            (),
            (
                ("FunctionReaddirPlus", SMBC.readdirplus_fn),
            ),
        )[hasattr(smbc, "smbc_readdirplus")]
    ) \
:
    func = getattr(smbc, "smbc_get" + name)
    func.restype = argtype
    func.argtypes = (SMBC.CTXptr,)
    func = getattr(smbc, "smbc_set" + name)
    func.restype = None
    func.argtypes = (SMBC.CTXptr, argtype)
#end for
del name, argtype, func

if hasattr(smbc, "smbc_setLogCallback") :
    smbc.smbc_setLogCallback.restype = None
    smbc.smbc_setLogCallback.argtypes = (SMBC.CTXptr, ct.c_void_p, SMBC.debug_callback_fn)
#end if
if hasattr(smbc, "smbc_setConfiguration") :
    smbc.smbc_setConfiguration.restype = ct.c_int
    smbc.smbc_setConfiguration.argtypes = (SMBC.CTXptr, ct.c_char_p)
#end if
if hasattr(smbc, "smbc_setOptionProtocols") :
    smbc.smbc_setOptionProtocols.restype = SMBC.bool
    smbc.smbc_setOptionProtocols.argtypes = (SMBC.CTXptr, ct.c_char_p, ct.c_char_p)
#end if

smbc.smbc_new_context.restype = SMBC.CTXptr
smbc.smbc_new_context.argtypes = ()
smbc.smbc_free_context.restype = ct.c_int
smbc.smbc_free_context.argtypes = (SMBC.CTXptr, ct.c_int)
# smbc_option_set, smbc_option_get deprecated
smbc.smbc_init_context.restype = SMBC.CTXptr
smbc.smbc_init_context.argtypes = (SMBC.CTXptr,)
smbc.smbc_init.restype = ct.c_int
smbc.smbc_init.argtypes = (SMBC.get_auth_data_fn, ct.c_int)
smbc.smbc_set_context.restype = SMBC.CTXptr
smbc.smbc_set_context.argtypes = (SMBC.CTXptr,)

smbc.smbc_open.restype = ct.c_int
smbc.smbc_open.argtypes = (ct.c_char_p, ct.c_int, SMBC.c_mode_t)
smbc.smbc_creat.restype = ct.c_int
smbc.smbc_creat.argtypes = (ct.c_char_p, SMBC.c_mode_t)
smbc.smbc_read.restype = ct.c_ssize_t
smbc.smbc_read.argtypes = (ct.c_int, ct.c_void_p, ct.c_size_t)
smbc.smbc_write.restype = ct.c_ssize_t
smbc.smbc_write.argtypes = (ct.c_int, ct.c_void_p, ct.c_size_t)
smbc.smbc_lseek.restype = SMBC.c_off_t
smbc.smbc_lseek.argtypes = (ct.c_int, SMBC.c_off_t, ct.c_int)
smbc.smbc_close.restype = ct.c_int
smbc.smbc_close.argtypes = (ct.c_int,)
smbc.smbc_unlink.restype = ct.c_int
smbc.smbc_unlink.argtypes = (ct.c_char_p,)
smbc.smbc_rename.restype = ct.c_int
smbc.smbc_rename.argtypes = (ct.c_char_p, ct.c_char_p)

smbc.smbc_opendir.restype = ct.c_int
smbc.smbc_opendir.argtypes = (ct.c_char_p,)
smbc.smbc_closedir.restype = ct.c_int
smbc.smbc_closedir.argtypes = (ct.c_int,)
smbc.smbc_getdents.restype = ct.c_int
smbc.smbc_getdents.argtypes = (ct.c_uint, ct.POINTER(SMBC.dirent), ct.c_int)
smbc.smbc_readdir.restype = ct.POINTER(SMBC.dirent)
smbc.smbc_readdir.argtypes = (ct.c_uint,)
if hasattr(smbc, "smbc_readdirplus") :
    smbc.smbc_readdirplus.restype = ct.POINTER(SMBC.file_info)
    smbc.smbc_readdirplus.argtypes = (ct.c_uint,)
#end if
smbc.smbc_telldir.restype = SMBC.c_off_t
smbc.smbc_telldir.argtypes = (ct.c_int,)
smbc.smbc_lseekdir.restype = ct.c_int
smbc.smbc_lseekdir.argtypes = (ct.c_int, SMBC.c_off_t)
smbc.smbc_mkdir.restype = ct.c_int
smbc.smbc_mkdir.argtypes = (ct.c_char_p, SMBC.c_mode_t)

smbc.smbc_notify.restype = ct.c_int
smbc.smbc_notify.argtypes = (ct.c_int, SMBC.bool, ct.c_uint, ct.c_uint, SMBC.notify_callback_fn, ct.c_void_p)
smbc.smbc_stat.restype = ct.c_int
smbc.smbc_stat.argtypes = (ct.c_char_p, ct.POINTER(SMBC.c_stat_t))
smbc.smbc_fstat.restype = ct.c_int
smbc.smbc_fstat.argtypes = (ct.c_int, ct.POINTER(SMBC.c_stat_t))
smbc.smbc_statvfs.restype = ct.c_int
smbc.smbc_statvfs.argtypes = (ct.c_char_p, ct.POINTER(SMBC.c_statvfs_t))
smbc.smbc_fstatvfs.restype = ct.c_int
smbc.smbc_fstatvfs.argtypes = (ct.c_int, ct.POINTER(SMBC.c_statvfs_t))
smbc.smbc_ftruncate.restype = ct.c_int
smbc.smbc_ftruncate.argtypes = (ct.c_int, SMBC.c_off_t)
smbc.smbc_chmod.restype = ct.c_int
smbc.smbc_chmod.argtypes = (ct.c_char_p, SMBC.c_mode_t)
smbc.smbc_utimes.restype = ct.c_int
smbc.smbc_utimes.argtypes = (ct.c_char_p, SMBC.c_utimbuf_t)
smbc.smbc_utime.restype = ct.c_int
smbc.smbc_utime.argtypes = (ct.c_int, ct.POINTER(SMBC.c_utimbuf_t))

smbc.smbc_setxattr.restype = ct.c_int
smbc.smbc_setxattr.argtypes = (ct.c_char_p, ct.c_char_p, ct.c_void_p, ct.c_size_t, ct.c_int)
smbc.smbc_lsetxattr.restype = ct.c_int
smbc.smbc_lsetxattr.argtypes = (ct.c_char_p, ct.c_char_p, ct.c_void_p, ct.c_size_t, ct.c_int)
smbc.smbc_fsetxattr.restype = ct.c_int
smbc.smbc_fsetxattr.argtypes = (ct.c_int, ct.c_char_p, ct.c_void_p, ct.c_size_t, ct.c_int)
smbc.smbc_getxattr.restype = ct.c_int
smbc.smbc_getxattr.argtypes = (ct.c_char_p, ct.c_char_p, ct.c_void_p, ct.c_size_t)
smbc.smbc_lgetxattr.restype = ct.c_int
smbc.smbc_lgetxattr.argtypes = (ct.c_char_p, ct.c_char_p, ct.c_void_p, ct.c_size_t)
smbc.smbc_fgetxattr.restype = ct.c_int
smbc.smbc_fgetxattr.argtypes = (ct.c_int, ct.c_char_p, ct.c_void_p, ct.c_size_t)
smbc.smbc_removexattr.restype = ct.c_int
smbc.smbc_removexattr.argtypes = (ct.c_char_p, ct.c_char_p)
smbc.smbc_lremovexattr.restype = ct.c_int
smbc.smbc_lremovexattr.argtypes = (ct.c_char_p, ct.c_char_p)
smbc.smbc_fremovexattr.restype = ct.c_int
smbc.smbc_fremovexattr.argtypes = (ct.c_int, ct.c_char_p)
smbc.smbc_listxattr.restype = ct.c_int
smbc.smbc_listxattr.argtypes = (ct.c_char_p, ct.c_char_p, ct.c_size_t)
smbc.smbc_llistxattr.restype = ct.c_int
smbc.smbc_llistxattr.argtypes = (ct.c_char_p, ct.c_char_p, ct.c_size_t)
smbc.smbc_flistxattr.restype = ct.c_int
smbc.smbc_flistxattr.argtypes = (ct.c_int, ct.c_char_p, ct.c_size_t)

smbc.smbc_print_file.restype = ct.c_int
smbc.smbc_print_file.argtypes = (ct.c_char_p, ct.c_char_p)
smbc.smbc_open_print_job.restype = ct.c_int
smbc.smbc_open_print_job.argtypes = (ct.c_char_p,)
smbc.smbc_list_print_jobs.restype = ct.c_int
smbc.smbc_list_print_jobs.argtypes = (ct.c_char_p, SMBC.list_print_job_fn)
smbc.smbc_unlink_print_job.restype = ct.c_int
smbc.smbc_unlink_print_job.argtypes = (ct.c_char_p, ct.c_int)

if hasattr(smbc, "smbc_remove_unused_server") :
    smbc.smbc_remove_unused_server.restype = ct.c_int
    smbc.smbc_remove_unused_server.argtypes = (SMBC.CTXptr, SMBC.SRVptr)
#end if
smbc.smbc_urldecode.restype = ct.c_int
smbc.smbc_urldecode.argtypes = (ct.c_char_p, ct.c_char_p, ct.c_size_t)
smbc.smbc_urlencode.restype = ct.c_int
smbc.smbc_urlencode.argtypes = (ct.c_char_p, ct.c_char_p, ct.c_size_t)

smbc.smbc_version.restype = ct.c_char_p
smbc.smbc_version.argtypes = ()

# smbc_set_credentials is obsolete
smbc.smbc_set_credentials_with_fallback.restype = None
smbc.smbc_set_credentials_with_fallback.argtypes = (SMBC.CTXptr, ct.c_char_p, ct.c_char_p, ct.c_char_p)

if hasattr(smbc, "smbc_thread_posix") :
    smbc.smbc_thread_posix.restype = None
    smbc.smbc_thread_posix.argtypes = ()
    smbc.smbc_thread_impl.restype = None
    smbc.smbc_thread_impl.argtypes = (SMBC.create_mutex_fn, SMBC.destroy_mutex_fn, SMBC.lock_mutex_fn, SMBC.create_tls_fn, SMBC.destroy_tls_fn, SMBC.set_tls_fn, SMBC.get_tls_fn)
#end if

#+
# Higher-level stuff begins here
#-

class SMBError(Exception) :
    "exception raised when libsmbclient returns an error." \
    " Note that errno is expected to be set."

    def __init__(self, doing_what) :
        self.errno = ct.get_errno()
        self.doing_what = doing_what
        self.args = ("libsmbclient error %d %s -- %s" % (self.errno, doing_what, os.strerror(self.errno)),)
    #end __init__

#end SMBError

class FBytes :
    "a container for a bytes string which can be variable-length" \
    " up to a maximum. The maximum includes the trailing null."

    __slots__ = ("_val", "max") # to forestall typos

    def __init__(self, init, max) :
        self.max = max
        self.value = init # let prop setter validate it
    #end __init__

    @property
    def value(self) :
        "the value without the trailing null."
        return \
            self._val[:-1]
    #end value

    @value.setter
    def value(self, val) :
        if isinstance(val, bytes) :
            pass
        elif isinstance(val, bytearray) or isinstance(val, array.array) and val.typecode == "B" :
            val = bytes(val)
        elif isinstance(val, str) :
            val = val.encode()
        elif isinstance(val, ct.POINTER(ct.c_char)) :
            val = ct.cast(val, ct.c_char_p).value
        else :
            raise TypeError("val must be a bytes, bytearray or array.array of bytes")
        #end if
        if val.find(0) >= 0 :
            raise ValueError("value cannot contain nulls")
        #end if
        if len(val) >= self.max :
            raise ValueError("value cannot exceed %d bytes" % (self.max - 1))
        #end if
        self._val = val + b"\0"
    #end value

    def store(self, dst, max) :
        assert max == self.max
        typ = len(self._val) * ct.c_char
        dest = ct.cast(dst, ct.POINTER(typ))
        dest[0].value = self._val
    #end store

    def __repr__(self) :
        return \
            "FBytes[%d](%s)" % (self.max, repr(self._val))
    #end __repr__

#end FBytes

_WorkQueueEntry = namedtuple("_WorkQueueEntry", ("func", "args", "done_fute"))

def encode_str0(s) :
    if isinstance(s, str) :
        c_s = s.encode()
    elif isinstance(s, (bytes, bytearray)) :
        c_s = bytes(s)
    else :
        raise TypeError("not a bytes or str: (%s) %s" % (type(s).__name__, repr(s)))
    #end if
    if c_s.find(0) >= 0 :
        raise ValueError("value cannot contain nulls")
    #end if
    return \
        c_s + b'\0'
#end encode_str0

def decode_bytes0(b, decode) :
    if decode :
        b = b.decode()
    else :
        endpos = b.find(0)
        if endpos >= 0 :
            b = b[:endpos]
        #end if
    #end if
    return \
        b
#end decode_bytes0

def decode_timespec(t) :
    "decodes a c_timespec_t into integer nanoseconds."
    return \
        t.tv_sec * BILLION + t.tv_nsec
#end decode_timespec

def _decode_dirent(adr, decode_bytes) :
    de = ct.cast(adr, ct.POINTER(SMBC.dirent)).contents
    if de.comment != None :
        comment = bytes(ct.cast(de.comment, ct.POINTER(de.commentlen * ct.c_char)).contents)
    else :
        comment = None
    #end if
    name = bytes(ct.cast(adr + SMBC.direntsize, ct.POINTER(de.namelen * ct.c_char)).contents)
    dirent = Dirent \
      (
        smbc_type = de.smbc_type,
        comment = decode_bytes0(comment, decode_bytes),
        name = decode_bytes0(name, decode_bytes)
      )
    return \
        dirent, de.dirlen
#end _decode_dirent

class Context :
    "a libsmbclient context. Do not instantiate directly; use the create or" \
    " get/set_current methods.\n" \
    "\n" \
    "Note on async calls: these are serialized on a single worker thread per Context." \
    " This is to avoid thread-safeness issues across async calls. Do not mix sync and" \
    " async calls on the same Context."

    __slots__ = \
        ( # to forestall typos
            "_smbobj",
            "decode_bytes",
            "simple_auth",
            "loop",
            "__weakref__",
            "_worker_thread",
            "_work_queue",
            "_function_auth_data",
            "_function_auth_data_with_context",
            # need to keep references to ctypes-wrapped functions
            # so they don't disappear prematurely:
            "_wrap_function_auth_data",
            "_wrap_function_auth_data_with_context",
        )

    _instances = WeakValueDictionary()

    class SimpleAuthEntry :
        "a simple table-driven mechanism for managing authentication information," \
        " as an alternative to specifying your own general callback. Keys in" \
        " the dict are («server», «share»), («server», None) or (None, None) tuples," \
        " and entries are («workgroup», «username», «password») tuples, where any of" \
        " the components can be None. A key of («server», None), if defined, is used as" \
        " a fallback if there is no specific entry for a particular («server», «share»)," \
        " while (None, None) will be used as a final fallback if specified and there is" \
        " no entry or fallback for a particular («server», «whatever»)."

        def __init__(self, parent) :
            self._entries = {}
            self._w_parent = weak_ref(parent)
        #end __init__

        @staticmethod
        def validate_key(key) :
            valid = True # to begin with
            if key == None :
                key = (None, None)
            elif isinstance(key, (bytes, bytearray, str)) :
                key = (encode_str0(key)[:-1], None)
            elif isinstance(key, tuple) and len(key) == 2 :
                if (
                        isinstance(key[0], (bytes, bytearray, str))
                    and
                        (key[1] == None or isinstance(key[1], (bytes, bytearray, str)))
                ) :
                    key = \
                        (
                            encode_str0(key[0])[:-1],
                            (lambda : None, lambda : encode_str0(key[1])[:-1])[key[1] != None]()
                        )
                elif key != (None, None) :
                    valid = False
                #end if
            else :
                valid = False
            #end if
            if not valid :
                raise TypeError \
                  (
                    "key for SimpleAuthEntry must be bytes/str/None or 2-tuple"
                    " (bytes/str, bytes/str/None) or (None, None)"
                  )
            #end if
            return \
                key
        #end validate_key

        def __getitem__(self, key) :
            key = self.validate_key(key)
            if key in self._entries :
                result = self._entries[key]
            elif key[1] != None and (key[0], None) in self._entries :
                result = self._entries[key[0], None]
            elif key[0] != None and (None, None) in self._entries :
                result = self._entries[None, None]
            else :
                result = (None, None, None)
            #end if
            return \
                result
        #end __getitem__

        def __setitem__(self, key, value) :
            parent = _wderef(self._w_parent, "Context")
            key = self.validate_key(key)
            if value == None :
                value = (None, None, None)
            elif (
                    not isinstance(value, tuple)
                or
                    len(value) != 3
                or
                    not all(isinstance(e, (bytes, bytearray, str, type(None))) for e in value)
            ) :
                raise TypeError("auth entry value must be 3-tuple of bytes/str/None")
            #end if
            if value != (None, None, None) :
                value = tuple((lambda : None, lambda : encode_str0(v)[:-1])[v != None]() for v in value)
                self._entries[key] = value
                parent.function_auth_data = self.do_auth
            else :
                self._entries.pop(key, None)
            #end if
        #end __setitem__

        def __contains__(self, key) :
            return \
                self.__getitem(self.validate_key(key)) != (None, None, None)
        #end __contains__

        def __delitem__(self, key) :
            key = self.validate_key(key)
            self._entries.__delitem__(key)
        #end __delitem__

        def __len__(self) :
            return \
                self._entries.__len__()
        #end __len__

        def __repr__(self) :
            return \
                self._entries.__repr__()
        #end __repr__

        def do_auth(self, server, share, workgroup, username, password) :
            parent = _wderef(self._w_parent, "Context")
            use_workgroup, use_username, use_password = self[server, share]
            if use_workgroup != None :
                workgroup.value = use_workgroup
            #end if
            if use_username != None :
                username.value = use_username
            #end if
            if use_password != None :
                password.value = use_password
            #end if
        #end do_auth

    #end SimpleAuthEntry

    def __new__(celf, _smbobj) :
        self = celf._instances.get(_smbobj)
        if self == None :
            self = super().__new__(celf)
            self._smbobj = _smbobj
            self.decode_bytes = True
            self.simple_auth = celf.SimpleAuthEntry(self)
            self._worker_thread = None
            self._work_queue = None
            self.loop = None
            self._wrap_function_auth_data = None
            self._wrap_function_auth_data_with_context = None
            self._function_auth_data = None
            self._function_auth_data_with_context = None
            celf._instances[_smbobj] = self
        #end if
        return \
            self
    #end __new__

    @classmethod
    def create(celf, init = True) :
        "creates and initializes a new Context."
        _smbobj = smbc.smbc_new_context()
        if _smbobj == None :
            raise SMBError("creating new Context")
        #end if
        if init :
            _smbobj = smbc.smbc_init_context(_smbobj)
            if _smbobj == None :
                raise SMBError("initing new Context")
            #end if
        #end if
        return \
            celf(_smbobj)
    #enc create

    def init(self) :
        "separate initialization call if you didn’t want to init as part of the create call."
        _smbobj = smbc.smbc_init_context(self._smbobj)
        if _smbobj == None :
            raise SMBError("initing Context")
        #end if
        assert self._smbobj == _smbobj
        return \
            self
    #end init

    # TODO: setLogCallback

    if hasattr(smbc, "smbc_setConfiguration") :

        def set_configuration(self, conffile) :
            c_conffile = encode_str0(conffile)
            if smbc.smbc_setConfiguration(self._smbobj, c_conffile) < 0 :
                raise SMBError("loading config file")
            #end if
            return \
                self
        #end set_configuration

    #end if

    if hasattr(smbc, "smbc_setOptionProtocols") :

        def set_option_protocols(self, min_proto = None, max_proto = None) :
            if min_proto != None :
                c_min_proto = encode_str0(min_proto)
            else :
                c_min_proto = None
            #end if
            if max_proto != None :
                c_max_proto = encode_str0(max_proto)
            else :
                c_max_proto = None
            #end if
            if smbc.smbc_setOptionProtocols(self._smbobj, c_min_proto, c_max_proto) == 0 :
                raise SMBError("setting protocols option")
            #end if
            return \
                self
        #end set_option_protocols

    #end if

    def _process_work_queue(w_self) :

        work_queue = _wderef(w_self, "Context")._work_queue

        def return_result(w_done_fute, result) :
            done_fute = w_done_fute()
            if done_fute != None and not done_fute.done() :
                done_fute.set_result(result)
            #end if
        #end return_result

        def return_exception(w_done_fute, fail) :
            done_fute = w_done_fute()
            if done_fute != None and not done_fute.done() :
                done_fute.set_exception(fail)
            #end if
        #end return_exception

    #begin _process_work_queue
        while True :
            entry = work_queue.get()
            if entry.func == None :
                # end-of-work indicator
                break
            try :
                result = entry.func(*entry.args)
            except Exception as fail :
                _wderef(w_self, "Context") \
                    .loop.call_soon_threadsafe(return_exception, weak_ref(entry.done_fute), fail)
            else :
                _wderef(w_self, "Context") \
                    .loop.call_soon_threadsafe(return_result, weak_ref(entry.done_fute), result)
            #end try
        #end while
    #end _process_work_queue

    def enable_async_calls(self, loop = None) :
        if loop == None :
            loop = asyncio.get_event_loop()
        #end if
        if self._work_queue == None :
            self.loop = loop
            self._work_queue = queue.SimpleQueue()
              # needs to be thread-safe -- used for passing requests to
              # worker thread
            self._worker_thread = threading.Thread \
              (
                target = type(self)._process_work_queue,
                args = (weak_ref(self),),
              )
            self._worker_thread.start()
        else :
            assert self.loop == loop
        #end if
    #end enable_async_calls

    def _call_async(self, func, args) :
        assert self.loop != None, "enable_async_calls not called"
        entry = _WorkQueueEntry \
          (
            func = func,
            args = args,
            done_fute = self.loop.create_future(),
          )
        self._work_queue.put(entry)
        return \
            entry.done_fute
    #end _call_async

    def __del__(self) :
        if self._smbobj != None :
            if self._work_queue != None :
                self._work_queue.put(_WorkQueueEntry(func = None, args = None, done_fute = None))
            #end if
            smbc.smbc_free_context(self._smbobj, 1)
            self._smbobj = None
        #end if
    #end __del__

    def close(self, shutdown_ctx) :
        if self._smbobj != None :
            if self._work_queue != None :
                # queue indication for worker thread to shut down
                self._work_queue.put(_WorkQueueEntry(func = None, args = None, done_fute = None))
                self._worker_thread.join()
            #end if
            if smbc.smbc_free_context(self._smbobj, shutdown_ctx) != 0 :
                raise SMBError("closing Context")
            #end if
            self._smbobj = None
        #end if
    #end close

    def set_credentials_with_fallback(self, workgroup, user, password) :
        c_workgroup = encode_str0(workgroup)
        c_user = encode_str0(user)
        c_password = encode_str0(password)
        smbc.smbc_set_credentials_with_fallback(self._smbobj, c_workgroup, c_user, c_password)
    #end set_credentials_with_fallback

    def set_current(self) :
        "sets this Context as the global current Context. Also" \
        " returns the previously-current Context."
        return \
            type(self)(smbc.smbc_set_context(self._smbobj))
    #end set_current

    @classmethod
    def get_current(celf) :
        "retrieves the current global Context."
        return \
            type(self)(smbc.smbc_set_context(None))
    #end get_current

    def open(self, fname, flags, mode) :
        c_fname = encode_str0(fname)
        file_smbobj = smbc.smbc_getFunctionOpen(self._smbobj)(self._smbobj, c_fname, flags, mode)
        if file_smbobj == None :
            raise SMBError("opening File %s" % repr(fname))
        #end if
        return \
            File(file_smbobj, self)
    #end open

    def open_async(self, fname, flags, mode) :
        return \
            self._call_async(self.open, (fname, flags, mode))
    #end open_async

    def creat(self, fname, mode) :
        c_fname = encode_str0(fname)
        file_smbobj = smbc.smbc_getFunctionCreat(self._smbobj)(self._smbobj, c_fname, mode)
        if file_smbobj == None :
            raise SMBError("creating File %s" % repr(fname))
        #end if
        return \
            File(file_smbobj, self)
    #end creat

    def creat_async(self, fname, mode) :
        return \
            self._call_async(self.creat, (fname, mode))
    #end creat_async

    def opendir(self, fname) :
        c_fname = encode_str0(fname)
        file_smbobj = smbc.smbc_getFunctionOpendir(self._smbobj)(self._smbobj, c_fname)
        if file_smbobj == None :
            raise SMBError("opening directory File %s" % repr(fname))
        #end if
        return \
            Directory(file_smbobj, self)
    #end opendir

    def opendir_async(self, fname) :
        return \
            self._call_async(self.opendir, (fname,))
    #end opendir_async

    def open_print_job(self, fname) :
        c_fname = encode_str0(fname)
        file_smbobj = smbc.smbc_getFunctionOpenPrintJob(self._smbobj)(self._smbobj, c_fname)
        if file_smbobj == None :
            raise SMBError("opening print job %s" % repr(fname))
        #end if
        return \
            File(file_smbobj, self)
    #end open_print_job

    def open_print_job_async(self, fname) :
        return \
            self._call_async(self.open_print_job, (fname,))
    #end open_print_job_async

    def unlink(self, fname) :
        c_fname = encode_str0(fname)
        if smbc.smbc_getFunctionUnlink(self._smbobj)(self._smbobj, c_fname) != 0 :
            raise SMBError("unlinking file %s" % repr(fname))
        #end if
    #end unlink

    def unlink_async(self, fname) :
        return \
            self._call_async(self.unlink, (fname,))
    #end unlink_async

    def rename(self, oname, other, nname) :
        if not isinstance(other, Context) :
            raise TypeError("other must be a Context")
        #end if
        c_oname = encode_str0(oname)
        c_nname = encode_str0(nname)
        if smbc.smbc_getFunctionRename(self._smbobj)(self._smbobj, c_oname, other._smbobj, c_nname) != 0 :
            raise SMBError("renaming %s to %s" % (repr(oname), repr(nname)))
        #end if
    #end rename

    def rename_async(self, oname, other, nname) :
        return \
            self._call_async(self.rename, (oname, other, nname))
    #end rename_async

    def stat(self, fname) :
        info = SMBC.c_stat_t()
        c_fname = encode_str0(fname)
        if smbc.smbc_getFunctionStat(self._smbobj)(self._smbobj, c_fname, ct.byref(info)) != 0 :
            raise SMBError("statting file")
        #end if
        return \
            StructStat \
              (*(
                (lambda x : x, decode_timespec)[f[0].endswith("tim")](getattr(info, f[0]))
                for f in SMBC.c_stat_t._fields_
                if not f[0].startswith("Ṕ")
              ))
    #end stat

    def stat_async(self, fname) :
        return \
            self._call_async(self.stat, (fname,))
    #end stat_async

    def statvfs(self, fname) :
        info = SMBC.c_statvfs_t()
        c_fname = encode_str0(fname)
        if smbc.smbc_getFunctionStatVFS(self._smbobj)(self._smbobj, c_fname, ct.byref(info)) != 0 :
            raise SMBError("statting VFS")
        #end if
        return \
            StructStatVFS \
              (*(
                getattr(info, f[0])
                for f in SMBC.c_statvfs_t._fields_
                if not f[0].startswith("Ṕ")
              ))
    #end statvfs

    def statvfs_async(self, fname) :
        return \
            self._call_async(self.statvfs, (fname,))
    #end statvfs_async

    def mkdir(self, fname, mode) :
        c_fname = encode_str0(fname)
        if smbc.smbc_getFunctionMkdir(self._smbobj)(self._smbobj, c_fname, mode) != 0 :
            raise SMBError("creating directory %s" % repr(fname))
        #end if
    #end mkdir

    def mkdir_async(self, fname, mode) :
        return \
            self._call_async(self.mkdir, (fname, mode))
    #end mkdir_async

    def rmdir(self, fname) :
        c_fname = encode_str0(fname)
        if smbc.smbc_getFunctionRmdir(self._smbobj)(self._smbobj, c_fname) != 0 :
            raise SMBError("removing directory %s" % repr(fname))
        #end if
    #end rmdir

    def rmdir_async(self, fname) :
        return \
            self._call_async(self.rmdir, (fname,))
    #end rmdir_async

    def chmod(self, fname, mode) :
        c_fname = encode_str0(fname)
        if smbc.smbc_getFunctionChmod(self._smbobj)(self._smbobj, c_fname, mode) != 0 :
            raise SMBError("changing mode on %s" % repr(fname))
        #end if
    #end chmod

    def chmod_async(self, fname, mode) :
        return \
            self._call_async(self.chmod, (fname, mode))
    #end chmod_async

    def utimes(self, fname, actime, modtime) :
        "sets the (last-access, modification) times tuple as integer microseconds."
        c_fname = encode_str0(fname)
        info = SMBC.c_utimbuf_t()
        info.actime.tv_sec = actime // MILLION
        info.actime.tv_usec = actime % MILLION
        info.modtime.tv_sec = modtime // MILLION
        info.modtime.tv_usec = modtime % MILLION
        if smbc.smbc_getFunctionUtimes(self._smbobj)(self._smbobj, c_fname, ct.byref(info)) != 0 :
            raise SMBError("setting utimes on %s" % repr(fname))
        #end if
    #end utimes

    def utimes_async(self, fname, actime, modtime) :
        return \
            self._call_async(self.utimes, (fname, actime, modtime))
    #end utimes_async

    def setxattr(self, fname, name, value, flags) :
        c_fname = encode_str0(fname)
        c_name = encode_str0(name)
        valuelen = len(value)
        if isinstance(value, str) :
            value = value.encode()
        #end if
        if isinstance(value, bytes) :
            valueadr = ct.cast(value, ct.c_void_p).value
        elif isinstance(value, bytearray) or isinstance(value, array.array) and value.typecode == "B" :
            valueadr = ct.addressof((ct.c_ubyte * 0).from_buffer(value))
        else :
            raise TypeError("value is not bytes, bytearray or array.array of bytes")
        #end if
        if smbc.smbc_getFunctionSetxattr(self._smbobj)(self._smbobj, c_fname, c_name, valueadr, valuelen, flags) != 0 :
            raise SMBError("setting xattr %s on %s" % (repr(name), repr(fname)))
        #end if
    #end setxattr

    def setxattr_async(self, fname, name, value, flags) :
        return \
            self._call_async(self.setxattr, (fname, name, value, flags))
    #end setxattr_async

    def getxattr(self, fname, name) :
        "returns None if attribute is valid, but item has no value for it."
        c_fname = encode_str0(fname)
        c_name = encode_str0(name)
        func = smbc.smbc_getFunctionGetxattr(self._smbobj)
        bufsize = func(self._smbobj, c_fname, c_name, None, 0)
        if bufsize < 0 :
            if ct.get_errno() == errno.ENODATA :
                bufsize = None
            else :
                raise SMBError("getting size of value of xattr %s for %s" % (repr(name), repr(fname)))
            #end if
        #end if
        if bufsize != None :
            buf = bytearray(bufsize)
            if func(self._smbobj, c_fname, c_name, ct.addressof((ct.c_ubyte * bufsize).from_buffer(buf)), bufsize) < 0 :
                raise SMBError("getting value of xattr %s for %s" % (repr(name), repr(fname)))
            #end if
            result = decode_bytes0(bytes(buf), self.decode_bytes)
        else :
            result = None
        #end if
        return \
            result
    #end getxattr

    def getxattr_async(self, fname, name) :
        return \
            sellf._call_async(self, (fname, name))
    #end getxattr_async

    def removexattr(self, fname, name) :
        c_fname = encode_str0(fname)
        c_name = encode_str0(name)
        if smbc.smbc_getFunctionRemovexattr(self._smbobj)(self._smbobj, c_fname, c_name) != 0 :
            raise SMBError("removing xattr %s on %s" % (repr(name), repr(fname)))
        #end if
    #end removexattr

    def removexattr_async(self, fname, name) :
        return \
            self._call_async(self.removexattr, (fname, name))
    #end removexattr_async

    def listxattr(self, fname) :
        "generator which yields names of all supported attribute names in turn."
        c_fname = encode_str0(fname)
        func = smbc.smbc_getFunctionListxattr(self._smbobj)
        bufsize = func(self._smbobj, c_fname, None, 0)
        if bufsize < 0 :
            raise SMBError("getting size of xattr names list for %s" % repr(fname))
        #end if
        buf = bytearray(bufsize)
        if func(self._smbobj, c_fname, ct.addressof((ct.c_ubyte * bufsize).from_buffer(buf)), bufsize) < 0 :
            raise SMBError("listing xattr names for %s" % repr(fname))
        #end if
        while True :
            pos = buf.find(0)
            if pos <= 0 : # ignore trailing empty entry
                break
            yield decode_bytes0(buf[:pos], self.decode_bytes)
            buf = buf[pos + 1:]
        #end while
    #end listxattr

    # not bothering to provide listxattr_async, since listattr
    # is implemented entirely within libsmbclient.

    def list_print_jobs(self, fname) :
        "returns a list of info about all print jobs matching fname."
        # having to use a callback means I cannot make it a generator, so I return
        # all results at once.

        result = []

        @SMBC.list_print_job_fn
        def print_job_action(c_info) :
            info = PrintJobInfo \
              (
                id = c_info.id,
                priority = c_info.priority,
                size = c_info.size,
                user = decode_bytes0(c_info.user, self.decode_bytes),
                name = decode_bytes0(c_info.name, self.decode_bytes),
                t = c_info.t,
              )
            result.append(info)
        #end print_job_action

    #begin list_print_jobs
        c_fname = encode_str0(fname)
        if smbc.smbc_getFunctionListPrintJobs(self._smbobj)(self._smbobj, c_fname, print_job_action) != 0 :
            raise SMBError("listing print jobs for %s" % repr(fname))
        #end if
        return \
            result
    #end list_print_jobs

    def list_print_jobs_async(self, fname) :
        return \
            self._call_async(self.list_print_jobs, (fname,))
    #end list_print_jobs_async

    def unlink_print_job(self, fname, id) :
        c_fname = encode_str0(fname)
        if smbc.smbc_getFunctionUnlinkPrintJob(self._smbobj)(self._smbobj, c_fname, id) != 0 :
            raise SMBError("unlinking print job %s id %d" % (repr(fname), id))
        #end if
    #end unlink_print_job

    def unlink_print_job_async(self, fname, id) :
        return \
            self._call_async(self.unlink_print_job, (fname, id))
    #end unlink_print_job_async

    def flush_async(self) :
        "waits until all prior queued async operations have completed."
        return \
            self._call_async(lambda x : None, ())
    #end flush_async

#end Context
def def_context_extra(Context) :

    def def_simple_method(name, funcname) :

        getfunc = getattr(smbc, "smbc_get" + funcname)
        setfunc = getattr(smbc, "smbc_set" + funcname)
        setter_name = "set_" + name

        def prop_getter(self) :
            return \
                getfunc(self._smbobj)
        #end prop_getter

        def prop_setter(self, val) :
            getattr(self, setter_name)(val)
        #end prop_setter

        def setter(self, val) :
            setfunc(self._smbobj, val)
            return \
                self
        #end setter

    #begin def_simple_method
        prop_getter.__name__= name
        prop_getter.__doc__ = "the current %s setting." % funcname
        prop_setter.__name__= name
        setter.__name__= setter_name
        setter.__doc__ = \
            (
                    "sets a new value for %s. Use for method chaining; otherwise, it’s"
                    " probably more convenient to assign to the %s property."
                %
                    (funcname, name)
            )
        setattr(Context, name, property(prop_getter, prop_setter))
        setattr(Context, setter_name, setter)
    #end def_simple_method

    def def_bool_method(name, funcname) :

        getfunc = getattr(smbc, "smbc_get" + funcname)
        setfunc = getattr(smbc, "smbc_set" + funcname)
        setter_name = "set_" + name

        def prop_getter(self) :
            return \
                getfunc(self._smbobj) != 0
        #end prop_getter

        def prop_setter(self, val) :
            getattr(self, setter_name)(val)
        #end prop_setter

        def setter(self, val) :
            if not isinstance(val, bool) :
                raise TypeError("new value must be a bool")
            #end if
            setfunc(self._smbobj, int(val))
            return \
                self
        #end setter

    #begin def_bool_method
        prop_getter.__name__= name
        prop_getter.__doc__ = "the current %s setting." % funcname
        prop_setter.__name__= name
        setter.__name__= setter_name
        setter.__doc__ = \
            (
                    "sets a new value for %s. Use for method chaining; otherwise, it’s"
                    " probably more convenient to assign to the %s property."
                %
                    (funcname, name)
            )
        setattr(Context, name, property(prop_getter, prop_setter))
        setattr(Context, setter_name, setter)
    #end def_bool_method

    def def_str_method(name, funcname) :

        getfunc = getattr(smbc, "smbc_get" + funcname)
        setfunc = getattr(smbc, "smbc_set" + funcname)
        setter_name = "set_" + name

        def prop_getter(self) :
            return \
                decode_bytes0(getfunc(self._smbobj), self.decode_bytes)
        #end prop_getter

        def prop_setter(self, val) :
            getattr(self, setter_name)(val)
        #end prop_setter

        def setter(self, val) :
            c_val = encode_str0(val)
            setfunc(self._smbobj, c_val)
            return \
                self
        #end setter

    #begin def_str_method
        prop_getter.__name__= name
        prop_getter.__doc__ = "the current %s setting." % funcname
        prop_setter.__name__= name
        setter.__name__= setter_name
        setter.__doc__ = \
            (
                    "sets a new value for %s. Use for method chaining; otherwise, it’s"
                    " probably more convenient to assign to the %s property."
                %
                    (funcname, name)
            )
        setattr(Context, name, property(prop_getter, prop_setter))
        setattr(Context, setter_name, setter)
    #end def_str_method

    def def_wrap_auth_data_fn(fn) :

        @SMBC.get_auth_data_fn
        def wrap_auth_data_fn(c_srv, c_shr, c_wg, wglen, c_un, unlen, c_pw, pwlen) :
            wg = FBytes(c_wg, wglen)
            un = FBytes(c_un, unlen)
            pw = FBytes(c_pw, pwlen)
            fn(bytes(c_srv), bytes(c_shr), wg, un, pw)
            wg.store(c_wg, wglen)
            un.store(c_un, unlen)
            pw.store(c_pw, pwlen)
        #end wrap_auth_data_fn

    #begin def_wrap_auth_data_fn
        return \
            wrap_auth_data_fn
    #end def_wrap_auth_data_fn

    def def_wrap_auth_data_with_context_fn(fn) :

        @SMBC.get_auth_data_with_context_fn
        def wrap_auth_data_with_context_fn(c_ctx, c_srv, c_shr, c_wg, wglen, c_un, unlen, c_pw, pwlen) :
            ctx = Context(c_ctx)
            wg = FBytes(c_wg, wglen)
            un = FBytes(c_un, unlen)
            pw = FBytes(c_pw, pwlen)
            fn(ctx, bytes(c_srv), bytes(c_shr), wg, un, pw)
            wg.store(c_wg, wglen)
            un.store(c_un, unlen)
            pw.store(c_pw, pwlen)
        #end wrap_auth_data_with_context_fn

    #begin def_wrap_auth_data_with_context_fn
        return \
            wrap_auth_data_fn
    #end def_wrap_auth_data_with_context_fn

    def def_callback_method(name, funcname, def_wrap, details) :

        getfunc = getattr(smbc, "smbc_get" + funcname)
        setfunc = getattr(smbc, "smbc_set" + funcname)
        setter_name = "set_" + name
        attr_name = "_" + name # attribute to hold caller-specified function
        wrap_attr_name = "_wrap_" + name # attribute to save reference to wrapped function

        def prop_getter(self) :
            return \
                getattr(self, attr_name)
        #end prop_getter

        def prop_setter(self, val) :
            getattr(self, setter_name)(val)
        #end prop_setter

        def setter(self, val) :
            if val != None :
                wrap_val = def_wrap(val)
            else :
                wrap_val = None
            #end if
            setattr(self, attr_name, val)
            setattr(self, wrap_attr_name, wrap_val)
            setfunc(self._smbobj, wrap_val)
            return \
                self
        #end setter

    #begin def_callback_method
        prop_getter.__name__= name
        prop_getter.__doc__ = \
            (
                "the current %(funcname)s callback. This should be a"
                " function of the form:\n\n    %(details)s"
            %
                {
                    "funcname" : funcname,
                    "details" : details,
                }
            )
        prop_setter.__name__= name
        setter.__name__= setter_name
        setter.__doc__ = \
            (
                    "sets a new value for %s. Use for method chaining; otherwise, it’s"
                    " probably more convenient to assign to the %s property."
                %
                    (funcname, name)
            )
        setattr(Context, name, property(prop_getter, prop_setter))
        setattr(Context, setter_name, setter)
    #end def_callback_method

#begin def_context_extra
    for name, funcname in \
        (
            ("option_debug_to_stderr", "OptionDebugToStderr"),
            ("option_full_time_names", "OptionFullTimeNames"),
            ("option_case_sensitive", "OptionCaseSensitive"),
            ("option_urlencode_readdir_entries", "OptionUrlEncodeReaddirEntries"),
            ("option_one_share_per_server", "OptionOneSharePerServer"),
            ("option_use_kerberos", "OptionUseKerberos"),
            ("option_fallback_after_kerberos", "OptionFallbackAfterKerberos"),
            ("option_no_auto_anonymous_login", "OptionNoAutoAnonymousLogin"),
            ("option_use_ccache", "OptionUseCCache"),
            ("option_use_nt_hash", "OptionUseNTHash"),
        ) \
    :
        def_bool_method(name, funcname)
    #end for
    for name, funcname in \
        (
            ("debug", "Debug"),
            ("timeout", "Timeout"),
            ("port", "Port"),
            ("option_open_share_mode", "OptionOpenShareMode"),
            ("option_user_data", "OptionUserData"),
            ("option_smb_encryption_level", "OptionSmbEncryptionLevel"),
            ("option_browse_max_lmb_count", "OptionBrowseMaxLmbCount"),
            ("server_cached_data", "ServerCacheData"),
        ) \
    :
        def_simple_method(name, funcname)
    #end for
    for name, funcname in \
        (
            ("netbios_name", "NetbiosName"),
            ("workgroup", "Workgroup"),
            ("user", "User"),
        ) \
    :
        def_str_method(name, funcname)
    #end for
    for name, funcname, def_wrap, details in \
        (
            (
                "function_auth_data",
                "FunctionAuthData",
                def_wrap_auth_data_fn,
                "auth_fn(srv, shr, wg, un, pw)\n\n"
                "where srv is the server name, shr is the share name, and wg, un and pw"
                " are FBytes objects for passing and returning the workgroup name,"
                " username and password. You can retrieve the initial settings from"
                " the FBytes’ value attributes, and assign new values, that must not exceed"
                " the maximum given by the max attributes.",
            ),
            (
                "function_auth_data_with_context",
                "FunctionAuthDataWithContext",
                def_wrap_auth_data_with_context_fn,
                "auth_fn(ctx, srv, shr, wg, un, pw)"
                "where ctx is the Context, srv is the server name, shr is the share name,"
                " and wg, un and pw"
                " are FBytes objects for passing and returning the workgroup name,"
                " username and password. You can retrieve the initial settings from"
                " the FBytes’ value attributes, and assign new values, that must not exceed"
                " the maximum given by the max attributes.",
            ),
        ) \
    :
        def_callback_method(name, funcname, def_wrap, details)
    #end for
#end def_context_extra
def_context_extra(Context)
del def_context_extra

class GenericFile :
    "represents an open libsmbclient file, directory or print job. Do not" \
    " instantiate directly; get from Context.open/creat/opendir/open_print_job methods."

    __slots__ = ("_smbobj", "parent", "_closename", "__weakref__") # to forestall typos

    _instances = WeakValueDictionary()

    def __new__(celf, _smbobj, parent, _closename) :
        self = celf._instances.get(_smbobj)
        if self == None :
            self = super().__new__(celf)
            self._smbobj = _smbobj
            self.parent = parent
            self._closename = _closename
            celf._instances[_smbobj] = self
        else :
            assert self.parent == parent and self._closename == _closename
        #end if
        return \
            self
    #end __new__

    def __del__(self) :
        self.close()
    #end __del__

    def close(self) :
        if self._smbobj != None :
            getattr(smbc, "smbc_get" + self._closename)(self.parent._smbobj) \
                (self.parent._smbobj, self._smbobj)
        #end if
        self._smbobj = None
    #end close

    def close_async(self) :
        return \
            self.parent._call_async(self.close, ())
    #end close_async

#end GenericFile

class File(GenericFile) :
    "represents an open libsmbclient file or print job. Do not instantiate" \
    " directly; get from Context.open/creat/open_print_job methods."

    __slots__ = ("read_at_once",) # to forestall typos

    def __new__(celf, _smbobj, _parent) :
        result = GenericFile.__new__(celf, _smbobj, _parent, "FunctionClose")
        result.read_at_once = 4096
        return \
            result
    #end __new__

    def read(self, to_read = None) :
        "tries to read the specified number of bytes if not None, else" \
        " reads until EOF. Returns the bytes read."
        if to_read == None :
            result = self.readall()
        else :
            # do just one underlying read call
            buf = array.array("B", [0] * to_read)
            nrbytes = smbc.smbc_getFunctionRead(self.parent._smbobj) \
                (
                    self.parent._smbobj, self._smbobj,
                    ct.addressof((ct.c_ubyte * 0).from_buffer(buf)), to_read
                )
            if nrbytes < 0 :
                raise SMBError("reading from file")
            #end if
            result = buf.tobytes()[:nrbytes]
        #end if
        return \
            result
    #end read

    def read_async(self, to_read = None) :
        return \
            self.parent._call_async(self.read, (to_read,))
    #end read_async

    def readall(self) :
        "reads everything from file until EOF."
        assert self.read_at_once != 0
        func = smbc.smbc_getFunctionRead(self.parent._smbobj)
        to_read = self.read_at_once
        buf = array.array("B", [0] * to_read)
        offset = 0
        while True :
            if to_read == 0 :
                break
            bufadr = ct.addressof((ct.c_ubyte * 0).from_buffer(buf)) + offset
              # need to keep refetching base address of buffer, because it
              # might have changed after previous resize (below)
            nrbytes = func(self.parent._smbobj, self._smbobj, bufadr, to_read)
            if nrbytes < 0 :
                raise SMBError("reading from file until EOF (after %d bytes)" % offset)
            #end if
            if nrbytes == 0 :
                break
            offset += nrbytes
            to_read -= nrbytes
            # extend buffer to keep some reasonable minimum size for read requests
            add_to_read = \
                (
                    (self.read_at_once * 3 // 2 - to_read)
                //
                    self.read_at_once
                *
                    self.read_at_once
                )
            if add_to_read > 0 :
                buf.extend([0] * add_to_read)
                to_read += add_to_read
            #end if
        #end while
        return \
            buf.tobytes()[:offset]
    #end readall

    def readall_async(self) :
        return \
            self.parent._call_async(self.readall, ())
    #end readall_async

    def readinto(self, buf) :
        "reads into a preallocated writeable bytes-like object, using at most" \
        " one underlying read call. Returns nr bytes read."
        to_read = len(buf)
        nrbytes = smbc.smbc_getFunctionRead(self.parent._smbobj) \
            (
                self.parent._smbobj, self._smbobj,
                ct.addressof((ct.c_ubyte * 0).from_buffer(buf)), to_read
            )
        if nrbytes < 0 :
            raise SMBError("reading from file into %d-byte buf" % to_read)
        #end if
        return \
            nrbytes
    #end readinto

    def readinto_async(self, buf) :
        return \
            self.parent._call_async(self.readinto, (buf,))
    #end readinto_async

    def write(self, data) :
        "tries to write the entire contents of the given bytes-like object," \
        " using at most one underlying write call. Returns nr bytes actually written."
        if isinstance(data, bytes) :
            srcadr = ct.cast(data, ct.c_void_p).value
        elif isinstance(data, bytearray) or isinstance(data, array.array) and data.typecode == "B" :
            srcadr = ct.addressof((ct.c_ubyte * 0).from_buffer(data))
        else :
            raise TypeError("data is not bytes, bytearray or array.array of bytes")
        #end if
        nrbytes = smbc.smbc_getFunctionWrite(self.parent._smbobj) \
            (self.parent._smbobj, self._smbobj, srcadr, len(data))
        if nrbytes <= 0 :
            raise SMBError("writing to file")
        #end if
        return \
            nrbytes
    #end write

    def write_async(self, data) :
        return \
            self.parent._call_async(self.write, (data,))
    #end write_async

    def splice(self, other, count, callback) :

        @SMBC.splice_cb_fn
        def c_callback(remaining, _) :
            return \
                int(callback(remaining))
        #end c_callback

    #begin splice
        if not isinstance(other, File) or other.parent != self.parent :
            raise TypeError("other must be a File sharing same parent Context")
        #end if
        result = smbc.smbc_getFunctionSplice(self.parent._smbobj) \
            (self.parent._smbobj, self._smbobj, other._smbobj, count, c_callback, None)
        if result < 0 :
            raise SMBError("splicing files")
        #end if
        return \
            result
    #end splice

    def splice_async(self, other, count, callback) :

        def do_callback(remaining) :
            # invoked on worker thread, dispatches to caller’s callback
            # on main thread.
            self.parent.loop.call_soon_threadsafe(callback, remaining)
        #end do_callback

    #begin splice_async
        return \
            self.parent._call_async(self.splice, (other, count, do_callback))
    #end slice_async

    def lseek(self, offset, whence) :
        offset = smbc.smbc_getFunctionLseek(self.parent._smbobj) \
            (self.parent._smbobj, self._smbobj, offset, whence)
        if offset < 0 :
            raise SMBError("lseeking on file")
        #end if
        return \
            offset
    #end lseek

    def lseek_async(self, offset, whence) :
        return \
            self.parent._call_async(self.lseek, (offset, whence))
    #end lseek_async

    def fstat(self) :
        info = SMBC.c_stat_t()
        if smbc.smbc_getFunctionFstat(self.parent._smbobj) \
            (self.parent._smbobj, self._smbobj, ct.byref(info)) != 0 :
            raise SMBError("statting file")
        #end if
        return \
            StructStat \
              (*(
                (lambda x : x, decode_timespec)[f[0].endswith("tim")](getattr(info, f[0]))
                for f in SMBC.c_stat_t._fields_
                if not f[0].startswith("Ṕ")
              ))
    #end fstat

    def fstat_async(self) :
        return \
            self.parent._call_async(self.fstat, ())
    #end fstat_async

    def fstatvfs(self) :
        info = SMBC.c_statvfs_t()
        if smbc.smbc_getFunctionFstatVFS(self.parent._smbobj) \
            (self.parent._smbobj, self._smbobj, ct.byref(info)) != 0 :
            raise SMBError("statting VFS")
        #end if
        return \
            StructStatVFS \
              (*(
                getattr(info, f[0])
                for f in SMBC.c_statvfs_t._fields_
                if not f[0].startswith("Ṕ")
              ))
    #end fstatvfs

    def fstatvfs_async(self) :
        return \
            self.parent._call_async(self.fstatvfs, ())
    #end fstatvfs_async

    def ftruncate(self, offset) :
        if (
                smbc.smbc_getFunctionFtruncate(self.parent._smbobj)
                    (self.parent._smbobj, self._smbobj, offset)
            !=
                0
        ) :
            raise SMBError("truncating file")
        #end if
    #end ftruncate

    def ftruncate_async(self, offset) :
        return \
            self.parent._call_async(self.ftruncate, (offset,))
    #end ftruncate_async

#end File

class Directory(GenericFile) :
    "represents an open libsmbclient directory. Do not instantiate directly;" \
    " get from Context.opendir method."

    __slots__ = () # to forestall typos

    def __new__(celf, _smbobj, _parent) :
        self = GenericFile.__new__(celf, _smbobj, _parent, "FunctionClosedir")
        return \
            self
    #end __new__

    def get_all_dents(self) :
        self.lseekdir(0)
        bufsize = ct.sizeof(SMBC.dirent) + SMBC.NAME_MAX
        align = ct.sizeof(ct.c_void_p)
        bufsize = bufsize + align - 1 & - align
        buf = (bufsize * ct.c_ubyte)()
        func = smbc.smbc_getFunctionGetdents(self.parent._smbobj)
        offset = 0
        nrbytes = 0
        while True :
            while True :
                if offset == nrbytes :
                    break
                dirent, direntlen = _decode_dirent(ct.addressof(buf) + offset, self.parent.decode_bytes)
                if dirent.name not in (b".", b"..") :
                    yield dirent
                #end if
                offset += direntlen
            #end while
            nrbytes = func \
              (
                self.parent._smbobj,
                self._smbobj,
                ct.cast(ct.addressof(buf), ct.POINTER(SMBC.dirent)),
                bufsize
              )
            if nrbytes <= 0 :
                if nrbytes < 0 :
                    raise SMBError("getting directory entries")
                #end if
                break
            #end if
            offset = 0
        #end while
    #end get_all_dents

    class _DentsAiter :
        # internal class for use by get_all_dents_async.

        def __init__(self, dir) :
            self.dir = dir
        #end __init__

        def __aiter__(self) :
            # I’m my own iterator.
            self.bufsize = ct.sizeof(SMBC.dirent) + SMBC.dirent_name_extra
            self.buf = (bufsize * ct.c_ubyte)()
            self.getdents = smbc.smbc_getFunctionGetdents(self.dir.parent._smbobj)
            self.offset = 0
            self.nrbytes = 0
            self.first = True
            return \
                self
        #end __aiter__

        async def __anext__(self) :
            if self.first :
                await self.dir.lseekdir_async(0)
                self.first = False
            #end if
            while True :
                if self.offset == self.nrbytes :
                    self.nrbytes = await self.dir.parent._call_async \
                      (
                        self.getdents,
                          (
                            self.dir.parent._smbobj,
                            self.dir._smbobj,
                            ct.cast(ct.addressof(self.buf), ct.POINTER(SMBC.dirent)),
                            self.bufsize
                          )
                      )
                    if self.nrbytes <= 0 :
                        if self.nrbytes < 0 :
                            raise SMBError("getting directory entries")
                        #end if
                        raise StopAsyncIteration("no more directory entries")
                    #end if
                    self.offset = 0
                #end if
                dirent, direntlen = _decode_dirent(ct.addressof(self.buf) + self.offset, self.parent.decode_bytes)
                self.offset += direntlen
                if dirent.name not in (b".", b"..") :
                    break
            #end while
            return \
                dirent
        #end __anext__

    #end _DentsAiter

    def get_all_dents_async(self) :
        return \
            type(self)._DentsAiter(self)
    #end get_all_dents_async

    def readdir(self) :
        result = ct.cast(smbc.smbc_getFunctionReaddir(self.parent._smbobj)(self.parent._smbobj, self._smbobj), ct.c_void_p).value
        if result != None :
            result = _decode_dirent(result, self.parent.decode_bytes)[0]
        #end if
        return \
            result
    #end readdir

    def readdir_async(self) :
        return \
            self.parent._call_async(self.readdir, ())
    #end readdir_async

    if hasattr(smbc, "smbc_readdirplus") :

        def readdirplus(self) :
            result = ct.cast(smbc.smbc_getFunctionReaddirPlus(self.parent._smbobj)(self.parent._smbobj, self._smbobj), ct.c_void_p).value
            if result != None :
                info = ct.cast(result, ct.POINTER(SMBC.file_info)).contents
                result = FileInfo \
                  (
                    size = info.size,
                    attrs = info.attrs,
                    uid = info.uid,
                    gid = info.gid,
                    btime_ts = decode_timespec(info.btime_ts),
                    mtime_ts = decode_timespec(info.mtime_ts),
                    atime_ts = decode_timespec(info.atime_ts),
                    ctime_ts = decode_timespec(info.ctime_ts),
                    name = decode_bytes0(info.name, self.parent.decode_bytes),
                    short_name = decode_bytes0(info.short_name, self.parent.decode_bytes),
                  )
            #end if
            return \
                result
        #end readdirplus

        def readdirplus_async(self) :
            return \
                self.parent._call_async(self.readdirplus, ())
        #end readdirplus_async

    #end if

    def telldir(self) :
        result = smbc.smbc_getFunctionTelldir(self.parent._smbobj)(self.parent._smbobj, self._smbobj)
        if result < 0 :
            raise SMBError("getting directory offset")
        #end if
        return \
            offset
    #end telldir

    def telldir_async(self) :
        return \
            self.parent._call_async(self.telldir, ())
    #end telldir_async

    def lseekdir(self, offset) :
        result = smbc.smbc_getFunctionLseekdir(self.parent._smbobj)(self.parent._smbobj, self._smbobj, offset)
        if result < 0 :
            raise SMBError("setting directory offset")
        #end if
    #end lseekdir

    def lseekdir_async(self, offset) :
        return \
            self.parent._call_async(self.lseekdir, (offset,))
    #end lseekdir_async

    def notify(self, recursive, filter, timeout, notifier) :

        @SMBC.notify_callback_fn
        def c_notifier(c_actions, nr_actions, _) :
            actions = []
            for i in range(nr_actions) :
                item = c_actions[i]
                actions.append \
                  (
                    NotifyCallbackAction(action = item.action, filename = item.filename)
                  )
            #end if
            result = notifier(actions)
            if not isinstance(result, int) :
                raise TypeError("notifier result must be int")
            #end if
            return \
                result
        #end c_notifier

    #begin notify
        if (
                smbc.smbc_getFunctionNotify(self.parent._smbobj)
                    (
                        self.parent._smbobj,
                        self._smbobj,
                        recursive,
                        filter,
                        round(timeout * THOUSAND),
                        c_notifier,
                        None
                    )
            !=
                0
        ) :
            raise SMBError("getting directory notifications")
        #end if
    #end notify

    class AsyncNotifier :
        "a notification object returned by Directory.notify_async(). Do" \
        " not instantiate directly; get instances from that call."

        def __init__(self, dir, recursive, filter, timeout, poll, action) :
            self.dir = dir
            self.recursive = recursive
            self.filter = filter
            self.timeout = timeout
            self.poll = poll
            self.action = action
            self.notifs = asyncio.Queue()
              # doesn’t need to be threadsafe -- only accessed on main thread
            self.stopping = False
            self.last_call = time.time()
            self.done_fute = self.dir.parent._call_async(self._run_notifications, ())
            self.async_for = False
            self.end_marker = object()
        #end __init__

        def __del__(self) :
            self.stop()
        #end __del__

        def _run_notifications(self) :
            # runs on the worker thread to actually collect the notifications
            # and return them to the main thread.

            w_self = weak_ref(self)

            def return_notif(self, items) :
                for item in items :
                    self.notifs.put_nowait(item)
                #end for
            #end return_notif

            @SMBC.notify_callback_fn
            def c_notifier(c_actions, nr_actions, _) :
                now = time.time()
                self = _wderef(w_self, "Directory.AsyncNotifier")
                items = []
                i = 0
                stopping = False
                while True :
                    if i == nr_actions :
                        break
                    item = c_actions[i]
                    action = NotifyCallbackAction(action = item.action, filename = item.filename)
                    if self.action != None :
                        result = self.action(action)
                        if not isinstance(result, int) :
                            raise TypeError("action result must be int")
                        #end if
                        if result != 0 :
                            stopping = True
                            break
                        #end if
                    #end if
                    items.append(action)
                    i += 1
                #end while
                if len(items) != 0 :
                    self.dir.parent.loop.call_soon_threadsafe(return_notif, self, items)
                    self.last_call = now
                #end if
                if self.stopping :
                    stopping = True
                #end if
                if not stopping and self.timeout != None and now - self.last_call > self.timeout :
                    if self.async_for :
                        stopping = True
                    else :
                        self.dir.parent.loop.call_soon_threadsafe(return_notif, self, [None])
                        self.last_call = now
                    #end if
                #end if
                if stopping :
                    self.dir.parent.loop.call_soon_threadsafe(return_notif, self, [self.end_marker])
                #end if
                return \
                    int(stopping)
            #end c_notifier

        #begin _run_notifications
            if (
                    smbc.smbc_getFunctionNotify(self.dir.parent._smbobj)
                        (
                            self.dir.parent._smbobj,
                            self.dir._smbobj,
                            self.recursive,
                            self.filter,
                            round(self.poll * THOUSAND),
                            c_notifier,
                            None
                        )
                !=
                    0
            ) :
                raise SMBError("getting async directory notifications")
            #end if
        #end _run_notifications

        def get(self) :
            "awaits and returns the next available notification. Returns" \
            " None on timeout."
            return \
                self.notifs.get()
        #end get

        def stop(self) :
            "tells worker-thread action to stop sending notifications" \
            " at its earliest convenience. May safely be called even" \
            " after notifications have stopped."
            self.stopping = True
        #end stop

        def __aiter__(self) :
            # for use with async-for.
            self.async_for = True
            # I’m my own iterator.
            return \
                self
        #end __aiter__

        async def __anext__(self) :
            # for use with async-for.
            item = await self.notifs.get()
            if item is self.end_marker :
                await self.done_fute # might raise exception
                raise StopAsyncIteration("end of async directory notifications")
            #end if
            return \
                item
        #end __anext__

    #end AsyncNotifier

    def notify_async(self, recursive, filter, timeout, poll, action = None) :
        "starts a notify call running on the parent Context for this Directory," \
        " allowing asynchronous retrieval of notification events." \
        " recursive, filter and timeout have the same meaning as for notify," \
        " except that the timeout is only checked at a granularity given by poll.\n" \
        "\n" \
        "Notification events may be retrieved from the returned AsyncNotifier object" \
        " in one of two ways. One way uses its get() method, something like\n" \
        "\n" \
        "    notifs = «dir».notify_async(...)\n" \
        "    while «cond» :\n" \
        "        notif = await notifs.get()\n" \
        "        if notif == None : # timeout\n" \
        "            break\n" \
        "        ... «process notif» ...\n" \
        "    #end while\n" \
        "    notifs.stop()\n" \
        "\n" \
        "Alternatively, the AsyncNotifier can be used in an async-for" \
        " statement like this:\n" \
        "\n" \
        "    async for notif in «dir».notify_async(...) :\n" \
        "        «process notif»\n" \
        "    #end for\n"
        return \
            type(self).AsyncNotifier(self, recursive, filter, timeout, poll, action)
    #end notify_async

#end Directory

def version(decode = True) :
    return \
        decode_bytes0(smbc.smbc_version(), decode)
#end version

if hasattr(smbc, "smbc_thread_posix") :

    def thread_posix() :
        smbc.smbc_thread_posix()
    #end thread_posix

#end if

#+
# Overall
#-

def _atexit() :
    # disable all __del__ methods at process termination to avoid segfaults
    for ċlass in Context, GenericFile :
        delattr(ċlass, "__del__")
    #end for
#end _atexit
atexit.register(_atexit)
del _atexit
