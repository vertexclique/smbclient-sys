#![allow(non_camel_case_types)]
#![allow(missing_copy_implementations)]
#![allow(unstable)]

extern crate libc;

use std::{option, mem, clone, default};

use libc::{c_int, c_char, c_double, c_void, c_uchar, c_uint, c_ulong, c_ushort, size_t, time_t,
	mode_t, ssize_t, off_t, stat, timeval};

static SMBC_BASE_FD        : i32 = 10000; /* smallest file descriptor returned */
static SMBC_WORKGROUP      : i32 = 1;
static SMBC_SERVER         : i32 = 2;
static SMBC_FILE_SHARE     : i32 = 3;
static SMBC_PRINTER_SHARE  : i32 = 4;
static SMBC_COMMS_SHARE    : i32 = 5;
static SMBC_IPC_SHARE      : i32 = 6;
static SMBC_DIR            : i32 = 7;
static SMBC_FILE           : i32 = 8;
static SMBC_LINK           : i32 = 9;

#[repr(C)]
#[derive(Copy)]
pub struct smbc_dirent {
    /** Type of entity.
	    SMBC_WORKGROUP=1,
	    SMBC_SERVER=2,
	    SMBC_FILE_SHARE=3,
	    SMBC_PRINTER_SHARE=4,
	    SMBC_COMMS_SHARE=5,
	    SMBC_IPC_SHARE=6,
	    SMBC_DIR=7,
	    SMBC_FILE=8,
	    SMBC_LINK=9,*/
	pub smbc_type: c_uint,

	/** Length of this smbc_dirent in bytes
	 */
	pub dirlen: c_uint,
	/** The length of the comment string in bytes (does not include
	 *  null terminator)
	 */
	pub commentlen: c_uint,
	/** Points to the null terminated comment string
	 */
	pub comment: *mut c_char,
	/** The length of the name string in bytes (does not include
	 *  null terminator)
	 */
	pub namelen: c_uint,
	/** Points to the null terminated name string
	 */
	pub name: [c_char; 1usize],
}

impl clone::Clone for smbc_dirent {
    fn clone(&self) -> Self { *self }
}

impl default::Default for smbc_dirent {
    fn default() -> Self { unsafe { mem::zeroed() } }
}

/*
 * Flags for smbc_setxattr()
 *   Specify a bitwise OR of these, or 0 to add or replace as necessary
 */
static SMBC_XATTR_FLAG_CREATE  : i32 = 0x1; /* fail if attr already exists */
static SMBC_XATTR_FLAG_REPLACE : i32 = 0x2; /* fail if attr does not exist */


/*
 * Mappings of the DOS mode bits, as returned by smbc_getxattr() when the
 * attribute name "system.dos_attr.mode" (or "system.dos_attr.*" or
 * "system.*") is specified.
 */
static SMBC_DOS_MODE_READONLY  : i32 = 0x01;
static SMBC_DOS_MODE_HIDDEN    : i32 = 0x02;
static SMBC_DOS_MODE_SYSTEM    : i32 = 0x04;
static SMBC_DOS_MODE_VOLUME_ID : i32 = 0x08;
static SMBC_DOS_MODE_DIRECTORY : i32 = 0x10;
static SMBC_DOS_MODE_ARCHIVE   : i32 = 0x20;

/*
 * Valid values for the option "open_share_mode", when calling
 * smbc_setOptionOpenShareMode()
 */
pub type smbc_share_mode = c_uint;
pub const SMBC_SHAREMODE_DENY_DOS: c_uint = 0;
pub const SMBC_SHAREMODE_DENY_ALL: c_uint = 1;
pub const SMBC_SHAREMODE_DENY_WRITE: c_uint = 2;
pub const SMBC_SHAREMODE_DENY_READ: c_uint = 3;
pub const SMBC_SHAREMODE_DENY_NONE: c_uint = 4;
pub const SMBC_SHAREMODE_DENY_FCB: c_uint = 7;

/**
 * Values for option SMB Encryption Level, as set and retrieved with
 * smbc_setOptionSmbEncryptionLevel() and smbc_getOptionSmbEncryptionLevel()
 */
pub type smbc_smb_encrypt_level = c_uint;
pub const SMBC_ENCRYPTLEVEL_NONE: c_uint = 0;
pub const SMBC_ENCRYPTLEVEL_REQUEST: c_uint = 1;
pub const SMBC_ENCRYPTLEVEL_REQUIRE: c_uint = 2;


/**
 * Capabilities set in the f_flag field of struct statvfs, from
 * smbc_statvfs(). These may be OR-ed together to reflect a full set of
 * available capabilities.
 */
pub type smbc_vfs_feature = c_uint;
pub const SMBC_VFS_FEATURE_RDONLY: c_uint = (1 << 0);
pub const SMBC_VFS_FEATURE_DFS: c_uint = (1 << 28);
pub const SMBC_VFS_FEATURE_CASE_INSENSITIVE: c_uint = (1 << 29);
pub const SMBC_VFS_FEATURE_NO_UNIXCIFS: c_uint = (1 << 30);

pub type smbc_bool = c_int;

#[repr(C)]
#[derive(Copy)]
pub struct print_job_info {
	/** numeric ID of the print job
	 */
	pub id: c_ushort,

	/** represents print job priority (lower numbers mean higher priority)
	 */
	pub priority: c_ushort,

	/** Size of the print job
	 */
	pub size: size_t,

	/** Name of the user that owns the print job
	 */
	pub user: [c_char; 128usize],

	/** Name of the print job. This will have no name if an anonymous print
	 *  file was opened. Ie smb://server/printer
	 */
	pub name: [c_char; 128usize],

	/** Time the print job was spooled
	 */
	pub t: time_t,
}

impl clone::Clone for print_job_info {
    fn clone(&self) -> Self { *self }
}

impl default::Default for print_job_info {
    fn default() -> Self { unsafe { mem::zeroed() } }
}

pub enum _SMBCSRV { }
pub type SMBCSRV = _SMBCSRV;
pub enum _SMBCFILE { }
pub type SMBCFILE = _SMBCFILE;
pub type SMBCCTX = _SMBCCTX;

/*
 * Flags for SMBCCTX->flags
 *
 * NEW CODE SHOULD NOT DIRECTLY MANIPULATE THE CONTEXT STRUCTURE.
 * Instead, use:
 *   smbc_setOptionUseKerberos()
 *   smbc_getOptionUseKerberos()
 *   smbc_setOptionFallbackAfterKerberos()
 *   smbc_getOptionFallbackAFterKerberos()
 *   smbc_setOptionNoAutoAnonymousLogin()
 *   smbc_getOptionNoAutoAnonymousLogin()
 *   smbc_setOptionUseCCache()
 *   smbc_getOptionUseCCache()
 */
static SMB_CTX_FLAG_USE_KERBEROS 			: i32 = (1 << 0);
static SMB_CTX_FLAG_FALLBACK_AFTER_KERBEROS : i32 = (1 << 1);
static SMBCCTX_FLAG_NO_AUTO_ANONYMOUS_LOGON : i32 = (1 << 2);
static SMB_CTX_FLAG_USE_CCACHE 				: i32 = (1 << 3);


pub type smbc_get_auth_data_fn = option::Option<extern "C" fn(srv: *const c_char,
                                        shr: *const c_char,
                                        wg: *mut c_char,
                                        wglen: c_int,
                                        un: *mut c_char,
                                        unlen: c_int,
                                        pw: *mut c_char,
                                        pwlen: c_int) -> ()>;
pub type smbc_get_auth_data_with_context_fn = Option<extern "C" fn(c: *mut SMBCCTX,
                                        srv: *const c_char,
                                        shr: *const c_char,
                                        wg: *mut c_char,
                                        wglen: c_int,
                                        un: *mut c_char,
                                        unlen: c_int,
                                        pw: *mut c_char,
                                        pwlen: c_int) -> ()>;
pub type smbc_list_print_job_fn = option::Option<extern "C" fn(i: *mut print_job_info) -> ()>;
pub type smbc_check_server_fn = option::Option<extern "C" fn(c: *mut SMBCCTX, srv: *mut SMBCSRV)
                              -> c_int>;
pub type smbc_remove_unused_server_fn = option::Option<extern "C" fn(c: *mut SMBCCTX, srv: *mut SMBCSRV)
                              -> c_int>;
pub type smbc_add_cached_srv_fn = option::Option<extern "C" fn(c: *mut SMBCCTX, srv: *mut SMBCSRV,
                                        server: *const c_char,
                                        share: *const c_char,
                                        workgroup: *const c_char,
                                        username: *const c_char)
                              -> c_int>;
pub type smbc_get_cached_srv_fn = option::Option<extern "C" fn(c: *mut SMBCCTX,
                                        server: *const c_char,
                                        share: *const c_char,
                                        workgroup: *const c_char,
                                        username: *const c_char)
                              -> *mut SMBCSRV>;
pub type smbc_remove_cached_srv_fn = option::Option<extern "C" fn(c: *mut SMBCCTX, srv: *mut SMBCSRV)
                              -> c_int>;
pub type smbc_purge_cached_fn = option::Option<extern "C" fn(c: *mut SMBCCTX) -> c_int>;


pub enum smbc_server_cache { }


pub type smbc_open_fn = option::Option<extern "C" fn(c: *mut SMBCCTX,
                                        fname: *const c_char,
                                        flags: c_int, mode: mode_t)
                              -> *mut SMBCFILE>;
pub type smbc_creat_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX,
                                        path: *const c_char,
                                        mode: mode_t) -> *mut SMBCFILE>;
pub type smbc_read_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, file: *mut SMBCFILE,
                                        buf: *mut c_void,
                                        count: size_t) -> ssize_t>;
pub type smbc_write_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, file: *mut SMBCFILE,
                                        buf: *const c_void,
                                        count: size_t) -> ssize_t>;
pub type smbc_unlink_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX,
                                        fname: *const c_char)
                              -> c_int>;
pub type smbc_rename_fn =
    option::Option<extern "C" fn(ocontext: *mut SMBCCTX,
                                        oname: *const c_char,
                                        ncontext: *mut SMBCCTX,
                                        nname: *const c_char)
                              -> c_int>;
pub type smbc_lseek_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, file: *mut SMBCFILE,
                                        offset: off_t, whence: c_int)
                              -> off_t>;
pub type smbc_stat_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX,
                                        fname: *const c_char,
                                        st: *mut stat)
                              -> c_int>;
pub type smbc_fstat_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, file: *mut SMBCFILE,
                                        st: *mut stat)
                              -> c_int>;
pub type smbc_statvfs_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX,
                                        path: *mut c_char,
                                        st: *mut Struct_statvfs)
                              -> c_int>;
pub type smbc_fstatvfs_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, file: *mut SMBCFILE,
                                        st: *mut Struct_statvfs)
                              -> c_int>;
pub type smbc_ftruncate_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, f: *mut SMBCFILE,
                                        size: off_t) -> c_int>;
pub type smbc_close_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, file: *mut SMBCFILE)
                              -> c_int>;
pub type smbc_opendir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX,
                                        fname: *const c_char)
                              -> *mut SMBCFILE>;
pub type smbc_closedir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, dir: *mut SMBCFILE)
                              -> c_int>;
pub type smbc_readdir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, dir: *mut SMBCFILE)
                              -> *mut smbc_dirent>;
pub type smbc_getdents_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, dir: *mut SMBCFILE,
                                        dirp: *mut smbc_dirent,
                                        count: c_int)
                              -> c_int>;
pub type smbc_mkdir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX,
                                        fname: *const c_char,
                                        mode: mode_t) -> c_int>;
pub type smbc_rmdir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX,
                                        fname: *const c_char)
                              -> c_int>;
pub type smbc_telldir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, dir: *mut SMBCFILE)
                              -> off_t>;
pub type smbc_lseekdir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, dir: *mut SMBCFILE,
                                        offset: off_t) -> c_int>;
pub type smbc_fstatdir_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX, dir: *mut SMBCFILE,
                                        st: *mut stat)
                              -> c_int>;
pub type smbc_chmod_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX,
                                        fname: *const c_char,
                                        mode: mode_t) -> c_int>;
pub type smbc_utimes_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX,
                                        fname: *const c_char,
                                        tbuf: *mut timeval)
                              -> c_int>;
pub type smbc_setxattr_fn =
    option::Option<extern "C" fn(context: *mut SMBCCTX,
                                        fname: *const c_char,
                                        name: *const c_char,
                                        value: *const c_void,
                                        size: size_t, flags: c_int)
                              -> c_int>;
pub type smbc_getxattr_fn =
    option::Option<extern "C" fn(context: *mut SMBCCTX,
                                        fname: *const c_char,
                                        name: *const c_char,
                                        value: *const c_void,
                                        size: size_t) -> c_int>;
pub type smbc_removexattr_fn =
    option::Option<extern "C" fn(context: *mut SMBCCTX,
                                        fname: *const c_char,
                                        name: *const c_char)
                              -> c_int>;
pub type smbc_listxattr_fn =
    option::Option<extern "C" fn(context: *mut SMBCCTX,
                                        fname: *const c_char,
                                        list: *mut c_char,
                                        size: size_t) -> c_int>;
pub type smbc_print_file_fn =
    option::Option<extern "C" fn(c_file: *mut SMBCCTX,
                                        fname: *const c_char,
                                        c_print: *mut SMBCCTX,
                                        printq: *const c_char)
                              -> c_int>;
pub type smbc_open_print_job_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX,
                                        fname: *const c_char)
                              -> *mut SMBCFILE>;
pub type smbc_list_print_jobs_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX,
                                        fname: *const c_char,
                                        _fn: smbc_list_print_job_fn)
                              -> c_int>;
pub type smbc_unlink_print_job_fn =
    option::Option<extern "C" fn(c: *mut SMBCCTX,
                                        fname: *const c_char,
                                        id: c_int) -> c_int>;


pub enum SMBC_internal_data { }
#[repr(C)]
#[derive(Copy)]
pub struct _SMBCCTX {
    pub debug: c_int,
    pub netbios_name: *mut c_char,
    pub workgroup: *mut c_char,
    pub user: *mut c_char,
    pub timeout: c_int,
    pub open: smbc_open_fn,
    pub creat: smbc_creat_fn,
    pub read: smbc_read_fn,
    pub write: smbc_write_fn,
    pub unlink: smbc_unlink_fn,
    pub rename: smbc_rename_fn,
    pub lseek: smbc_lseek_fn,
    pub stat: smbc_stat_fn,
    pub fstat: smbc_fstat_fn,
    pub close_fn: smbc_close_fn,
    pub opendir: smbc_opendir_fn,
    pub closedir: smbc_closedir_fn,
    pub readdir: smbc_readdir_fn,
    pub getdents: smbc_getdents_fn,
    pub mkdir: smbc_mkdir_fn,
    pub rmdir: smbc_rmdir_fn,
    pub telldir: smbc_telldir_fn,
    pub lseekdir: smbc_lseekdir_fn,
    pub fstatdir: smbc_fstatdir_fn,
    pub chmod: smbc_chmod_fn,
    pub utimes: smbc_utimes_fn,
    pub setxattr: smbc_setxattr_fn,
    pub getxattr: smbc_getxattr_fn,
    pub removexattr: smbc_removexattr_fn,
    pub listxattr: smbc_listxattr_fn,
    pub print_file: smbc_print_file_fn,
    pub open_print_job: smbc_open_print_job_fn,
    pub list_print_jobs: smbc_list_print_jobs_fn,
    pub unlink_print_job: smbc_unlink_print_job_fn,
    pub callbacks: _smbc_callbacks,
    pub reserved: *mut c_void,
    pub flags: c_int,
    pub options: _smbc_options,
    pub internal: *mut SMBC_internal_data,
}

impl clone::Clone for _SMBCCTX {
    fn clone(&self) -> Self { *self }
}

impl default::Default for _SMBCCTX {
    fn default() -> Self { unsafe { mem::zeroed() } }
}

#[repr(C)]
#[derive(Copy)]
pub struct _smbc_callbacks {
    pub auth_fn: smbc_get_auth_data_fn,
    pub check_server_fn: smbc_check_server_fn,
    pub remove_unused_server_fn: smbc_remove_unused_server_fn,
    pub add_cached_srv_fn: smbc_add_cached_srv_fn,
    pub get_cached_srv_fn: smbc_get_cached_srv_fn,
    pub remove_cached_srv_fn: smbc_remove_cached_srv_fn,
    pub purge_cached_fn: smbc_purge_cached_fn,
}

impl clone::Clone for _smbc_callbacks {
    fn clone(&self) -> Self { *self }
}

impl default::Default for _smbc_callbacks {
    fn default() -> Self { unsafe { mem::zeroed() } }
}

#[repr(C)]
#[derive(Copy)]
pub struct _smbc_options {
    pub browse_max_lmb_count: c_int,
    pub urlencode_readdir_entries: c_int,
    pub one_share_per_server: c_int,
}
impl clone::Clone for _smbc_options {
    fn clone(&self) -> Self { *self }
}
impl default::Default for _smbc_options {
    fn default() -> Self { unsafe { mem::zeroed() } }
}

extern "C" {
	pub fn smbc_urldecode(dest: *mut c_char, src: *mut c_char, max_dest_len: size_t) -> c_int;
	pub fn smbc_urlencode(dest: *mut c_char, src: *mut c_char, max_dest_len: size_t) -> c_int;
}

#[test]
fn test_name() {
	assert_eq!(SMBC_DOS_MODE_DIRECTORY, 16)
}
