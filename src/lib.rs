#![allow(non_camel_case_types)]
#![allow(missing_copy_implementations)]
#![allow(unstable)]

extern crate libc;

use libc::{c_int, c_char, c_double, c_void, c_uchar, c_uint, c_ulong};

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
	pub name: c_char,
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
#[repr(C)]
#[derive(Show)]
pub enum smbc_share_mode {
	SMBC_SHAREMODE_DENY_DOS = 0,
    SMBC_SHAREMODE_DENY_ALL,
    SMBC_SHAREMODE_DENY_WRITE,
    SMBC_SHAREMODE_DENY_READ,
    SMBC_SHAREMODE_DENY_NONE,
    SMBC_SHAREMODE_DENY_FCB
}

/**
 * Values for option SMB Encryption Level, as set and retrieved with
 * smbc_setOptionSmbEncryptionLevel() and smbc_getOptionSmbEncryptionLevel()
 */
#[repr(C)]
#[derive(Show)]
pub enum smbc_smb_encrypt_level {
	SMBC_ENCRYPTLEVEL_NONE = 0,
    SMBC_ENCRYPTLEVEL_REQUEST,
    SMBC_ENCRYPTLEVEL_REQUIRE,
}


/**
 * Capabilities set in the f_flag field of struct statvfs, from
 * smbc_statvfs(). These may be OR-ed together to reflect a full set of
 * available capabilities.
 */
#[repr(C)]
#[derive(Show)]
pub enum smbc_vfs_feature {
    /* Defined by POSIX or in Linux include files (low-order bits) */
    SMBC_VFS_FEATURE_RDONLY         = (1 << 0),

    /* Specific to libsmbclient (high-order bits) */
    SMBC_VFS_FEATURE_DFS              = (1 << 28),
    SMBC_VFS_FEATURE_CASE_INSENSITIVE = (1 << 29),
    SMBC_VFS_FEATURE_NO_UNIXCIFS      = (1 << 30),
}

pub type smbc_bool = c_int;

#[test]
fn test_name() {
	assert_eq!(SMBC_DOS_MODE_DIRECTORY, 16)
}
