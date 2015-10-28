smbclient-sys
=====================

[![Join the chat at https://gitter.im/vertexclique/smbclient-sys](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/vertexclique/smbclient-sys?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
![Samba](http://wiki.univention.de/images/thumb/6/6d/Logo_Samba.png/300px-Logo_Samba.png)

FFI wrapper around libsmbclient which is the part of SAMBA implementation.

[![Travis](https://img.shields.io/travis/vertexclique/smbclient-sys.svg?style=flat-square)]()
|
[![Crates.io](https://img.shields.io/crates/v/smbclient-sys.svg?style=flat-square)]()
| [![Documentation](https://img.shields.io/badge/documentation-0.1.0-blue.svg?style=flat-square)](http://vertexclique.github.io/smbclient-sys/smbclient_sys/index.html)

Usage
------------

Add this to your `Cargo.toml`

```
smbclient_sys = "0.1.0"
```

To access a SMB share and read a file:

```
extern crate smbclient_sys as smbc;
extern crate libc;

use std::str;
use std::ffi::{CStr, CString};
use libc::{c_char, c_int, strncpy, O_RDONLY};

extern "C" fn auth_data(srv: *const c_char,
            shr: *const c_char,
            wg: *mut c_char,
            wglen: c_int,
            un: *mut c_char,
            unlen: c_int,
            pw: *mut c_char,
            pwlen: c_int) {
                unsafe {
        strncpy(un, CString::new("vertexclique").unwrap().as_ptr(), 12);
        strncpy(pw, CString::new("1234").unwrap().as_ptr(), 3);
    }
}

pub static mut authCallback: smbc::smbc_get_auth_data_fn = Some(auth_data);

fn main() {
    println!("Launch...");
    unsafe {
        let fname = CString::new("smb://air5650-nas/rechner/naber.txt").unwrap();

        // Buffer for contents
        let dstlen = 300;
        let mut file_contents = Vec::with_capacity(dstlen as usize);

        smbc::smbc_init(authCallback, 0);
        let retval: i32 = smbc::smbc_open(fname.as_ptr(), O_RDONLY, 0);
        if retval < 0 {
            println!("Couldn't accessed to a SMB file");
        } else {
            println!("Accessed to specified SMB file");

            // Read file to buffer
            let read_val: i64 = smbc::smbc_read(retval, file_contents.as_mut_ptr(), dstlen);
            if read_val > 0 {
                // File successfully read, print contents to stdout

                let c_str: &CStr = CStr::from_ptr(file_contents.as_mut_ptr() as *const i8);
                let content_bytes: &[u8] = c_str.to_bytes();
                let str_slice: &str = str::from_utf8(content_bytes).unwrap();
                let str_buf: String = str_slice.to_owned();

                println!("{0}", str_buf);
            } else {
                // Panic \o/ if you couldn't read
                panic!("Couldn't read file over SMB share");
            }

            // Close it
            smbc::smbc_close(read_val as i32);
        }
    }
}

```

For more information please see the `examples` dir.

Requirements
------------

* `libsmbclient` is needed with development environment
* Some of the systems need `udev` with samba packages. (optional dependency)
