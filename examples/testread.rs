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
        strncpy(pw, CString::new("1234").unwrap().as_ptr(), 4);
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
            let read_val = smbc::smbc_read(retval, file_contents.as_mut_ptr(), dstlen);
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
