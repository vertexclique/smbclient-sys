extern crate pkg_config;

fn main ()
{
    match pkg_config::find_library("smbclient") {
        Ok(_) => println!("cargo:rustc-flags=-l smbclient"),
        Err(e) => {
            println!("error: SMB Client library not found! Probably libsmbclient is not installed.");
            panic!("{}", e);
        }
    };
}
