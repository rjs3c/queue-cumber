//! Shellcode input file parsing utilities.
#![allow(dead_code)]

use std::{
    ffi::c_void,
    fs::read,
    io::ErrorKind
};

// Associated type for compatibility with
// start routine parameters.
pub type ShellcodeFn = Option<unsafe extern "system" fn(*mut c_void) -> u32>;

// pfnAPC type for injected shellcode.
pub type ShellcodeAPCRoutine = Option<unsafe extern "system" fn(usize) -> ()>;

pub fn parse_shellcode_path(path: Option<String>) -> Result<Vec<u8>, String> {
    // Reads an input file, expecting shellcode, and parses into
    // a vector for injection.

    if let Some(path) = path {

        match read(path.as_str()) {

            Ok(raw_contents) => {
    
                Ok(raw_contents)
            },
    
            Err(err) => match err.kind() {
    
                ErrorKind::NotFound         => Err("Input file not found.".to_string()),
                ErrorKind::PermissionDenied => Err("Permission to input file denied.".to_string()),
                _                           => Err("Shellcode parsing failed.".to_string())
            }
        }

    } else {

        Err("First positional shellcode path argument not supplied.".to_string())
    }
}