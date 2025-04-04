//! Provides ancillary functions for interacting with
//! system processes.
#![allow(dead_code)]

use crate::wrapper::process::RemoteProcess;
use std::{
    mem::size_of,
    ffi::{ CString, OsString },
    // OsStringExt added as a trait to support
    // a from with a u16 vector (szExeFile).
    os::windows::ffi::OsStringExt
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot,
    Process32FirstW,
    Process32NextW,
    PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};

pub fn get_process_by_name(p_name: &CString) -> Option<RemoteProcess> {
    // Given a needle representing the process name, traverse list of
    // processes to return the very first instance.

    let p_snapshot = unsafe {
        
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    };

    let mut p_entry = PROCESSENTRY32W {

        dwSize: size_of::<PROCESSENTRY32W>() as u32,

        // Populate remaining attributes as not pertinent to us.
        ..Default::default()
    };

    if unsafe { Process32FirstW(p_snapshot.clone().unwrap(), &mut p_entry) }.is_ok() {

        while unsafe {

            Process32NextW(p_snapshot.clone().unwrap(), &mut p_entry)

        }.is_ok() {

            // Allows comparison between &[u16; 160] (wide) and &str,
            // using OsString and OsStringExt.
            if OsString::from_wide(&p_entry.szExeFile).to_str().unwrap()
                .starts_with(p_name.to_str().unwrap()) { break; }
        }

        return Some(RemoteProcess::from(p_entry));
    }

    None
}