//! Provides helper functions for resolving un-loaded Win32 DLLs, and subsequent exports.

use std::mem::transmute;
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::NTSTATUS,
        System::LibraryLoader::{ GetModuleHandleA, GetProcAddress }
    }
};

// Function prototype for NtTestAlert.
pub type NtTestAlertSignature = unsafe extern "system" fn() -> NTSTATUS;

pub fn resolve_nt_test_alert(module: &str, needle: &str) -> Option<NtTestAlertSignature> {
    // Produces address of NTDLL NtTestAlert export.

    // String literal -> PCSTR for conformancy with function
    // signatures.
    let (module_raw, needle_raw) 
        = (PCSTR::from_raw(module.as_ptr()), PCSTR::from_raw(needle.as_ptr()));

    unsafe {

        if let Some(m_address)

            // Creates handle to DLL and fetches address to specific export.
            = GetProcAddress(GetModuleHandleA(module_raw).unwrap(), needle_raw) {
            
               return Some(transmute(m_address));
            }
    }

    None
}