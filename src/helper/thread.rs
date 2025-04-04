//! Helper utilities for process thread manipulation.
#![allow(dead_code)]

use crate::{
    helper::shellcode::ShellcodeFn,
    wrapper::process::RemoteProcess
};
use log::info;
use std::mem::transmute;
use windows::Win32::{
    Foundation::HANDLE,
    System::Threading::CreateRemoteThread
};

pub fn create_thread(remote_process: RemoteProcess) -> Result<(*mut u32, HANDLE), String> {
    // Spawns a new thread within a given target process
    // and returns a handle/thread ID.

    if let (Some(p_handle), Some(p_target_address))
        = (remote_process.p_handle, remote_process.p_target_address) {

            let shellcode_fn: ShellcodeFn = unsafe { transmute(p_target_address) };

            // Stores pointer to thread identifier.
            #[allow(unused_mut)]
            let mut t_id = 0 as *mut u32;

            let t_handle = unsafe {

                CreateRemoteThread(
                    p_handle,
                    None,
                    0,
                    shellcode_fn,
                    None,
                    0,
                    Some(t_id)
                )

            };

            if t_handle.is_err() { return Err(String::from("Failed to create thread.")); }

            info!("Handle created to remote thread with ID {:?}.", t_id);

            Ok((t_id, t_handle.unwrap()))

    } else {

        Err(String::from("Cannot create thread on non-existent handle."))
    }
}