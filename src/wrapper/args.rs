//! Representation for user-supplied process
//! arguments (be it PID or process name).
#![allow(dead_code)]

use log::error;
use std::ffi::CString;

#[derive(Debug)]
pub enum ProcessArgs {

    // Ordinal representing the target
    // process ID.
    PID(u32),

    // Process name, alternatively to an
    // exact PID. Later feature.
    PName(CString)
}

impl ProcessArgs {

    pub fn parse_into(input_variants: &[String]) -> Result<Self, ()> {
        // Map command-line arguments to relevant enum variant
        // with type casting and parsing.

        if input_variants.len() != 2 {

            error!("Process arguments were not supplied as expected.");
            return Err(());
        }

        let kwarg = input_variants[0].clone();
        let val = input_variants[1].clone();

        // Examine the keyword argument and map to an appropriate
        // enum variant.
        match kwarg.trim().to_lowercase().as_str() {

            "-p" | "--pid"  => Ok(ProcessArgs::PID(val.parse::<u32>().unwrap())),
            "-n" | "--name" => Ok(ProcessArgs::PName(CString::new(val).unwrap())),
            _               => Err(())
        }
    }
}