//! Integration test suite.

use queue_cumber::{
    helper::shellcode::parse_shellcode_path,
    wrapper::{

        args::ProcessArgs,
        process::attach_to_process
    }
};

#[test]
fn test_shellcode_input_file_parses() {

    // Load in mock shellcode file.
    let mock_shellcode_path = Some(String::from(".\\tests\\mock\\shellcode.bin"));
    let mock_shellcode_parsed =
        parse_shellcode_path(mock_shellcode_path);

    // Expecting Result<Vec<u8>, ()> output.
    assert!(mock_shellcode_parsed.is_ok());
}

#[test]
fn test_attach_to_process_by_pid() {

    let p_handle = attach_to_process(

        // Requires changing to fit. Hardcoded for now.
        ProcessArgs::PID(1000)
    );

    assert!(p_handle.is_ok());
}

#[test]
fn test_allocate_memory_in_process() {

    todo!("Implement test.");
} 

#[test]
fn test_write_shellcode_to_process_memory() {

    todo!("Implement test.");
}