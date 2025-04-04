# :cucumber: QueueCumber :cucumber:
An APC Queue Injection Proof-of-Concept Written in :crab:

## Background: What is APC Queue Injection?

APC (**Asynchronous Procedure Call**) Queue Injection ([MITRE ATT&CK T1055](https://attack.mitre.org/techniques/T1055/004/)) is a process injection technique that circumvents particular Windows API calls that *most* modern endpoint detection and response (EDR) solutions would otherwise hook and identify the invocations of.

APCs are passable callback functions that, once invoked, are done so within a given (existing or self-created) thread of a process ([MSDN Documentation](https://learn.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls)). What this allows is asynchronous computation, in that the threads in question will eventually execute said function if in a satisfiable state - awaiting otherwise. To do so, an APC can be queued by a thread using the Windows API ```QueueUserAPC``` call.

As alluded to, a thread must be within a particular, ready for a blocking operation, state - this is called **alertible** ([MSDN Documentation](https://learn.microsoft.com/en-us/windows/win32/fileio/alertable-i-o)). A particular set of Windows API functions can be called to induce this state, of which are listed in the previous link (i.e., ```SleepEx```). However, there exist undocumented and likely more challenging calls for this - including the NTDLL function ```NtTestAlert``` ([NTAPI Undocumented Functions](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FAPC%2FNtTestAlert.html)). This is used within the tool, emptying the APC queue to free up execution of our injected payload.

Ultimately, how this lends itself to detection evasion is by bypassing the need for us to perform preliminary actions that are likely detectable by endpoint controls. Namely, creation of a thread in a target process (i.e., ```CreateRemoteThread```, likely hooked) in conjunction with the likes of allocating/writing to process memory.

## Credits

Significant credit goes to [0xflux](https://github.com/0xflux) for paving the way in demonstrating [APC Queue Injection using Rust](https://github.com/0xflux/Rust-APC-Queue-Injection) and furthering this interesting area of research. Further, additional context was gained from [Red Team Notes](https://www.ired.team/offensive-security/code-injection-process-injection/apc-queue-code-injection), in addition to a [write-up](https://www.ired.team/offensive-security/code-injection-process-injection/shellcode-execution-in-a-local-process-with-queueuserapc-and-nttestalert) alluding to the use of ```NtTestAlert``` in the context of APC Queue Injection.

## Usage

Via Cargo (Recommended):
```bash
cargo run -- "PAYLOAD_PATH" ( --name|-n "PROCESS_NAME" |  --pid|-p PID )
```

Example (via Cargo):

```bash
cargo run -- "tests\\mock\\shellcode.bin" --name "msedge.exe"
```

## Further Development

Any issues, further enhancements and more can be made via the **Issues** section. Any contributions can be made by forking this repository and raising a **Pull Request**, in which I will review as soon as able.

## Disclaimer

This repository has been created solely out of professional curiosity, and is intended **strictly** for research purposes. In no way should this be applied in contexts that are deemed illegal in your respective jurisdiction. The author of this repository claims no responsibility for the application of this, nor the implications faced thereafter should any risks materialise.

Further, please be conscious when invoking this tool. Depending on environment, this could very well pose a severe impact - including but not limited to host impairment, undermining security hygiene, disciplinary action and more. The sample shellcode provided merely opens multiple instances of Windows Notepad, though this could be co-opted to execute other, more impactful payloads. In this instance, the author provides no responsibility for the payload(s) passed into this.