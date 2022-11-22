use nix::sys::ptrace;
use nix::unistd::Pid;

pub fn attacher(pid: Pid) -> Result<Pid, String> {
    if let Err(_) = ptrace::attach(pid) {
        return Err(format!("Error attaching to process {pid}").to_string())
    }
    return Ok(pid)
}

pub fn detacher(pid: Pid) -> Result<(), String> {
    if let Err(_) = ptrace::detach(pid, None) {
        return Err(format!("Error detaching from process {pid}").to_string())
    }
    return Ok(())
}