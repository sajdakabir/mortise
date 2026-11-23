//! Who is on the other end of a local socket.
//!
//! The command-line socket hands out secrets, so the app needs to tell the
//! user *which process* is asking. Anything the client says about itself is
//! a claim; the kernel's answer is not. This asks the kernel.
//!
//! Every `unsafe` block below is a read-only syscall into a buffer we own and
//! size ourselves, and each checks the returned length before trusting it.

use std::ffi::{OsStr, c_int, c_void};
use std::mem::{MaybeUninit, size_of};
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use super::ProcessInfo;

/// The pid of the process connected to a Unix socket.
///
/// `LOCAL_PEERPID` is recorded by the kernel when the connection is made, so
/// the client cannot choose it. Returns `None` if the kernel will not say,
/// which callers must treat as "unidentified", never as "anyone".
pub fn peer_pid(fd: RawFd) -> Option<i32> {
    let mut pid: libc::pid_t = 0;
    let mut len = size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: `pid` is a valid, writable pid_t and `len` holds its exact size,
    // which is what getsockopt(LOCAL_PEERPID) writes. An invalid fd makes the
    // call fail with EBADF; it cannot write outside the buffer.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&raw mut pid).cast::<c_void>(),
            &mut len,
        )
    };
    (rc == 0 && len as usize == size_of::<libc::pid_t>() && pid > 0).then_some(pid)
}

/// What the kernel knows about `pid`, or `None` if it has gone or is not ours.
pub fn process_info(pid: i32) -> Option<ProcessInfo> {
    let bsd = bsd_info(pid)?;
    Some(ProcessInfo {
        pid,
        parent_pid: i32::try_from(bsd.pbi_ppid).ok().filter(|p| *p > 0),
        executable: executable(pid),
        cwd: cwd(pid),
    })
}

fn bsd_info(pid: i32) -> Option<libc::proc_bsdinfo> {
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = size_of::<libc::proc_bsdinfo>() as c_int;
    // SAFETY: the buffer is `size` bytes and the kernel writes at most `size`.
    // proc_bsdinfo is plain integers and byte arrays, so all-zero is a valid
    // value even if the call fails partway.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    // SAFETY: zero-initialised above, and every bit pattern is a valid value.
    (written == size).then(|| unsafe { info.assume_init() })
}

fn executable(pid: i32) -> Option<PathBuf> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: `buf` is writable for exactly the length passed.
    let len = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    let len = usize::try_from(len)
        .ok()
        .filter(|l| *l > 0 && *l <= buf.len())?;
    Some(PathBuf::from(OsStr::from_bytes(&buf[..len])))
}

fn cwd(pid: i32) -> Option<PathBuf> {
    let mut info = MaybeUninit::<libc::proc_vnodepathinfo>::zeroed();
    let size = size_of::<libc::proc_vnodepathinfo>() as c_int;
    // SAFETY: as in `bsd_info`; the struct is integers and byte arrays.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if written != size {
        return None;
    }
    // SAFETY: zero-initialised, fully written, every bit pattern valid.
    let info = unsafe { info.assume_init() };
    // libc models MAXPATHLEN as [[c_char; 32]; 32] for old-compiler reasons;
    // it is one NUL-terminated byte string.
    let bytes: Vec<u8> = info
        .pvi_cdir
        .vip_path
        .iter()
        .flatten()
        .map(|c| *c as u8)
        .take_while(|b| *b != 0)
        .collect();
    (!bytes.is_empty()).then(|| PathBuf::from(OsStr::from_bytes(&bytes)))
}
