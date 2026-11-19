//! Peer identification against a real socket pair.
#![cfg(target_os = "macos")]

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

#[test]
fn a_socket_peer_is_identified_as_this_process() {
    let (a, _b) = UnixStream::pair().unwrap();
    let pid = mortise_macos::peer_pid(a.as_raw_fd()).expect("kernel should report the peer");
    assert_eq!(pid, std::process::id() as i32);

    let info = mortise_macos::process_info(pid).unwrap();
    assert_eq!(
        info.cwd.as_deref(),
        Some(
            std::env::current_dir()
                .unwrap()
                .canonicalize()
                .unwrap()
                .as_path()
        )
    );
    assert_eq!(
        info.executable.unwrap().canonicalize().unwrap(),
        std::env::current_exe().unwrap().canonicalize().unwrap()
    );
}

#[test]
fn the_chain_walks_up_to_the_parent() {
    let chain = mortise_macos::process_chain(std::process::id() as i32, 4);
    assert!(
        chain.len() >= 2,
        "a test binary always has a parent: {chain:?}"
    );
    assert_eq!(chain[1].pid, chain[0].parent_pid.unwrap());
}

#[test]
fn an_unconnected_fd_is_unidentified() {
    assert_eq!(mortise_macos::peer_pid(-1), None);
}
