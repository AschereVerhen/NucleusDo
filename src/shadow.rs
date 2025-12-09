use syscalls::{syscall, Sysno, Errno};
use crate::uid::_exit;
//Open /etc/passwd and filter for username from uid(we have uid: rid)
pub fn open_passwd() -> Result<Vec<u8>, Errno> {
    let path = b"/etc/passwd\0";
    const O_RDONLY: u32 = 0o0;
    let fd = unsafe {
        syscall!(Sysno::open, path.as_ptr(), O_RDONLY)?
    };
    let mut buffer = [0u8; 2000]; //a buffer of 2 kb
    let bytes_read: usize = unsafe {
        syscall!(Sysno::read, fd, buffer.as_mut_ptr(), buffer.len())?
    };
    // now we transfer the contents of buffer to a new vector.
    let contents = buffer[..bytes_read as usize].to_vec();
    Ok(contents)
}

pub fn get_username(passwd: Vec<u8>, uid: usize) -> Result<String, Errno> {
    let contents_in_string = match String::from_utf8(passwd) {
        Ok(s) => s,
        Err(_) => _exit(255),
    };
    let username = contents_in_string
        .lines()
        .find(|line| {
            if let Some(got_uid) = line.split(':').nth(2) {
                uid.to_string() == got_uid
            } else {
                false
            }
        })
        .and_then(|line| {
            line.split(':').next()
        });
    match username {
        Some(username) => Ok(username.to_string()),
        None => _exit(255), 
    }
}

pub fn open_shadow() -> Result<Vec<u8>, Errno> {
    let path = b"/etc/shadow\0";
    const O_RDONLY: u32 = 0o0;
    let fd = unsafe {
        syscall!(Sysno::open, path.as_ptr(), O_RDONLY)?
    };
    let mut buffer = [0u8; 2000];
    let bytes_read: usize = unsafe{
        syscall!(Sysno::read, fd, buffer.as_mut_ptr(), buffer.len())?
    };
    let contents = buffer[..bytes_read].to_vec();
    Ok(contents)
}

pub fn get_hash(shadow: Vec<u8>, username: String) -> Result<String, Errno> {
    let shadow_string = match String::from_utf8(shadow) {
        Ok(s) => s,
        Err(_) => _exit(255)
    };
    let hash_str = shadow_string
        .lines()
        .find(|line| {
            if let Some(line_username) = line.split(':').next() { //Using next. As username is at $0
                line_username == username
            } else {
                false
            }
        })
        .and_then(|line| {
            line.split(':').nth(1)
        });
    match hash_str {
        Some(s) => Ok(s.to_string()),
        None => _exit(255),
    }
}

