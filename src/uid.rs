use syscalls::{Sysno, syscall, Errno};

#[derive(Debug, PartialEq)]
pub enum PrivState {
    FullRoot, //rid,eid,sid == 0
    HalfRoot, //eid,sid==0; rid!=0;
    NoRoot, //rid,eid,sid != 0;
    UnknownState, //rid!=sid!=eid or such. Abort here.
}


pub fn getuid() -> Result<(u32, u32, u32), Errno>{
    unsafe {
        let mut rid: u32 = 0;
        let mut eid: u32 = 0;
        let mut sid: u32 = 0;
        syscall!(
            Sysno::getresuid,
            &mut rid as *mut u32,
            &mut eid as *mut u32,
            &mut sid as *mut u32
        )?;

        return Ok((rid, eid, sid))
    }
}
pub fn getgid() -> Result<(u32, u32, u32), Errno>{
    unsafe {
        let mut rid: u32 = 0;
        let mut eid: u32 = 0;
        let mut sid: u32 = 0;
        syscall!(
            Sysno::getresgid,
            &mut rid as *mut u32,
            &mut eid as *mut u32,
            &mut sid as *mut u32
        )?;

        return Ok((rid, eid, sid))
    }
}
pub fn setuid(uid: usize, gid: usize) -> Result<(), Errno> {
    unsafe {
        syscall!(Sysno::setgroups, 0, 0)?;
        syscall!(Sysno::setresgid, gid, gid, gid)?; //Use the more secure setresuid & setresgid
        syscall!(Sysno::setresuid, uid, uid, uid)?;
        //instead of the simple setuid. This gets real, effective, and saved userid/groupid at the
        //same time ensuring no exploits.
    }
    Ok(())
}
pub fn _exit(exit_code: i32) -> ! {
    unsafe {
        let _ = syscall!(Sysno::exit, exit_code);
        core::hint::unreachable_unchecked(); //since we called exit, nothing after the above line
        //should be executed. And if it does, we do an panic unwinder. So we are telling the
        //compiler that through this line.
    }
}

pub fn get_state() -> PrivState {
    let (rid, eid, sid) = getuid().unwrap();
    match (rid, eid, sid) {
        (0,0,0) => PrivState::FullRoot,
        (_,0,0) => PrivState::HalfRoot,
        (u1, u2, u3) if u1 == u2 && u2 == u3 => PrivState::NoRoot,
        _ => PrivState::UnknownState,
    }
}
