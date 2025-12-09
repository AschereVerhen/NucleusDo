use syscalls::Errno;
use yescrypt::yescrypt_verify;
mod uid;
mod passwd;
mod shadow;
mod run;
//2 if error is EAGAIN
//3 if error is EINVAL
//4 if error is EFAULT
//255 if unknown error.
fn main() {
    let state = uid::get_state();
    if state == uid::PrivState::NoRoot {
        println!("The binary is not owned by root. Failure.");
        uid::_exit(4);
    }
    if state == uid::PrivState::FullRoot {
        run::run(); //Start the run command early on.
        uid::_exit(0);
    }
    let target_uid = 0;
    let target_gid = 0;

    let mut password = match passwd::read_passwd() {
        Ok(vec) => vec,
        Err(err) => {
            eprintln!("An error occured: {err:?}");
            uid::_exit(255);
        }
    };
    //Getting the username;
    let passwd = shadow::open_passwd().unwrap();
    let (rid, _, _) = uid::getuid().unwrap();
    let (grid, _, _) = uid::getgid().unwrap();
    let username = shadow::get_username(passwd, rid as usize).unwrap();
    match uid::setuid(target_uid, target_gid) {
        Ok(_) => {println!("Uid switch successfull.")},
        Err(err) => {
            eprintln!("Uid switch was not successfull. Err: {err:?}");
            match err {
                Errno::EPERM => {
                    eprintln!("You do not have the permission to change uid.");
                    let _ = uid::_exit(1);
                },
                Errno::EAGAIN => {
                    eprintln!("The kernel does not have enough resource to do this syscall. Please try again later.");
                    let _ = uid::_exit(2);
                },
                Errno::EINVAL => {
                    eprintln!("The uid: {target_uid} Does not exists.");
                    let _ = uid::_exit(3);
                },
                _ => {
                    eprintln!("Unknown error occured.");
                    let _ = uid::_exit(255);
                }
            }
        }
    };
    let shadow = shadow::open_shadow().unwrap();
    let hash = shadow::get_hash(shadow, username).unwrap();
    let is_match = yescrypt_verify(&password, hash.as_str()).is_ok();
    if ! is_match {
        println!("Password is invalid.");
        uid::_exit(255)
    }

    //Since the password is correct, we should remove the bits of that password.
    let raw_ptr = password.as_mut_ptr();
    unsafe {
        std::ptr::write_bytes(raw_ptr, 0xFF, password.len());
    }
    run::run();
    let og_uid: usize = rid.try_into().unwrap();
    let og_gid: usize = grid.try_into().unwrap();
    uid::setuid(og_uid, og_gid).unwrap(); //rid was the user's id.
}
