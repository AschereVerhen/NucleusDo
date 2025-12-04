use syscalls::Errno;
use yescrypt::yescrypt_verify;
use std::process::Command;
mod uid;
mod passwd;
mod shadow;
fn print_ids() {
    let (ruid,euid,suid) = uid::getuid().unwrap();
    let (rgid,egid,sgid) = uid::getgid().unwrap();

    println!(
        "UID => r={} e={} s={} | GID => r={} e={} s={}",
        ruid,euid,suid,rgid,egid,sgid
    );
    println!("Privilege state: {:?}", uid::get_state())
}

fn main() {
    //Error Codes: 1 if error is EPERM
    //2 if error is EAGAIN
    //3 if error is EINVAL
    //4 if error is EFAULT
    //255 if unknown error.
    print_ids();
    let target_uid = 0;
    let target_gid = 0;
    println!("Switching to uid: {target_uid} and gid: {target_gid} now.");
    println!("Please enter your password");
    let password = match passwd::read_passwd() {
        Ok(vec) => vec,
        Err(err) => {
            eprintln!("An error occured: {err:?}");
            uid::_exit(255);
        }
    };
    //Getting the username;
    let passwd = shadow::open_passwd().unwrap();
    let (rid, _, _) = uid::getuid().unwrap();
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
    let hash256 = shadow::get_hash256(shadow, username).unwrap();
    println!("Found hash: {}", hash256);
    let is_match = yescrypt_verify(&password, hash256.as_str()).is_ok();
    if ! is_match {
        println!("Password is invalid.");
        uid::_exit(255)
    }
    print_ids();
    println!("Password successful. You are now root.");
    let mut cmd = Command::new("/bin/nu");
    cmd
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    let status = cmd.status().unwrap();
    let og_id: usize = rid.try_into().unwrap();
    uid::setuid(og_id, og_id).unwrap(); //rid was the user's id.
}
