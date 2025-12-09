use std::env::{
    args,
    set_var,
    remove_var,
};
use std::process::Command;

//This module handles the running part. It also removes harmful env variables and sets a
//pre-determined path.(Aka: PATH=/usr/bin
//
//Returns (command, [args])
fn args_sanitize () -> Vec<String> {
    //Firstly, lets set the PATH Variable to a more secure list(Sudo's default.).
    let path = "PATH";
    let path_value = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    unsafe {
        set_var(path, path_value);
    }
    //Now, we remove all the variables we do not want.
    let no_keep = ["LD_PRELOAD", "LD_LIBRARY_PATH", "SHELL", "BASH_ENV", "ENV"];

    unsafe {
        for var in no_keep.iter() {
            remove_var(var) 
        }
    }
    //Now lets get the arguments.
    let arguments: Vec<String> = args().collect();
    return arguments;
}

pub fn run() -> () {
    let cmdline = args_sanitize();
    //Now lets use std::process::Command. but first lets just use std::process::Command.env_clear() just to
    //be safe.
    
    if cmdline.len() == 1 {
        return //There is nothing to run. So do nothing.
    }

    let command = &cmdline[1];
    let args = &cmdline[2..];
    let mut cmd = Command::new(command);
    cmd
        .args(args)
        .stdout(std::process::Stdio::inherit())
        .stdin(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    Command::env_clear(&mut cmd);
    match cmd.status() {
        Ok(status) => {
            println!("Command completed with status code: {status}");
        },
        Err(e) => {
            println!("Command failed with error code: {e:?}");
        }
    }
}
