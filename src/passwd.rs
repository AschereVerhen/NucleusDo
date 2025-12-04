use syscalls::{syscall, Sysno, Errno};

const TCGETS: usize = 0x5401;
const TCSETS: usize = 0x5402;
const ECHO: u32 = 0x00000008;

#[repr(C)]
#[derive(Clone, Debug)]
struct Termios {
    c_iflags: u32, //Input Flags,
    c_oflags: u32, //Output flags,
    c_cflags: u32, //Control flags
    c_lflags: u32, //Local flags
    line: u8,
    cc: [u8; 32],
    ispeed: u32,
    ospeed: u32,
}

fn get_termios(fd: usize) -> Result<Termios, Errno> {
    let mut termios = Termios {
        c_iflags: 0,
        c_oflags: 0,
        c_cflags: 0,
        c_lflags: 0,
        line: 0,
        cc: [0u8; 32],
        ispeed: 0,
        ospeed: 0,
    };

    unsafe {
        syscall!(Sysno::ioctl, fd, TCGETS, &mut termios as *mut Termios)?;
    }
    Ok(termios)
}

fn disable_echo(fd: usize, termios: &mut Termios) -> Result<(), Errno> {
    //Firstly, we will perform a bitwise and and not operaton to ensure ECHO bit is 0.
    termios.c_lflags &= !ECHO;
    //Now, we pass the new termios to ioctl with the operation as TCSETS
    unsafe {
        syscall!(Sysno::ioctl, fd, TCSETS, termios as *mut Termios)?;
    }
    Ok(())
}

fn enable_echo(fd: usize, termios: &Termios) -> Result<(), Errno> {
    unsafe {
        syscall!(Sysno::ioctl, fd, TCSETS, termios as *const Termios)?;
    }
    Ok(())
}

pub fn read_passwd() -> Result<Vec<u8>, Errno> {
    //First, lets initialse the read-write flag.
    const O_RDWR: u8 = 0o2; //this evaluates to 2.
    let tty = b"/dev/tty\0";
    let fd = unsafe {
        syscall!(Sysno::open, tty.as_ptr(), O_RDWR)
    }?;
    //lets initialise the buffer now, from where we will write the chars read from tty.
    
    let termios = get_termios(fd)?;
    let mut temp = termios.clone();
    //Disable echo.
    disable_echo(fd, &mut temp)?;
    //Lets write Enter password: to tty.
    let prompt = b"Password: \0";
    unsafe {
        syscall!(Sysno::write, fd, prompt.as_ptr(), prompt.len())?;
    }

    let mut buf = vec![0u8; 256]; //buf len is 256.

    let number_of_bytes_read = unsafe {
        syscall!(Sysno::read, fd, buf.as_mut_ptr(), buf.len())
    }?;
    enable_echo(fd, &termios)?;
    //then, we strip newlines.
    let mut vector: Vec<u8> = buf[..number_of_bytes_read as usize].to_vec();
    if let Some(pos) = vector.iter().position(|b| *b == b'\n') {
        vector.truncate(pos);
    }
    Ok(vector)
}
