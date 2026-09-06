//! Spike A/C: mount a hello-world filesystem on macOS by dlopen-ing the vendor libfuse
//! (macFUSE or FUSE-T), calling `fuse_mount_compat25` and handing the fd to fuser.
//! For `fuse-t` the session runs with `KernelAbi::Linux` (see Spike C): FUSE-T decodes the Linux
//! struct layouts, not the macFUSE ones. `macfuse` keeps `KernelAbi::Native`.
//! Usage: cargo run -p cryptomator-mount --example spike_macos_dlopen -- <fuse-t|macfuse> <empty-mountpoint-dir>
//! Unmount from another shell with `umount <mountpoint>`; the program then exits.

#[cfg(all(target_os = "macos", feature = "fuse"))]
mod spike {
    use fuser::{
        Config, Errno, FileAttr, FileHandle, FileType, Filesystem, Generation, INodeNo, KernelAbi,
        LockOwner, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyStatfs,
        Request, Session, SessionACL,
    };
    use std::ffi::{c_char, c_int, CString, OsStr};
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::path::Path;
    use std::time::{Duration, UNIX_EPOCH};

    #[repr(C)]
    struct FuseArgs {
        argc: c_int,
        argv: *const *const c_char,
        allocated: c_int,
    }

    const TTL: Duration = Duration::from_secs(1);
    const CONTENT: &[u8] = b"Hello from crypto spike A!\n";

    fn attr(ino: u64, kind: FileType, size: u64, perm: u16, nlink: u32) -> FileAttr {
        FileAttr {
            ino: INodeNo(ino),
            size,
            blocks: 1,
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind,
            perm,
            nlink,
            uid: unsafe { libc_geteuid() },
            gid: unsafe { libc_getegid() },
            rdev: 0,
            flags: 0,
            blksize: 512,
        }
    }

    extern "C" {
        #[link_name = "geteuid"]
        fn libc_geteuid() -> u32;
        #[link_name = "getegid"]
        fn libc_getegid() -> u32;
    }

    struct HelloFs;

    impl Filesystem for HelloFs {
        fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
            if parent == INodeNo::ROOT && name == "hello.txt" {
                reply.entry(
                    &TTL,
                    &attr(2, FileType::RegularFile, CONTENT.len() as u64, 0o444, 1),
                    Generation(0),
                );
            } else {
                reply.error(Errno::ENOENT);
            }
        }

        fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
            match u64::from(ino) {
                // nlink 2 for the root directory: "." plus its entry in the parent.
                1 => reply.attr(&TTL, &attr(1, FileType::Directory, 0, 0o755, 2)),
                2 => reply.attr(
                    &TTL,
                    &attr(2, FileType::RegularFile, CONTENT.len() as u64, 0o444, 1),
                ),
                _ => reply.error(Errno::ENOENT),
            }
        }

        fn read(
            &self,
            _req: &Request,
            ino: INodeNo,
            _fh: FileHandle,
            offset: u64,
            size: u32,
            _flags: OpenFlags,
            _lock_owner: Option<LockOwner>,
            reply: ReplyData,
        ) {
            if u64::from(ino) != 2 {
                reply.error(Errno::ENOENT);
                return;
            }
            let start = (offset as usize).min(CONTENT.len());
            let end = (start + size as usize).min(CONTENT.len());
            reply.data(&CONTENT[start..end]);
        }

        fn readdir(
            &self,
            _req: &Request,
            ino: INodeNo,
            _fh: FileHandle,
            offset: u64,
            mut reply: ReplyDirectory,
        ) {
            if ino != INodeNo::ROOT {
                reply.error(Errno::ENOENT);
                return;
            }
            let entries = [
                (1u64, FileType::Directory, "."),
                (1, FileType::Directory, ".."),
                (2, FileType::RegularFile, "hello.txt"),
            ];
            for (i, (ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
                if reply.add(INodeNo(*ino), (i + 1) as u64, *kind, name) {
                    break;
                }
            }
            reply.ok();
        }

        // FUSE-T sends STATFS before anything else; fuser's default reply advertises 0 blocks,
        // which some clients treat as a broken filesystem.
        fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
            reply.statfs(1_000_000, 500_000, 500_000, 1000, 500, 4096, 255, 4096);
        }
    }

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let args: Vec<String> = std::env::args().collect();
        if args.len() != 3 {
            eprintln!("usage: spike_macos_dlopen <fuse-t|macfuse> <mountpoint>");
            std::process::exit(2);
        }
        let (lib_path, extra_opts, abi): (&str, &[&str], KernelAbi) = match args[1].as_str() {
            "fuse-t" => (
                "/usr/local/lib/libfuse-t.dylib",
                &["-o", "nonamedattr"],
                KernelAbi::Linux,
            ),
            "macfuse" => (
                "/usr/local/lib/libfuse.2.dylib",
                &["-o", "noappledouble"],
                KernelAbi::Native,
            ),
            other => {
                eprintln!("unknown backend {other}");
                std::process::exit(2);
            }
        };
        if !Path::new(lib_path).exists() {
            eprintln!("{lib_path} not found – install FUSE-T (brew install --cask macos-fuse-t/homebrew-cask/fuse-t) or macFUSE");
            std::process::exit(2);
        }
        let mountpoint = &args[2];

        // SAFETY: loading a vendor library; symbols are called with the documented libfuse 2.x C signatures.
        let lib = unsafe { libloading::Library::new(lib_path)? };
        let fuse_mount: libloading::Symbol<
            unsafe extern "C" fn(*const c_char, *const FuseArgs) -> c_int,
        > = unsafe { lib.get(b"fuse_mount_compat25\0")? };

        let mut argv_owned: Vec<CString> = vec![
            CString::new("crypto-spike")?,
            CString::new("-o")?,
            CString::new("volname=crypto-spike")?,
        ];
        for opt in extra_opts {
            argv_owned.push(CString::new(*opt)?);
        }
        let argv: Vec<*const c_char> = argv_owned.iter().map(|s| s.as_ptr()).collect();
        let fuse_args = FuseArgs {
            argc: argv.len() as c_int,
            argv: argv.as_ptr(),
            allocated: 0,
        };
        let mp = CString::new(mountpoint.as_str())?;

        let raw_fd = unsafe { fuse_mount(mp.as_ptr(), &fuse_args) };
        if raw_fd < 0 {
            return Err(format!(
                "fuse_mount_compat25 failed: {}",
                std::io::Error::last_os_error()
            )
            .into());
        }
        // SAFETY: raw_fd is a freshly returned, owned file descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let mut config = Config::default();
        config.abi = abi;
        let session = Session::from_fd(HelloFs, fd, SessionACL::Owner, config)?;
        println!(
            "mounted at {mountpoint}; in another shell run: cat {mountpoint}/hello.txt && umount {mountpoint}"
        );
        session.run()?;
        println!("session ended (unmounted)");
        Ok(())
    }
}

#[cfg(all(target_os = "macos", feature = "fuse"))]
fn main() {
    if let Err(err) = spike::run() {
        eprintln!("spike failed: {err}");
        std::process::exit(1);
    }
}

#[cfg(not(all(target_os = "macos", feature = "fuse")))]
fn main() {
    eprintln!("this spike only runs on macOS with the `fuse` feature");
    std::process::exit(2);
}
