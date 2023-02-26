#[cfg(feature = "sandbox")]
/// Initialize sandbox
pub fn init_sandbox() {
    if cfg!(target_os = "linux") {
        drop_capabilities();

        if let Err(err) = init_landlock() {
            log::warn!("Failed to apply Landlock filter: {err}");
        };

        init_seccomp();
    } else {
        log::debug!("No sandbox available");
    }
}

/// Drop unneeded Linux capabilities
#[cfg(all(feature = "sandbox", target_os = "linux"))]
fn drop_capabilities() {
    use caps::{CapSet, Capability, CapsHashSet};

    if std::env::var("STARSHIP_CAPABILITY_SKIP").is_ok() {
        log::info!(
            "Not dropping capabilities due to environment variable STARSHIP_CAPABILITY_SKIP set"
        );
        return;
    }

    let cur = match caps::read(None, CapSet::Permitted) {
        Ok(cur) => cur,
        Err(err) => {
            log::warn!("Failed to get permitted capability set: {err}");
            return;
        }
    };

    if cur.is_empty() {
        log::debug!("Current permitted capability set is empty");
        return;
    }

    let mut newcaps = CapsHashSet::new();

    if cur.contains(&Capability::CAP_DAC_READ_SEARCH) {
        newcaps.insert(Capability::CAP_DAC_READ_SEARCH);
    }

    if let Err(err) = caps::set(None, CapSet::Effective, &newcaps) {
        log::warn!("Failed to set effective capability set: {err}");
        return;
    }

    if let Err(err) = caps::set(None, CapSet::Permitted, &newcaps) {
        log::warn!("Failed to set permitted capability set: {err}");
        return;
    }

    match caps::read(None, CapSet::Permitted) {
        Ok(cur) => {
            if cur.is_empty() {
                log::debug!("Current permitted capability set is empty");
            } else if cur.len() == 1 && cur.contains(&Capability::CAP_DAC_READ_SEARCH) {
                log::debug!("Current permitted capability set: {:?}", cur);
            } else {
                log::warn!("Current permitted capability set: {:?}", cur);
            }
        }
        Err(err) => log::warn!("Failed to get permitted capabilities: {err}"),
    }
}

/// Initialize landlock filter
#[cfg(all(feature = "sandbox", target_os = "linux"))]
fn init_landlock() -> Result<(), landlock::RulesetError> {
    use landlock::{
        path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus, ABI,
    };

    if std::env::var("STARSHIP_LANDLOCK_SKIP").is_ok() {
        log::info!(
            "Skipping Landlock filter due to environment variable STARSHIP_LANDLOCK_SKIP set"
        );
        return Ok(());
    }

    let abi = ABI::V2;
    let status = Ruleset::new()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        .add_rules(path_beneath_rules(&["/"], AccessFs::from_read(abi)))?
        // git(1) opens /dev/null with O_RDWR to sanitize standard file descriptors
        .add_rules(path_beneath_rules(&["/dev/null"], AccessFs::from_all(abi)))?
        .restrict_self()?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => log::debug!("Landlock fully enforced"),
        RulesetStatus::PartiallyEnforced => log::debug!("Landlock partially enforced"),
        RulesetStatus::NotEnforced => log::warn!("Landlock not enforced (probably too old kernel)"),
    }

    Ok(())
}

/// Initialize seccomp filter
#[cfg(all(feature = "sandbox", target_os = "linux"))]
fn init_seccomp() {
    if std::env::var("STARSHIP_SECCOMP_SKIP").is_ok() {
        log::info!("Skipping seccomp filter due to environment variable STARSHIP_SECCOMP_SKIP set");
        return;
    }

    let arch = match std::env::consts::ARCH.try_into() {
        Ok(a) => a,
        Err(e) => {
            log::warn!("Skipping seccomp filter due to unsupported architecture: {e}");
            return;
        }
    };

    const JSON_FILTER: &str = r#"{
    "main": {
        "mismatch_action": "trap",
        "match_action": "allow",
        "filter": [
            {
                "syscall": "access"
            },
            {
                "syscall": "arch_prctl"
            },
            {
                "syscall": "bind"
            },
            {
                "syscall": "brk"
            },
            {
                "syscall": "chdir"
            },
            {
                "syscall": "clone3"
            },
            {
                "syscall": "close"
            },
            {
                "syscall": "dup2"
            },
            {
                "syscall": "execve"
            },
            {
                "syscall": "exit"
            },
            {
                "syscall": "exit_group"
            },
            {
                "syscall": "fcntl",
                "args": [
                    {
                        "index": 1,
                        "type": "dword",
                        "op": "eq",
                        "val": 1,
                        "comment": "F_GETFD"
                    }
                ]
            },
            {
                "syscall": "fcntl",
                "args": [
                    {
                        "index": 1,
                        "type": "dword",
                        "op": "eq",
                        "val": 3,
                        "comment": "F_GETFL"
                    }
                ]
            },
            {
                "syscall": "futex"
            },
            {
                "syscall": "getcwd"
            },
            {
                "syscall": "getdents64"
            },
            {
                "syscall": "getegid"
            },
            {
                "syscall": "geteuid"
            },
            {
                "syscall": "getgid"
            },
            {
                "syscall": "getpid"
            },
            {
                "syscall": "getppid"
            },
            {
                "syscall": "getrandom"
            },
            {
                "syscall": "getsockname"
            },
            {
                "syscall": "getuid"
            },
            {
                "syscall": "ioctl",
                "args": [
                    {
                        "index": 1,
                        "type": "dword",
                        "op": "ne",
                        "val": 21522,
                        "comment": "Forbid TIOCSTI"
                   }
                ]
            },
            {
                "syscall": "lseek"
            },
            {
                "syscall": "madvise"
            },
            {
                "syscall": "mmap"
            },
            {
                "syscall": "mprotect"
            },
            {
                "syscall": "munmap"
            },
            {
                "syscall": "newfstatat"
            },
            {
                "syscall": "open",
                "args": [
                    {
                        "index": 1,
                        "type": "dword",
                        "op": {
                            "masked_eq": 1601
                        },
                        "val": 0,
                        "comment": "Forbid O_CREAT|O_TRUNC|O_APPEND|O_WRONLY; use 1603 (including O_RDWR) once git does not open /dev/null anymore"
                   }
                ]
            },
            {
                "syscall": "openat",
                "args": [
                    {
                        "index": 2,
                        "type": "dword",
                        "op": {
                            "masked_eq": 1601
                        },
                        "val": 0,
                        "comment": "Forbid O_CREAT|O_TRUNC|O_APPEND|O_WRONLY; use 1603 (including O_RDWR) once git does not open /dev/null anymore"
                   }
                ]
            },
            {
                "syscall": "pipe2"
            },
            {
                "syscall": "poll"
            },
            {
                "syscall": "pread64"
            },
            {
                "syscall": "prlimit64"
            },
            {
                "syscall": "read"
            },
            {
                "syscall": "readlink"
            },
            {
                "syscall": "recvfrom"
            },
            {
                "syscall": "rseq"
            },
            {
                "syscall": "rt_sigaction"
            },
            {
                "syscall": "rt_sigprocmask"
            },
            {
                "syscall": "rt_sigreturn"
            },
            {
                "syscall": "sched_getaffinity"
            },
            {
                "syscall": "sched_yield"
            },
            {
                "syscall": "sendto"
            },
            {
                "syscall": "set_robust_list"
            },
            {
                "syscall": "set_tid_address"
            },
            {
                "syscall": "sigaltstack"
            },
            {
                "syscall": "socket",
                "args": [
                    {
                        "index": 0,
                        "type": "dword",
                        "op": "eq",
                        "val": 16,
                        "comment": "AF_NETLINK"
                    },
                    {
                        "index": 1,
                        "type": "dword",
                        "op": "eq",
                        "val": 3,
                        "comment": "SOCK_RAW"
                    },
                    {
                        "index": 2,
                        "type": "dword",
                        "op": "eq",
                        "val": 0,
                        "comment": "NETLINK_ROUTE"
                    }
                ]
            },
            {
                "syscall": "statx"
            },
            {
                "syscall": "sysinfo"
            },
            {
                "syscall": "uname"
            },
            {
                "syscall": "vfork"
            },
            {
                "syscall": "wait4"
            },
            {
                "syscall": "waitid"
            },
            {
                "syscall": "write"
            }
        ]
    }
}"#;

    let filter_map = seccompiler::compile_from_json(JSON_FILTER.as_bytes(), arch)
        .expect("Failed to parse JSON seccomp filter");
    let filter = filter_map
        .get("main")
        .expect("Failed to get seccomp program from parsed filter");

    seccompiler::apply_filter(filter).expect("Failed to apply seccomp filter");

    log::debug!("Seccomp filter applied");
}
