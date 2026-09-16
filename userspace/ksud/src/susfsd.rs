use crate::susfs_response::{ERR_CMD_NOT_SUPPORTED, parse_response};
use anyhow::{Result, anyhow};
use libc::{SYS_reboot, syscall};

// Constants from susfsd.c
const KSU_INSTALL_MAGIC1: u64 = 0xDEAD_BEEF;
const SUSFS_MAGIC: u64 = 0xFAFA_FAFA;

const CMD_SUSFS_SHOW_VERSION: u64 = 0x555e1;
const CMD_SUSFS_SHOW_ENABLED_FEATURES: u64 = 0x555e2;
const CMD_SUSFS_SHOW_VARIANT: u64 = 0x555e3;

const SUSFS_ENABLED_FEATURES_SIZE: usize = 8192;
const SUSFS_MAX_VERSION_BUFSIZE: usize = 16;
const SUSFS_MAX_VARIANT_BUFSIZE: usize = 16;

#[repr(C)]
struct SusfsVersion {
    version: [u8; SUSFS_MAX_VERSION_BUFSIZE],
    err: i32,
}

#[repr(C)]
struct SusfsVariant {
    variant: [u8; SUSFS_MAX_VARIANT_BUFSIZE],
    err: i32,
}

#[repr(C)]
struct SusfsEnabledFeatures {
    features: [u8; SUSFS_ENABLED_FEATURES_SIZE],
    err: i32,
}

pub fn show_version() -> Result<()> {
    let mut cmd = SusfsVersion {
        version: [0; SUSFS_MAX_VERSION_BUFSIZE],
        err: ERR_CMD_NOT_SUPPORTED,
    };

    unsafe {
        syscall(
            SYS_reboot,
            KSU_INSTALL_MAGIC1,
            SUSFS_MAGIC,
            CMD_SUSFS_SHOW_VERSION,
            &raw mut cmd,
        );
    }

    let version =
        parse_response("version", &cmd.version, cmd.err, CMD_SUSFS_SHOW_VERSION)?.to_string_lossy();
    println!("{version}");
    Ok(())
}

pub fn show_variant() -> Result<()> {
    let mut cmd = SusfsVariant {
        variant: [0; SUSFS_MAX_VARIANT_BUFSIZE],
        err: ERR_CMD_NOT_SUPPORTED,
    };

    unsafe {
        syscall(
            SYS_reboot,
            KSU_INSTALL_MAGIC1,
            SUSFS_MAGIC,
            CMD_SUSFS_SHOW_VARIANT,
            &raw mut cmd,
        );
    }

    let variant =
        parse_response("variant", &cmd.variant, cmd.err, CMD_SUSFS_SHOW_VARIANT)?.to_string_lossy();
    println!("{variant}");
    Ok(())
}

pub fn show_features(check_only: bool) -> Result<()> {
    let mut cmd = SusfsEnabledFeatures {
        features: [0; SUSFS_ENABLED_FEATURES_SIZE],
        err: ERR_CMD_NOT_SUPPORTED,
    };

    unsafe {
        syscall(
            SYS_reboot,
            KSU_INSTALL_MAGIC1,
            SUSFS_MAGIC,
            CMD_SUSFS_SHOW_ENABLED_FEATURES,
            &raw mut cmd,
        );
    }

    let features_cstr = parse_response(
        "features",
        &cmd.features,
        cmd.err,
        CMD_SUSFS_SHOW_ENABLED_FEATURES,
    )?;
    let has_features = !features_cstr.to_bytes().is_empty();

    if check_only {
        if has_features {
            println!("Supported");
            Ok(())
        } else {
            Err(anyhow!("Unsupported"))
        }
    } else if has_features {
        print!("{}", features_cstr.to_string_lossy());
        Ok(())
    } else {
        Err(anyhow!("Invalid (Error: {})", cmd.err))
    }
}
