use anyhow::{Result, anyhow};
use std::ffi::CStr;

pub const ERR_CMD_NOT_SUPPORTED: i32 = 126;

pub fn parse_response<'a>(field: &str, buffer: &'a [u8], err: i32, cmd: u64) -> Result<&'a CStr> {
    if err == ERR_CMD_NOT_SUPPORTED {
        return Err(anyhow!(
            "CMD: '0x{cmd:x}', SUSFS operation not supported, please enable it in kernel"
        ));
    }
    if err != 0 {
        return Err(anyhow!("Invalid (Error: {err})"));
    }
    CStr::from_bytes_until_nul(buffer)
        .map_err(|_| anyhow!("Invalid {field} response: missing NUL terminator"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_bounded_value() {
        let value =
            parse_response("version", b"2.1.0\0ignored", 0, 0x555e1).expect("valid response");
        assert_eq!(value.to_bytes(), b"2.1.0");
    }

    #[test]
    fn accepts_empty_value() {
        let value = parse_response("features", b"\0", 0, 0x555e2).expect("empty response is valid");
        assert!(value.to_bytes().is_empty());
    }

    #[test]
    fn rejects_error_before_buffer_access() {
        let error = parse_response("features", &[b'x'; 8], 5, 0x555e2)
            .expect_err("errno must fail before parsing");
        assert_eq!(error.to_string(), "Invalid (Error: 5)");
    }

    #[test]
    fn preserves_unsupported_error() {
        let error = parse_response("variant", &[b'x'; 8], ERR_CMD_NOT_SUPPORTED, 0x555e3)
            .expect_err("unsupported command must fail");
        assert!(error.to_string().contains("operation not supported"));
    }

    #[test]
    fn rejects_full_buffer_without_nul() {
        let error = parse_response("version", &[b'x'; 16], 0, 0x555e1)
            .expect_err("unterminated response must fail");
        assert!(error.to_string().contains("missing NUL terminator"));
    }
}
