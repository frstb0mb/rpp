use std::ffi::CStr;

pub fn conv_str_from_u8array(base:&[u8], offset:usize) -> Option<&str> {
    if base.len() <= offset {
        return None;
    }

    if let Ok(cstr) = CStr::from_bytes_until_nul(&base[offset..]) {
        if let Ok(ret) = cstr.to_str() {
            return Some(ret);
        }
    }
    None
}

pub fn align_up(val:usize, align:usize) -> usize {
    (val+(align-1))&(!(align-1))
}