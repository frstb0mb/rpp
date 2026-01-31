use bit_field::BitField;
use bitflags::bitflags;

bitflags! {
    pub struct UnwindFlag: u8 {
        const UNW_FLAG_NHANDLER = 0;
        const UNW_FLAG_EHANDLER = 1;
        const UNW_FLAG_UHANDLER = 2;
        const UNW_FLAG_CHAININFO = 4;
    }
}

pub struct UnwindCode {
    pub code_offset: u8,
    pub unwid_op: u8,
    pub op_info: u8,
}

pub struct UnwindCodeIter<'a> {
    pub codes: std::slice::Iter<'a, u16>,
}

impl<'a> Iterator for UnwindCodeIter<'a> {
    type Item = UnwindCode;
    fn next(&mut self) -> Option<Self::Item> {
        let raw = self.codes.next()?;
        Some(
            UnwindCode {
                code_offset: raw.get_bits(0..8) as u8,
                unwid_op: raw.get_bits(8..12) as u8,
                op_info: raw.get_bits(12..16) as u8,
            }
        )
    }
}

pub struct UnwindInfo {
    pub version: u8,
    pub flags: UnwindFlag,
    pub size_of_prolog: u8,
    pub count_of_codes: u8,
    pub frame_register: u8,
    pub frame_offset: u8,
    //pub unwind_codes: Option<Vec<UnwindCode>>,
}

impl UnwindInfo {
    pub fn new(raw:u32) -> Self {
        UnwindInfo {
            version:        raw.get_bits(0..3)      as u8,
            flags:          UnwindFlag::from_bits_truncate(raw.get_bits(3..8) as u8),
            size_of_prolog: raw.get_bits(8..16)     as u8,
            count_of_codes: raw.get_bits(16..24)    as u8,
            frame_register: raw.get_bits(24..28)    as u8,
            frame_offset:   raw.get_bits(28..32)    as u8,
        }
    }
}

