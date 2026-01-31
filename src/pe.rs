use windows::Win32::System::{Diagnostics::Debug, SystemServices, SystemInformation};

pub enum ExeBit {
    None,
    Bit32,
    Bit64,
}
pub enum NTHeader {
    Image32(Debug::IMAGE_NT_HEADERS32),
    Image64(Debug::IMAGE_NT_HEADERS64),
}
pub enum OptionalHeader {
    Image32(Debug::IMAGE_OPTIONAL_HEADER32),
    Image64(Debug::IMAGE_OPTIONAL_HEADER64),
}

pub struct PEInfo<'a> {
    pub(crate) raw: &'a [u8],
    pub bit: ExeBit,
    offset_nt: Option<usize>,
    nt_header: Option<NTHeader>,
    section_headers: Option<Vec<Debug::IMAGE_SECTION_HEADER>>,
}

impl NTHeader {
    pub fn signature(&self) -> u32 {
        match self {
            NTHeader::Image32(h) => h.Signature,
            NTHeader::Image64(h) => h.Signature,
        }
    }
    pub fn file_header(&self) -> Debug::IMAGE_FILE_HEADER {
        match self {
            NTHeader::Image32(h) => h.FileHeader,
            NTHeader::Image64(h) => h.FileHeader,
        }
    }
    pub fn optional_header(&self) -> OptionalHeader {
        match self {
            NTHeader::Image32(h) => OptionalHeader::Image32(h.OptionalHeader),
            NTHeader::Image64(h) => OptionalHeader::Image64(h.OptionalHeader),
        }
    }
    pub fn size(&self) -> usize {
        match self {
            NTHeader::Image32(_) => size_of::<Debug::IMAGE_NT_HEADERS32>(),
            NTHeader::Image64(_) => size_of::<Debug::IMAGE_NT_HEADERS64>(),
        }
    }
}

impl OptionalHeader {
    pub fn size_of_code(&self) -> u32 {
        match self {
            OptionalHeader::Image32(h) => h.SizeOfCode,
            OptionalHeader::Image64(h) => h.SizeOfCode,
        }
    }
    pub fn data_directory(&self, index: Debug::IMAGE_DIRECTORY_ENTRY) -> Debug::IMAGE_DATA_DIRECTORY {
        match self {
            OptionalHeader::Image32(h) => h.DataDirectory[index.0 as usize],
            OptionalHeader::Image64(h) => h.DataDirectory[index.0 as usize],
        }
    }
}

impl<'a> PEInfo<'a> {
    pub fn new(file:&'a [u8]) -> Self {
        let mut pe = PEInfo{raw: file,offset_nt:None, bit:ExeBit::None, nt_header:None, section_headers: None};
        pe.set_nt_header();
        pe.set_section_headers();
        return pe;
    }
    pub fn get_dos_header(&self) -> Option<SystemServices::IMAGE_DOS_HEADER>
    {
        if self.raw.len() < size_of::<SystemServices::IMAGE_DOS_HEADER>() {
            return None;
        }
        let dos = unsafe{std::ptr::read_unaligned(self.raw.as_ptr() as *const SystemServices::IMAGE_DOS_HEADER)};
        Some(dos)
    }
    pub fn get_nt_header(&self) -> &Option<NTHeader> {
        return &self.nt_header;
    }

    fn set_nt_header(&mut self) {
        if self.nt_header.is_some() {
            return;
        }
        if self.offset_nt.is_none() {
            if let Some(dos_header) = self.get_dos_header() {
                let offset_nt = dos_header.e_lfanew as usize;
                if self.raw.len() < offset_nt + size_of::<Debug::IMAGE_NT_HEADERS64>() {
                    return;
                }
                self.offset_nt = Some(offset_nt);
            }
            else {
                return;
            }
        }

        let nt_head_raw = &self.raw[self.offset_nt.unwrap()..];
        let nt_head = unsafe{std::ptr::read_unaligned(nt_head_raw.as_ptr() as *const Debug::IMAGE_NT_HEADERS32)};
        if matches!(nt_head.FileHeader.Machine, 
            SystemInformation::IMAGE_FILE_MACHINE_ALPHA64 | SystemInformation::IMAGE_FILE_MACHINE_AMD64 |
            SystemInformation::IMAGE_FILE_MACHINE_ARM64 | SystemInformation::IMAGE_FILE_MACHINE_IA64)
        {
            self.bit = ExeBit::Bit64;
            let nt_head = unsafe{std::ptr::read_unaligned(nt_head_raw.as_ptr() as *const Debug::IMAGE_NT_HEADERS64)};
            self.nt_header =  Some(NTHeader::Image64(nt_head));
        }
        else {
            self.bit = ExeBit::Bit32;
            self.nt_header = Some(NTHeader::Image32(nt_head));
        }
    }

    pub fn get_section_headers(&self) -> &Option<Vec<Debug::IMAGE_SECTION_HEADER>> {
        return &self.section_headers;
    }

    fn set_section_headers(&mut self) {
        if self.section_headers.is_some() {
            return;
        }
        let nt_header = self.get_nt_header();
        if let Some(nt_header) = nt_header {
            let num_section  = nt_header.file_header().NumberOfSections;
            let mut v =  Vec::<Debug::IMAGE_SECTION_HEADER>::with_capacity(num_section as usize);
            
            if let Some(offset_nt) = self.offset_nt {
                let offset_section = offset_nt + nt_header.size();
                for i in 0 .. num_section {
                    let section_raw = &self.raw[offset_section + i as usize * size_of::<Debug::IMAGE_SECTION_HEADER>()..];
                    v.push( unsafe{std::ptr::read_unaligned(section_raw.as_ptr() as *const Debug::IMAGE_SECTION_HEADER)});
                }
                self.section_headers = Some(v);
            }
        }
    }

    pub fn rva_to_offset(&self, rva:u32) -> Option<usize>
    {
        if let Some(section_headers) = &self.section_headers{
           for section_header in section_headers {
                if section_header.VirtualAddress <= rva && section_header.VirtualAddress + section_header.SizeOfRawData > rva {
                    return Some((section_header.PointerToRawData + rva - section_header.VirtualAddress) as usize);
                }
           } 
        }
        None
    }

    pub fn read_unalinged_from_offset<T>(&self, offset:usize) -> Option<T>{
        if self.raw.len() < offset + size_of::<T>() {
            return None;
        }

        let raw = &self.raw[offset..offset + size_of::<T>()];
        Some(unsafe{std::ptr::read_unaligned(raw.as_ptr() as *const T)})
    }

    pub fn read_unalinged_from_offset_arb<T>(&self, offset:usize, size:usize) -> Option<T>{
        if self.raw.len() < offset + size {
            return None;
        }

        let raw = &self.raw[offset..offset + size];
        Some(unsafe{std::ptr::read_unaligned(raw.as_ptr() as *const T)})
    }
}