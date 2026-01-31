use windows::Win32::System::{SystemServices, Diagnostics::Debug};


use super::{PEInfo};

#[derive(PartialEq)]
pub enum RelocType {
    TypeUnSupported,
    TypeZero,
    Type32bit,
    Type64bit,
}

pub struct RelocList {
    pub reloc_type: RelocType,
    pub reloc_rva: u32,
}

pub struct RelocListIter<'a> {
    list: std::slice::Iter<'a, u16>,
    base_rva: u32,
    skip: bool,
}

pub struct  RelocDescriptor<'a> {
    pub base_reloc: SystemServices::IMAGE_BASE_RELOCATION,
    pub list_iter: RelocListIter<'a>,
    pub list_count: usize,
}

pub struct RelocDescriptorIter<'a> {
    pe: &'a PEInfo<'a>,
    offset: usize,
    limit: usize,
}

impl RelocType {
    fn new(raw:u16) -> Self {
        let flag = raw & 0xF000;
        if flag == SystemServices::IMAGE_REL_BASED_ABSOLUTE as u16 * 0x1000 {
            return RelocType::TypeZero;
        }
        else if flag == SystemServices::IMAGE_REL_BASED_HIGHLOW as u16 * 0x1000 {
            return RelocType::Type32bit;
        }
        else if flag == SystemServices::IMAGE_REL_BASED_DIR64 as u16 * 0x1000 {
            return RelocType::Type64bit;
        }
        else {
            return RelocType::TypeUnSupported;
        }
    }
}

impl<'a> Iterator for RelocListIter<'a> {
    type Item = RelocList;
    fn next(&mut self) -> Option<Self::Item> {
        if self.skip == true {
            return None;
        }
        let val = *self.list.next()?;
        let reloc_type = RelocType::new(val);
        if reloc_type == RelocType::TypeZero {
            self.skip = true;
        }

        let reloc_rva = if reloc_type == RelocType::TypeZero || reloc_type == RelocType::TypeUnSupported {
            0
        }
        else {
            (val & 0xFFF) as u32 + self.base_rva
        };
        Some(
            RelocList { reloc_type, reloc_rva }
        )
    }
}


impl<'a> Iterator for RelocDescriptorIter<'a> {
    type Item = RelocDescriptor<'a>;
    fn next(&mut self) -> Option<Self::Item> {

        let base_reloc = self.pe.read_unalinged_from_offset::<SystemServices::IMAGE_BASE_RELOCATION>(self.offset)?;
        if base_reloc.SizeOfBlock == 0 || self.offset >= self.limit {
            return None;
        }

        let list_count = ((base_reloc.SizeOfBlock as usize) - size_of::<SystemServices::IMAGE_BASE_RELOCATION>()) / size_of::<u16>();
        let list_offset = self.offset + size_of::<SystemServices::IMAGE_BASE_RELOCATION>();
        if self.pe.raw.len() <= list_offset + base_reloc.SizeOfBlock as usize {
            return None;
        }
        let list_raw = &self.pe.raw[list_offset..list_offset + base_reloc.SizeOfBlock as usize];
        let list = 
            unsafe {
                std::slice::from_raw_parts(
                    list_raw.as_ptr() as *const u16,
                    list_raw.len() / std::mem::size_of::<u16>(),
                )
            };

        self.offset += base_reloc.SizeOfBlock as usize;

        Some(
            RelocDescriptor {
                base_reloc,
                list_iter: RelocListIter{list:list.iter(), base_rva: base_reloc.VirtualAddress, skip:false},
                list_count,
            }
        )
    }
}

impl<'a> PEInfo<'a> {
    pub fn get_relocs(&self) -> Option<RelocDescriptorIter<'_>>
    {
        let nt_header = self.get_nt_header().as_ref()?;
        let reloc_dir = nt_header.optional_header().data_directory(Debug::IMAGE_DIRECTORY_ENTRY_BASERELOC);
        let reloc_desc_offset = self.rva_to_offset(reloc_dir.VirtualAddress)?;

        Some(
            RelocDescriptorIter {
                pe: self,
                offset: reloc_desc_offset,
                limit: reloc_desc_offset + reloc_dir.Size as usize,
            }
        )
    }
}