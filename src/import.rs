use windows::Win32::System::{SystemServices, WindowsProgramming, Diagnostics::Debug};

use super::{PEInfo, pe::ExeBit, utils};


pub enum ImageThunkDataEnum {
    Image32(WindowsProgramming::IMAGE_THUNK_DATA32),
    Image64(WindowsProgramming::IMAGE_THUNK_DATA64),
}

pub enum ImageThunkImportInfo<'a> {
    Ordinal(u64),
    Name(&'a str),
}

pub struct ImportDescriptor<'a> {
    pe: &'a PEInfo<'a>,
    pub desc: SystemServices::IMAGE_IMPORT_DESCRIPTOR,
}

pub struct ImportDescriptorIter<'a> {
    pe: &'a PEInfo<'a>,
    offset: usize,
    limit: usize,
}

pub struct ImageThunkData<'a> {
    pe: &'a PEInfo<'a>,
    pub thunk: ImageThunkDataEnum,
}

pub struct ImageThunkDataIter<'a> {
    pe: &'a PEInfo<'a>,
    thunk_offset: usize,
}

impl<'a> ImportDescriptor<'a> {
    pub fn dll_name(&self) -> Option<&'a str> {
        let str_offset = self.pe.rva_to_offset(self.desc.Name)?;
        utils::conv_str_from_u8array(self.pe.raw, str_offset)
    }

    pub fn get_int(&self) -> Option<ImageThunkDataIter<'a>> {
        let thunk_offset = self.pe.rva_to_offset(unsafe{self.desc.Anonymous.OriginalFirstThunk})?;
        Some(ImageThunkDataIter {
            pe: self.pe,
            thunk_offset,
        })
    }

}

impl<'a> Iterator for ImportDescriptorIter<'a> {
    type Item = ImportDescriptor<'a>;
    fn next(&mut self) -> Option<Self::Item>
    {
        if self.offset >= self.limit {
            return None;
        }

        let desc =  self.pe.read_unalinged_from_offset::<SystemServices::IMAGE_IMPORT_DESCRIPTOR>(self.offset)?;
        if unsafe { desc.Anonymous.Characteristics == 0 } &&
            desc.FirstThunk == 0 && desc.ForwarderChain == 0 && desc.Name == 0 && desc.TimeDateStamp == 0 {
            return None;
        }
        self.offset += size_of::<SystemServices::IMAGE_IMPORT_DESCRIPTOR>();
        Some(ImportDescriptor{
            pe: self.pe,
            desc: desc,
        })
    }
}

impl<'a> ImageThunkData<'a> {
    pub fn forwarder_string(&self) -> u64 {
        match self.thunk {
            ImageThunkDataEnum::Image32(h) => unsafe {h.u1.ForwarderString as u64},
            ImageThunkDataEnum::Image64(h) => unsafe {h.u1.ForwarderString},
        }
    }
    pub fn function(&self) -> u64 {
        match self.thunk {
            ImageThunkDataEnum::Image32(h) => unsafe {h.u1.Function as u64},
            ImageThunkDataEnum::Image64(h) => unsafe {h.u1.Function},
        }
    }
    pub fn oridinal(&self) -> u64 {
        match self.thunk {
            ImageThunkDataEnum::Image32(h) => unsafe {h.u1.Ordinal as u64},
            ImageThunkDataEnum::Image64(h) => unsafe {h.u1.Ordinal},
        }
    }
    pub fn address_of_data(&self) -> u64 {
        match self.thunk {
            ImageThunkDataEnum::Image32(h) => unsafe {h.u1.AddressOfData as u64},
            ImageThunkDataEnum::Image64(h) => unsafe {h.u1.AddressOfData},
        }
    }

    pub fn size(&self) -> usize {
        match self.thunk {
            ImageThunkDataEnum::Image32(_) => size_of::<WindowsProgramming::IMAGE_THUNK_DATA32>(),
            ImageThunkDataEnum::Image64(_) => size_of::<WindowsProgramming::IMAGE_THUNK_DATA64>(),
        }
    }
    pub fn is_zero(&self) -> bool {
        self.forwarder_string() == 0
    }

    pub fn get_name(&self) -> Option<ImageThunkImportInfo<'a>> {
        let ordinal = self.oridinal();
        let flag = match self.thunk {
            ImageThunkDataEnum::Image32(_) => 0x80000000,
            ImageThunkDataEnum::Image64(_) => 0x8000000000000000,
        };
        if ordinal & flag != 0 {
            return Some(ImageThunkImportInfo::Ordinal(ordinal ^ flag));
        }

        let str_offset = self.pe.rva_to_offset(self.address_of_data() as u32)? + size_of::<u16>();
        let name = utils::conv_str_from_u8array(self.pe.raw, str_offset)?;
        Some(ImageThunkImportInfo::Name(name))
    }
}

impl<'a> Iterator for ImageThunkDataIter<'a> {
    type Item = ImageThunkData<'a>;
    fn next(&mut self) -> Option<Self::Item>
    {
        let thunk = match self.pe.bit {
            ExeBit::Bit32 => {
                let thunk = self.pe.read_unalinged_from_offset::<WindowsProgramming::IMAGE_THUNK_DATA32>(self.thunk_offset)?;
                ImageThunkDataEnum::Image32(thunk)
            }
            ExeBit::Bit64 => {
                let thunk = self.pe.read_unalinged_from_offset::<WindowsProgramming::IMAGE_THUNK_DATA64>(self.thunk_offset)?;
                ImageThunkDataEnum::Image64(thunk)
            },
            _ => return None,
        };
        let thunk_data = ImageThunkData { pe:self.pe, thunk };

        if thunk_data.is_zero() {
            return None;
        }

        self.thunk_offset += thunk_data.size();
        Some(thunk_data)
    }
}

impl<'a> PEInfo<'a>  {
    pub fn get_imports(&self) -> Option<ImportDescriptorIter<'_>> {
        let nt_headedr = self.get_nt_header().as_ref()?;
        let image_dir = nt_headedr.optional_header().data_directory(Debug::IMAGE_DIRECTORY_ENTRY_IMPORT);
        let import_desc_offset = self.rva_to_offset(image_dir.VirtualAddress)?;

        if self.raw.len() < import_desc_offset + image_dir.Size as usize {
            return None;
        }
        Some(
            ImportDescriptorIter {
                pe: self,
                offset: import_desc_offset,
                limit: import_desc_offset + image_dir.Size as usize,
            }
        )
    }
}