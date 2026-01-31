use windows::Win32::System::{SystemServices, Diagnostics::Debug};

use super::{PEInfo, macros, utils};

pub struct ExportDescriptor<'a> {
    pe: &'a PEInfo<'a>,
    pub desc: SystemServices::IMAGE_EXPORT_DIRECTORY,
}

pub struct RVAArrayIter<'a> {
    pe: &'a PEInfo<'a>,
    index: usize,
    array: &'a [u32],
}

pub struct ExportInfoDescriptor<'a> {
    pub ord:u16,
    pub function_rva: u32,
    pub name_rva: u32,
    pub function_name: &'a str,
    pub forwarder: Option<&'a str>,
}

pub struct ExportInfoDescriptorIter<'a> {
    pe: &'a PEInfo<'a>,
    func_rva_array: &'a [u32],
    name_rva_iter: std::slice::Iter<'a, u32>,
    ord_iter: std::slice::Iter<'a, u16>,
}

impl<'a> ExportDescriptor<'a> {
    pub fn get_dll_name(&self) -> Option<&str>
    {
        let name_offset = self.pe.rva_to_offset(self.desc.Name)?;
        utils::conv_str_from_u8array(self.pe.raw, name_offset)
    }

    pub fn get_func_rva_array(&self) -> Option<&[u32]> {
        macros::rva_array!(self, self.desc.AddressOfFunctions, self.desc.NumberOfFunctions, u32)
    }

    pub fn get_name_rva_array(&self) -> Option<&[u32]> {
        macros::rva_array!(self, self.desc.AddressOfNames, self.desc.NumberOfNames, u32)
    }

    pub fn get_ord_array(&self) -> Option<&[u16]> {
        macros::rva_array!(self, self.desc.AddressOfNameOrdinals, self.desc.NumberOfNames, u16)
    }

    pub fn get_func_names(&self) -> Option<RVAArrayIter<'_>> {
        let array = self.get_name_rva_array()?;
        Some(
            RVAArrayIter {
                pe: self.pe,
                index: 0,
                array: array,
            }
        )
    }

    pub fn get_export_info(&self) -> Option<ExportInfoDescriptorIter<'_>> {
        Some(
            ExportInfoDescriptorIter {
                pe:self.pe,
                func_rva_array: self.get_func_rva_array()?,
                name_rva_iter: self.get_name_rva_array()?.iter(),
                ord_iter: self.get_ord_array()?.iter(),
            }
        )
    }

}

impl<'a> Iterator for RVAArrayIter<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.array.len() {
            return None;
        }
        let rva = self.array[self.index];
        self.index += 1;

        let offset = self.pe.rva_to_offset(rva)?;
        utils::conv_str_from_u8array(self.pe.raw, offset)
    }
}

impl<'a> Iterator for ExportInfoDescriptorIter<'a> {
    type Item = ExportInfoDescriptor<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let ord = *self.ord_iter.next()?;
        let name_rva = *self.name_rva_iter.next()?;
        let function_rva = *self.func_rva_array.get(ord as usize)?;
        let export_dir = self.pe.get_nt_header().as_ref()?.optional_header().data_directory(Debug::IMAGE_DIRECTORY_ENTRY_EXPORT);
        
        let forwarder = if function_rva >= export_dir.VirtualAddress && function_rva < export_dir.VirtualAddress + export_dir.Size {
            utils::conv_str_from_u8array(self.pe.raw, self.pe.rva_to_offset(function_rva)?)
        }
        else {
            None
        };

        Some(
            ExportInfoDescriptor {
                    ord,
                    function_rva,
                    name_rva,
                    function_name:utils::conv_str_from_u8array(self.pe.raw, self.pe.rva_to_offset(name_rva)?)?,
                    forwarder,
            }
        )
    }
}

impl<'a> PEInfo<'a> {
    pub fn get_exports(&self) -> Option<ExportDescriptor<'_>>
    {
        let nt_header = self.get_nt_header().as_ref()?;
        let export_dir = nt_header.optional_header().data_directory(Debug::IMAGE_DIRECTORY_ENTRY_EXPORT);
        let export_desc_offset = self.rva_to_offset(export_dir.VirtualAddress)?;

        Some(
            ExportDescriptor {
                pe: self,
                desc: self.read_unalinged_from_offset_arb::<SystemServices::IMAGE_EXPORT_DIRECTORY>(export_desc_offset, export_dir.Size as usize)?,
            }
        )
    }
}