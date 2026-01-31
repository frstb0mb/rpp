use windows::Win32::System::{Diagnostics::Debug, SystemInformation};

use super::{PEInfo, unwind, utils};

//IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY

pub struct ExceptionEntryX86<'a> {
    pub rt_function: Debug::IMAGE_RUNTIME_FUNCTION_ENTRY,
    pub unwind_info: unwind::UnwindInfo,
    pub unwind_code_iter: Option<unwind::UnwindCodeIter<'a>>,
    pub handler_rva: Option<u32>,
    pub chain_info: Option<ExceptionEntryX86Iter<'a>>,
}

pub struct ExceptionEntryX86Iter<'a> {
    pe: &'a PEInfo<'a>,
    offset:usize,
    limit:usize,
}

/*
pub struct ExceptionEntryArm64Iter<'a> {
    pe: &'a PEInfo<'a>,
}
*/

pub enum ExceptionEntryIter<'a> {
    X86(ExceptionEntryX86Iter<'a>),
    //Arm64(ExceptionEntryArm64Iter<'a>),
}

impl<'a> Iterator for ExceptionEntryX86Iter<'a> {
    type Item = ExceptionEntryX86<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.limit {
            return None;
        }

        let rt_function = self.pe.read_unalinged_from_offset::<Debug::IMAGE_RUNTIME_FUNCTION_ENTRY>(self.offset)?;
        if rt_function.BeginAddress == 0 || rt_function.BeginAddress == 0 {
            return None;
        }

        let info_offset = self.pe.rva_to_offset(unsafe{rt_function.Anonymous.UnwindInfoAddress})?;
        let info_limit = info_offset + size_of::<u32>();
        let unwind_info = unwind::UnwindInfo::new(self.pe.read_unalinged_from_offset::<u32>(info_offset)?);

        let code_limit = info_limit + unwind_info.count_of_codes as usize * size_of::<u16>();
        let unwind_code_iter = if code_limit > info_limit {
            if self.pe.raw.len() < code_limit {
                return None;
            }
            let code_raw = &self.pe.raw[info_limit..code_limit];
            let code_raw_array = unsafe {
                std::slice::from_raw_parts(
                    code_raw.as_ptr() as *const u16,
                    code_raw.len() / std::mem::size_of::<u16>(),
                )
            };
            Some(
                unwind::UnwindCodeIter {
                    codes: code_raw_array.iter(),
                }
            )
        }
        else {
            None
        };

        let handler_rva = if unwind_info.flags.contains(unwind::UnwindFlag::UNW_FLAG_EHANDLER | unwind::UnwindFlag::UNW_FLAG_UHANDLER) {
            let handler_offset = utils::align_up(code_limit, size_of::<u32>());
            self.pe.read_unalinged_from_offset::<u32>(handler_offset)
        }
        else {
            None
        };

        let chain_info = if unwind_info.flags.contains(unwind::UnwindFlag::UNW_FLAG_CHAININFO) {
            let chain_offset = info_limit + ((unwind_info.count_of_codes+1) & !1) as usize * size_of::<u16>();
            Some (
                ExceptionEntryX86Iter {
                    pe: self.pe,
                    offset: chain_offset,
                    limit: chain_offset + size_of::<Debug::IMAGE_RUNTIME_FUNCTION_ENTRY>(),
                }
            )
        }
        else {
            None
        };

        self.offset += size_of::<Debug::IMAGE_RUNTIME_FUNCTION_ENTRY>();
        Some(
            ExceptionEntryX86 {
                rt_function,
                unwind_info,
                unwind_code_iter,
                handler_rva,
                chain_info,
            }
        )
    }
}

/*
impl<'a> Iterator for ExceptionEntryIterArm64Iter<'a> {
    type Item = ExceptionEntryIterArm64;
    fn next(&mut self) -> Option<Self::Item> {
    }
}
*/

impl<'a> PEInfo<'a> {
    pub fn get_exceptions(&self) -> Option<ExceptionEntryIter<'_>>
    {
        let nt_header = self.get_nt_header().as_ref()?;
        let exception_dir = nt_header.optional_header().data_directory(Debug::IMAGE_DIRECTORY_ENTRY_EXCEPTION);
        let exception_desc_offset = self.rva_to_offset(exception_dir.VirtualAddress)?;

        match nt_header.file_header().Machine {
            SystemInformation::IMAGE_FILE_MACHINE_AMD64 => {
                Some(
                    ExceptionEntryIter::X86(
                        ExceptionEntryX86Iter {
                            pe: self,
                            offset: exception_desc_offset,
                            limit: exception_desc_offset + exception_dir.Size as usize,
                        }
                    ),
                )
            },
            /*
            SystemInformation::IMAGE_FILE_MACHINE_ARM64 => {
                Some(
                    ExceptionEntryIter::Arm64(
                        ExceptionEntryArm64Iter {

                        }
                    )
                )
            }
            */
            _ => None,
        }
    }
}