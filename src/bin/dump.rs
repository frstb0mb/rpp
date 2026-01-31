use std::{error::Error, fs::File, env};
use memmap2::Mmap;
use windows::Win32::System::Diagnostics::Debug;

use rpp::{PEInfo, import, relocs::RelocType, exceptions};

fn print_unwind_info(exception: exceptions::ExceptionEntryX86<'_>) {
    println!("{:x} {:x} {:x}", exception.rt_function.BeginAddress, exception.rt_function.EndAddress, unsafe{exception.rt_function.Anonymous.UnwindInfoAddress});
    println!("{:x} {:x} {:x} {:x} {:x} {:x}", exception.unwind_info.version, exception.unwind_info.flags, exception.unwind_info.size_of_prolog,
                                exception.unwind_info.count_of_codes, exception.unwind_info.frame_register, exception.unwind_info.frame_offset);
    if let Some(handler_rva) = exception.handler_rva {
        println!("{:x}", handler_rva);
    }

    if let Some(unwind_codes) = exception.unwind_code_iter {
        for code in unwind_codes {
            println!("    {:x} {:x} {:x}", code.code_offset, code.unwid_op, code.op_info);
        }
    }

    if let Some(chain_infos) = exception.chain_info {
        println!("ChainInfo");
        for chain_info in chain_infos {
            print_unwind_info(chain_info);
        }
        println!("ChainInfoEnd");
    }
    
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let file = if args.len() <= 1 {
        File::open("C:\\Windows\\system32\\kernel32.dll")?
    }
    else {
        File::open(args[1].clone())?
    };

    let mapped_file = unsafe {Mmap::map(&file)?};
    let pe = PEInfo::new(&mapped_file[..]);
    let e_lfanew = pe.get_dos_header().unwrap().e_lfanew;
    println!("{:x}",e_lfanew);

    println!("{:x}", pe.get_nt_header().as_ref().unwrap().optional_header().size_of_code());
    println!("{:x}", pe.get_nt_header().as_ref().unwrap().optional_header().data_directory(Debug::IMAGE_DIRECTORY_ENTRY_IMPORT).VirtualAddress);

    for section in pe.get_section_headers().as_ref().unwrap() {
        println!("{:x}/{:x}", section.VirtualAddress, section.SizeOfRawData);
    }

    match pe.get_imports() {
        Some(import_descs) => {
            for import_desc in import_descs {
                println!("{} {:x} {:x}", import_desc.dll_name().unwrap(), import_desc.desc.FirstThunk, import_desc.desc.Name);
                for func_desc in  import_desc.get_int().unwrap() {
                    let address: u64 = func_desc.address_of_data();
                    let func_name = func_desc.get_name().unwrap();
                    match func_name {
                        import::ImageThunkImportInfo::Name(name) => println!("    {} {:x}",name, address),
                        import::ImageThunkImportInfo::Ordinal(ordinal) => println!("    {:x} {:x}",ordinal, address),
                    }
                    
                }
            }
        },
        None => {
            println!("Cannot query import_descriptor");
        },
    }

    match pe.get_exports() {
        Some(export_desc) => {
            println!("{:x} {}", export_desc.desc.AddressOfFunctions, export_desc.get_dll_name().unwrap());

            /*
            let funcs = export_desc.get_func_rva_array().unwrap();
            for func in funcs {
                println!("    {:x}", func);
            } */
            /*
            match export_desc.get_func_names() {
                Some(exports) => {
                    for func in exports {
                        println!("    {}", func);
                    }
                },
                None => {
                    println!("No exports\n");
                }
            } */

            match export_desc.get_export_info() {
                Some(exports) => {
                    for info in exports {
                        match info.forwarder {
                            Some(forwarder) => {
                                println!("    {:x} {:x} {:x} {} {}", info.ord, info.function_rva, info.name_rva, info.function_name, forwarder);
                            },
                            _ => {
                                println!("    {:x} {:x} {:x} {}", info.ord, info.function_rva, info.name_rva, info.function_name);
                            }
                        }
                    }
                }
                None => {
                    println!("No exports info\n");
                }
            }
            
            
            /*
            for export_desc in export_descs {
                println!("{} {:x} {:x}", import_desc.dll_name().unwrap(), import_desc.desc.FirstThunk, import_desc.desc.Name);
                for func_desc in  import_desc.get_int().unwrap() {
                    let address: u64 = func_desc.address_of_data();
                    let func_name = func_desc.get_name().unwrap();
                    match func_name {
                        import::ImageThunkImportInfo::Name(name) => println!("    {} {:x}",name, address),
                        import::ImageThunkImportInfo::Ordinal(ordinal) => println!("    {:x} {:x}",ordinal, address),
                    }
                    
                }
            } */
        },
        None => {
            println!("Cannot query export_descriptor");
        },
    }

    match pe.get_relocs() {
            Some(reloc_descs) => {
                for reloc_desc in reloc_descs {
                    println!("{:x} {:x} {:x}", reloc_desc.base_reloc.VirtualAddress, reloc_desc.base_reloc.SizeOfBlock, reloc_desc.list_count);
                    
                    for elem in reloc_desc.list_iter {
                        let reloc_type = match elem.reloc_type {
                            RelocType::Type32bit => {
                                "Type32"
                            },
                            RelocType::Type64bit => {
                                "Type64"
                            },
                            RelocType::TypeZero => {
                                "TypeZero"
                            },
                            _ => {
                                "TypeUnknown"
                            },
                        };
                        println!("    {:x} {}", elem.reloc_rva, reloc_type);
                    }
                }
            },
            None => {
                println!("Cannot query reloc_descriptor");
            }
    }

    match pe.get_exceptions() {
        Some(exception) => {
            if let exceptions::ExceptionEntryIter::X86(exceptions) = exception {
                for exception in exceptions {
                    print_unwind_info(exception);
                }
            }
            
        },
        None => {
            println!("Cannot query exception");
        }
    }

    Ok(())
}
