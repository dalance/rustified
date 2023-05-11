use elf::File;
use exe::pe::{VecPE, PE};
use exe::types::CCharString;
use std::path::Path;
use walkdir::WalkDir;

static RUST_FUNCTIONS: &[&'static str] = &["rust_panic", "rust_eh_personality"];

fn main() {
    for entry in WalkDir::new(".").into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let path = entry.path();
            match rustified(&path) {
                Rustified::Maybe { cause } => {
                    println!("{} ({})", path.to_string_lossy(), cause)
                }
                Rustified::Not => (),
            }
        }
    }
}

enum FileType {
    Elf,
    Pe,
    Unknown,
}

enum Rustified {
    Maybe { cause: String },
    Not,
}

fn rustified<T: AsRef<Path>>(path: T) -> Rustified {
    if let Ok(binary) = std::fs::read(&path) {
        let filetype = check_filetype(&binary);
        match filetype {
            FileType::Elf => rustified_elf(&binary),
            FileType::Pe => rustified_pe(&binary),
            FileType::Unknown => Rustified::Not,
        }
    } else {
        Rustified::Not
    }
}

fn check_filetype(binary: &[u8]) -> FileType {
    if File::open_stream(binary).is_ok() {
        return FileType::Elf;
    }

    let image = VecPE::from_disk_data(binary);
    if image.get_section_table().is_ok() {
        return FileType::Pe;
    }
    FileType::Unknown
}

fn rustified_elf(binary: &[u8]) -> Rustified {
    let mut file = File::open_stream(binary).unwrap();
    if let Some((sym_table, str_table)) = file.symbol_table().unwrap() {
        for sym in sym_table.iter() {
            let sym_name = str_table.get(sym.st_name as usize).unwrap();
            for func in RUST_FUNCTIONS {
                if sym_name.contains(func) {
                    return Rustified::Maybe {
                        cause: String::from(format!("function \"{}\" is found", sym_name)),
                    };
                }
            }
        }
        Rustified::Not
    } else if let Some((sym_table, str_table)) = file.dynamic_symbol_table().unwrap() {
        for sym in sym_table.iter() {
            let sym_name = str_table.get(sym.st_name as usize).unwrap();
            for func in RUST_FUNCTIONS {
                if sym_name.contains(func) {
                    return Rustified::Maybe {
                        cause: String::from(format!("function \"{}\" is found", sym_name)),
                    };
                }
            }
        }
        Rustified::Not
    } else {
        Rustified::Not
    }
}

fn rustified_pe(binary: &[u8]) -> Rustified {
    let image = VecPE::from_disk_data(binary);
    let sections = image.get_section_table().unwrap();

    for section in sections {
        match section.name.as_str() {
            Ok(x) if x == ".data" => {
                let buf = section
                    .pointer_to_raw_data
                    .read(&image, section.size_of_raw_data as usize)
                    .unwrap();
                for func in RUST_FUNCTIONS {
                    if find_subsequence(buf, func.as_bytes()).is_some() {
                        return Rustified::Maybe {
                            cause: String::from(format!("function \"{}\" is found", func)),
                        };
                    }
                }
            }
            _ => (),
        }
    }
    Rustified::Not
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
