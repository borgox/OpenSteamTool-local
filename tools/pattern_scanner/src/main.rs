use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

fn fnv1a_hash(s: &str) -> u32 {
    let mut hash = 0x811c9dc5;
    for &byte in s.as_bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

struct Section {
    name: String,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
}

struct PeFile<'a> {
    data: &'a [u8],
    sections: Vec<Section>,
}

impl<'a> PeFile<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        if data.len() < 0x40 {
            return Err("File too small for DOS header");
        }
        if &data[0..2] != b"MZ" {
            return Err("Missing MZ signature");
        }
        let pe_offset = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
        if data.len() < pe_offset + 24 {
            return Err("File too small for NT headers");
        }
        if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return Err("Missing PE signature");
        }
        let num_sections = u16::from_le_bytes(data[pe_offset + 6..pe_offset + 8].try_into().unwrap()) as usize;
        let size_of_opt_header = u16::from_le_bytes(data[pe_offset + 20..pe_offset + 22].try_into().unwrap()) as usize;

        let section_table_offset = pe_offset + 24 + size_of_opt_header;
        let mut sections = Vec::new();
        for i in 0..num_sections {
            let offset = section_table_offset + i * 40;
            if data.len() < offset + 40 {
                return Err("File truncated in section table");
            }
            let sec_data = &data[offset..offset + 40];
            let name_bytes = &sec_data[0..8];
            let mut name_len = 0;
            while name_len < 8 && name_bytes[name_len] != 0 {
                name_len += 1;
            }
            let name = String::from_utf8_lossy(&name_bytes[0..name_len]).into_owned();
            let virtual_address = u32::from_le_bytes(sec_data[12..16].try_into().unwrap());
            let size_of_raw_data = u32::from_le_bytes(sec_data[16..20].try_into().unwrap());
            let pointer_to_raw_data = u32::from_le_bytes(sec_data[20..24].try_into().unwrap());
            sections.push(Section {
                name,
                virtual_address,
                size_of_raw_data,
                pointer_to_raw_data,
            });
        }

        Ok(PeFile { data, sections })
    }

    fn file_offset_to_rva(&self, offset: usize) -> Option<u32> {
        for sec in &self.sections {
            let start = sec.pointer_to_raw_data as usize;
            let end = start + sec.size_of_raw_data as usize;
            if offset >= start && offset < end {
                return Some((offset - start) as u32 + sec.virtual_address);
            }
        }
        None
    }
}

fn parse_sig(sig_str: &str) -> Vec<Option<u8>> {
    let mut pattern = Vec::new();
    for token in sig_str.split_whitespace() {
        if token == "??" || token == "?" {
            pattern.push(None);
        } else if let Ok(val) = u8::from_str_radix(token, 16) {
            pattern.push(Some(val));
        }
    }
    pattern
}

fn scan_pattern(data: &[u8], pattern: &[Option<u8>]) -> Option<usize> {
    if pattern.is_empty() || data.len() < pattern.len() {
        return None;
    }
    for i in 0..=(data.len() - pattern.len()) {
        let mut matched = true;
        for (j, pat_byte) in pattern.iter().enumerate() {
            if let Some(b) = pat_byte {
                if data[i + j] != *b {
                    matched = false;
                    break;
                }
            }
        }
        if matched {
            return Some(i);
        }
    }
    None
}

struct SignatureDefinition {
    name: &'static str,
    sigs: Vec<&'static str>,
}

fn get_steamclient_defs() -> Vec<SignatureDefinition> {
    vec![
        SignatureDefinition {
            name: "BBuildAndAsyncSendFrame",
            sigs: vec![
                "48 8B C4 55 48 8D 68 A1 48 81 EC C0 00 00 00 48 89 70 18",
                "48 8B C4 55 48 8D 68 A1 48 81 EC C0 00 00 00",
            ],
        },
        SignatureDefinition {
            name: "BuildDepotDependency",
            sigs: vec!["48 8B C4 4C 89 48 20 89 50 10 48 89 48 08 55 57"],
        },
        SignatureDefinition {
            name: "BuildSpawnEnvBlock",
            sigs: vec![
                "4C 89 4C 24 20 4C 89 44 24 18 48 89 54 24 10 48 89 4C 24 08 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 B8 FD FF FF",
                "48 89 5C 24 20 4C 89 44 24 18 48 89 54 24 10 48 89 4C 24 08 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 B0 FD FF FF",
            ],
        },
        SignatureDefinition {
            name: "CUtlBufferEnsureCapacity",
            sigs: vec![
                "48 89 5C 24 08 57 48 83 EC 30 48 8B D9 8D 7A 01",
                "48 89 5C 24 08 57 48 83 EC 30 0F B6 41 1F",
            ],
        },
        SignatureDefinition {
            name: "CUtlMemoryGrow",
            sigs: vec![
                "48 89 5C 24 10 57 48 83 EC 30 8B FA 48 8B D9 8B 51 08 8B 49 10 8D 04 39",
                "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 30 8B 71 10 48 8B D9 8B 49 08",
            ],
        },
        SignatureDefinition {
            name: "CheckAppOwnership",
            sigs: vec![
                "48 8B C4 89 50 10 48 89 48 08 55 53",
                "48 8B C4 89 50 10 55 53 48 8D 68 D8",
            ],
        },
        SignatureDefinition {
            name: "CloseAppCloud",
            sigs: vec![
                "48 89 5C 24 10 57 48 83 EC 30 8B FA 48 8B D9 85 D2",
                "48 89 5C 24 18 57 48 83 EC 30 8B FA",
            ],
        },
        SignatureDefinition {
            name: "ConfigStoreGetBinary",
            sigs: vec![
                "40 53 55 56 57 48 83 EC 38 48 63 FA 49 8B E9",
                "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 48 63 FA 49 8B E9",
            ],
        },
        SignatureDefinition {
            name: "GetAppDataFromAppInfo",
            sigs: vec![
                "40 53 55 56 57 41 56 41 57 48 81 EC 78 01 00 00",
                "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 56 41 57 48 81 EC 70 01 00 00",
            ],
        },
        SignatureDefinition {
            name: "GetAppIDForCurrentPipe",
            sigs: vec![
                "8B 81 30 0D 00 00 83 F8 FF 74 ??",
                "48 83 EC 08 8B 81 30 0D 00 00",
            ],
        },
        SignatureDefinition {
            name: "GetDecryptionKey",
            sigs: vec!["40 53 55 56 57 48 81 EC 48 01 00 00 8B FA"],
        },
        SignatureDefinition {
            name: "GetOrAddAppData",
            sigs: vec![
                "48 83 EC 58 48 8B 05 ?? ?? ?? ?? 48 89 5C 24 68 48 89 6C 24 70",
                "48 83 EC 68 48 8B 05 ?? ?? ?? ?? 48 89 5C 24 78 48 89 6C 24 60",
            ],
        },
        SignatureDefinition {
            name: "GetPackageInfo",
            sigs: vec![
                "48 89 5C 24 18 89 54 24 10 55 56 57 48 83 EC 20 44 8B 49 20",
                "48 89 6C 24 20 41 56 48 83 EC 30 8B 41 20",
            ],
        },
        SignatureDefinition {
            name: "GetPipeClient",
            sigs: vec!["85 D2 74 ?? 44 0F B7 CA 44 3B 49 60"],
        },
        SignatureDefinition {
            name: "IPCProcessMessage",
            sigs: vec![
                "48 89 5C 24 18 48 89 6C 24 20 57 41 54 41 55 41 56 41 57 48 83 EC 30",
                "48 89 5C 24 18 48 89 6C 24 20 56 41 54 41 55",
            ],
        },
        SignatureDefinition {
            name: "KeyValues_FindOrCreateKey",
            sigs: vec![
                "48 8B C4 57 48 81 EC 50 04 00 00",
                "48 8B C4 4C 89 48 20 57 48 81 EC 60 04 00 00",
            ],
        },
        SignatureDefinition {
            name: "KeyValues_ReadAsBinary",
            sigs: vec![
                "48 8B C4 44 88 48 20 55 48 8D 68 A9",
                "48 8B C4 44 88 48 20 44 89 40 18",
            ],
        },
        SignatureDefinition {
            name: "LoadDepotDecryptionKey",
            sigs: vec![
                "40 53 55 56 57 48 83 EC 38 48 63 FA 49 8B E9",
                "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 48 63 FA 49 8B E9",
            ],
        },
        SignatureDefinition {
            name: "LoadPackage",
            sigs: vec![
                "44 89 44 24 18 53 55 56 57 41 55",
                "48 89 5C 24 18 48 89 6C 24 20 56 57 41 54 41 55 41 57 48 81 EC 20 01 00 00",
            ],
        },
        SignatureDefinition {
            name: "MarkLicenseAsChanged",
            sigs: vec![
                "48 89 5C 24 20 89 54 24 10 55 56 57 48 83 EC 20",
                "89 54 24 10 53 55 56 57 41 56 48 83 EC 20",
            ],
        },
        SignatureDefinition {
            name: "OptedInMask",
            sigs: vec![
                "89 54 24 10 55 53 56 57 41 54 41 55 48 8D AC 24 38 FF FF FF",
                "89 54 24 10 55 53 56 41 55 41 56 41 57",
            ],
        },
        SignatureDefinition {
            name: "PchMsgNameFromEMsg",
            sigs: vec!["48 89 5C 24 08 57 48 83 EC 20 8B D9 E8 ?? ?? ?? ??"],
        },
        SignatureDefinition {
            name: "ProcessPendingLicenseUpdates",
            sigs: vec![
                "41 56 41 57 48 83 EC 38 83 B9 98 24 00 00 00",
                "4C 8B DC 49 89 4B 08 41 55 41 57 48 83 EC 48",
            ],
        },
        SignatureDefinition {
            name: "RecvPkt",
            sigs: vec!["48 8B C4 55 48 8D A8 98 F6 FF FF"],
        },
        SignatureDefinition {
            name: "SendCallbackToPipe",
            sigs: vec!["48 89 5C 24 08 57 48 83 EC 30 41 8B D9 41 8B F8"],
        },
        SignatureDefinition {
            name: "SpawnProcess",
            sigs: vec![
                "48 89 5C 24 18 4C 89 4C 24 20 48 89 54 24 10 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 30 FF FF FF",
                "48 89 5C 24 18 4C 89 4C 24 20 48 89 54 24 10 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 20 FF FF FF",
            ],
        },
    ]
}

fn get_steamui_defs() -> Vec<SignatureDefinition> {
    vec![
        SignatureDefinition {
            name: "AddProtobufAsBinary",
            sigs: vec![
                "40 53 55 56 57 48 83 EC 28 48 8B 05 ?? ?? ?? ?? 48 8B F2",
                "48 89 5C 24 10 48 89 6C 24 18 48 89 74 24 20 57 48 83 EC 20",
            ],
        },
        SignatureDefinition {
            name: "BuildCompleteAppOverviewChange",
            sigs: vec![
                "4C 89 44 24 18 48 89 54 24 10 48 89 4C 24 08 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 E1",
                "4C 89 44 24 18 48 89 54 24 10 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 E1",
            ],
        },
        SignatureDefinition {
            name: "CSteamUIAppControllerRunFrame",
            sigs: vec![
                "48 89 5C 24 10 48 89 6C 24 18 56 57 41 54 41 56 41 57 48 83 EC 40 0F 29 74 24 30",
                "48 89 5C 24 18 48 89 6C 24 20 56 57 41 54 41 55 41 57 48 83 EC 40",
            ],
        },
        SignatureDefinition {
            name: "FillInAppOverview",
            sigs: vec![
                "48 89 54 24 10 48 89 4C 24 08 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 E1 48 81 EC B8 00 00 00",
                "48 89 54 24 10 48 89 4C 24 08 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 E1",
            ],
        },
        SignatureDefinition {
            name: "GetAppByID",
            sigs: vec![
                "89 54 24 10 53 48 83 EC 40 48 8B 05 ?? ?? ?? ??",
                "89 54 24 10 56 48 83 EC 40 48 8B 05 ?? ?? ?? ??",
            ],
        },
        // NOTE: GetTopManager is a 2-instruction stub (mov rax,[rip+X]; ret).
        // Its signature is too generic for reliable automated scanning — requires
        // cross-reference based discovery via a disassembler. See README.md.
        SignatureDefinition {
            name: "LoadModuleWithPath",
            sigs: vec![
                "48 89 5C 24 18 55 56 41 57 48 83 EC 40",
                "48 89 5C 24 18 48 89 6C 24 20 56 41 54 41 57 48 83 EC 40",
            ],
        },
        SignatureDefinition {
            name: "MarkAppChange",
            sigs: vec![
                "48 83 EC 78 48 8B 05 ?? ?? ?? ?? 48 89 74 24 70",
                "48 83 EC 78 48 8B 05 ?? ?? ?? ?? 48 89 7C 24 68",
            ],
        },
        SignatureDefinition {
            name: "RepeatedFieldUint32_Add",
            sigs: vec!["48 89 74 24 10 48 89 7C 24 18 41 56 48 83 EC 20 8B 31 48 8B F9 8B 49 04"],
        },
        SignatureDefinition {
            name: "ShouldShowAppInLibrary",
            sigs: vec!["40 53 48 83 EC 20 48 8B 01 48 8B D9 FF 10 3D D6 0C 09 00"],
        },
    ]
}

fn process_dll(dll_path: &Path, is_steamui: bool, out_dir: &Path) -> io::Result<()> {
    let mut file = File::open(dll_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Calculate SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let sha256_hex = format!("{:x}", hasher.finalize());
    println!("Processing: {}", dll_path.display());
    println!("  SHA-256: {}", sha256_hex);

    let pe = match PeFile::parse(&buffer) {
        Ok(pe) => pe,
        Err(err) => {
            eprintln!("  Failed to parse PE file: {}", err);
            return Ok(());
        }
    };

    let text_sec = match pe.sections.iter().find(|s| s.name == ".text") {
        Some(sec) => sec,
        None => {
            eprintln!("  Could not find .text section");
            return Ok(());
        }
    };

    let text_start = text_sec.pointer_to_raw_data as usize;
    let text_end = text_start + text_sec.size_of_raw_data as usize;
    let text_data = &pe.data[text_start..text_end];

    let defs = if is_steamui {
        get_steamui_defs()
    } else {
        get_steamclient_defs()
    };

    let mut output_lines = Vec::new();

    for def in defs {
        let fnv_hash = fnv1a_hash(def.name);
        let mut found_rva = None;
        let mut matched_sig = "";

        for &sig_str in &def.sigs {
            let pattern = parse_sig(sig_str);
            if let Some(offset) = scan_pattern(text_data, &pattern) {
                let file_offset = text_start + offset;
                if let Some(rva) = pe.file_offset_to_rva(file_offset) {
                    found_rva = Some(rva);
                    matched_sig = sig_str;
                    break;
                }
            }
        }

        if let Some(rva) = found_rva {
            output_lines.push(format!("[{:#010X}]", fnv_hash));
            output_lines.push(format!("name = \"{}\"", def.name));
            output_lines.push(format!("rva = \"{:#X}\"", rva));
            output_lines.push(format!("sig = \"{}\"", matched_sig));
            output_lines.push("".to_string());
        } else {
            eprintln!("  [WARNING] Could not find pattern for function: {}", def.name);
        }
    }

    let component = if is_steamui { "steamui" } else { "steamclient" };
    // Cache hierarchy: <out_dir>/<channel>/<component>/<sha256>.toml
    // This mirrors what RemoteToml writes and reads under
    // <Steam>/opensteamtool/pattern/<component>/<sha256>.toml
    let component_dir = out_dir.join(component);
    fs::create_dir_all(&component_dir)?;

    let out_file_path = component_dir.join(format!("{}.toml", sha256_hex));
    let mut out_file = File::create(&out_file_path)?;
    for line in output_lines {
        writeln!(out_file, "{}", line)?;
    }

    println!("  Written to cache: {}", out_file_path.display());
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: pattern_scanner <steam_directory_or_dll_path> [output_directory]");
        println!("  steam_directory  — path to the Steam root (contains steamclient64.dll).");
        println!("                    Default output: <steam_dir>/opensteamtool/pattern/");
        println!("  output_directory — optional override for the output root.");
        println!("                    Files are written as <out>/<component>/<sha256>.toml");
        println!();
        println!("Examples:");
        println!("  pattern_scanner \"C:\\Program Files (x86)\\Steam\"");
        println!("  pattern_scanner \"C:\\Steam\" D:\\my-toml-files");
        return Ok(());
    }

    let input_path = Path::new(&args[1]);

    if input_path.is_dir() {
        // Default: write into the standard OpenSteamTool cache tree inside the Steam dir.
        let out_dir = if args.len() >= 3 {
            PathBuf::from(&args[2])
        } else {
            input_path.join("opensteamtool").join("pattern")
        };

        let client_path = input_path.join("steamclient64.dll");
        let ui_path = input_path.join("steamui.dll");

        if client_path.exists() {
            process_dll(&client_path, false, &out_dir)?;
        } else {
            println!("No steamclient64.dll found in {}", input_path.display());
        }

        if ui_path.exists() {
            process_dll(&ui_path, true, &out_dir)?;
        } else {
            println!("No steamui.dll found in {}", input_path.display());
        }
    } else if input_path.is_file() {
        // Single-DLL mode: output dir must be explicit (no Steam root to infer from).
        let out_dir = if args.len() >= 3 {
            PathBuf::from(&args[2])
        } else {
            env::current_dir()?
        };

        let filename = input_path.file_name().unwrap().to_string_lossy().to_lowercase();
        if filename.contains("steamui") {
            process_dll(input_path, true, &out_dir)?;
        } else if filename.contains("steamclient") {
            process_dll(input_path, false, &out_dir)?;
        } else {
            println!("Unknown DLL. Please specify either steamclient64.dll or steamui.dll");
        }
    } else {
        println!("Input path does not exist!");
    }

    Ok(())
}
