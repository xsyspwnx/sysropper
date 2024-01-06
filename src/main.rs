//// Blazing fast custom ROP Generator for x86/x64 systems with System call support
//// Created by : Microsvuln (Arash Ale Ebrahim)
//// Copyright : SysPWN
use capstone::prelude::*;
use goblin::elf::Elf;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use clap::{App, Arg};

use std::collections::HashMap;

#[derive(Debug)]
enum Register {
    EAX,
    EBX,
    ECX,
    EDX,

}

struct SyscallRequirement {
    register: Register,
    value: SyscallValue,
}

#[derive(Debug)]
enum SyscallValue {
    Fixed(u32),     
    Pointer(String), 
    Null,           
}

fn build_syscall_mapping() -> HashMap<&'static str, Vec<SyscallRequirement>> {
    let mut syscalls = HashMap::new();

    // Mapping for execve
    syscalls.insert("execve", vec![
        SyscallRequirement {
            register: Register::EAX,
            value: SyscallValue::Fixed(11), 
        },
        SyscallRequirement {
            register: Register::EBX,
            value: SyscallValue::Pointer("/bin/sh".to_string()), 
        },
        SyscallRequirement {
            register: Register::ECX,
            value: SyscallValue::Null,
        },
        SyscallRequirement {
            register: Register::EDX,
            value: SyscallValue::Null,
        },
    ]);

    syscalls.insert("write", vec![
        SyscallRequirement {
            register: Register::EAX,
            value: SyscallValue::Fixed(11), 
        },
        SyscallRequirement {
            register: Register::EBX,
            value: SyscallValue::Pointer("/bin/sh".to_string()), 
        },
        SyscallRequirement {
            register: Register::ECX,
            value: SyscallValue::Null,
        },
        SyscallRequirement {
            register: Register::EDX,
            value: SyscallValue::Null,
        },
    ]);


    // Add mappings for other syscalls similarly

    syscalls
}

struct Gadget {
    address: u64,
    instructions: Vec<String>,
}

impl Gadget {
    fn sets_register_to(&self, register: &str, value: u32) -> bool {
        match register {
            "ecx" => self.instructions.iter().any(|instr| {
                (instr.contains("xor ecx, ecx") || instr.contains("mov ecx, 0")) && value == 0
            }),
            // Add cases for other registers as needed
            _ => false,
        }
    }
}


fn find_gadgets(elf_file: &Path, section_name: &str) -> Vec<Gadget>  {
    let mut f = File::open(elf_file).expect("Failed to open file!");
    let mut buffer = Vec::new();
    let mut current_gadget_instructions: Vec<String> = Vec::new();
    f.read_to_end(&mut buffer).expect("Failed to read the file");

    let elf = Elf::parse(&buffer).expect("Failed to parse ELF file");

    let code_section = elf.section_headers.iter()
        .find(|&sh| elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("") == section_name)
        .expect("Section not found!");

    let opcodes = &buffer[code_section.sh_offset as usize..(code_section.sh_offset + code_section.sh_size) as usize];

    let cs = Capstone::new()
        .x86()
        .mode(capstone::arch::x86::ArchMode::Mode32)
        .syntax(capstone::arch::x86::ArchSyntax::Intel)
        .build()
        .expect("Failed to create Capstone object");

     let insns = cs.disasm_all(opcodes, code_section.sh_addr).expect("Failed to disassemble!");
     let max_instructions_per_gadget = 12;
         let mut gadgets = Vec::new();
    let mut current_gadget_instructions = Vec::new();
    let max_instructions_per_gadget = 12;

    for i in insns.iter() {
        let formatted_instruction = format!("0x00{:x}: {} {}", i.address(), i.mnemonic().unwrap_or(""), i.op_str().unwrap_or(""));

        // Check if the instruction matches the start pattern or is part of a gadget
        if formatted_instruction.contains("xor ecx, ecx") || !current_gadget_instructions.is_empty() {
            current_gadget_instructions.push(formatted_instruction);

            // Check if the gadget has reached the maximum length or found a 'ret'
            if i.mnemonic().unwrap_or("") == "ret" || current_gadget_instructions.len() == max_instructions_per_gadget {
                if i.mnemonic().unwrap_or("") == "ret" {
                    gadgets.push(Gadget {
                        address: i.address() - (current_gadget_instructions.len() as u64 - 1),
                        instructions: current_gadget_instructions.clone(),
                    });
                }
                current_gadget_instructions.clear();
            }
        }
    }

    gadgets
}


fn filter_gadgets(gadgets: Vec<Gadget>, pattern: &str) -> Vec<Gadget> {
    gadgets.into_iter()
        .filter(|gadget| {
            gadget.instructions.iter().any(|instr| instr.contains(pattern))
        })
        .collect()
}




fn main(){
    let args: Vec<String> = env::args().collect();


    let matches = App::new("SysROPPER")
        .version("1.0")
        .author("Arash Ale Ebrahim")
        .about("Generates ROP chains for specific syscalls")
        .arg(Arg::with_name("elf_file")
             .help("Specifies the ELF file to analyze")
             .required(true)
             .index(1))
        .arg(Arg::with_name("section")
             .help("Specifies the section to search for gadgets")
             .required(true)
             .index(2))
        .arg(Arg::with_name("syscall")
             .long("syscall")
             .takes_value(true)
             .help("Specifies the syscall for which to generate the ROP chain"))
        .arg(Arg::with_name("parameters")
             .short("p")
             .long("parameters")
             .takes_value(true)
             .help("Specifies the parameters for the syscall"))
        .get_matches();

    let elf_file = matches.value_of("elf_file").unwrap();
    let section = matches.value_of("section").unwrap();
    let syscall = matches.value_of("syscall").unwrap_or_default();
    let parameters = matches.value_of("parameters").unwrap_or_default();

    println!("ELF file: {}", elf_file);
    println!("Section: {}", section);
    println!("Syscall: {}", syscall);
    println!("Parameters: {}", parameters);


    let elf_file = Path::new(&args[1]);
    let section  = &args[2];

    let syscall_mapping = build_syscall_mapping();

    if let Some(requirements) = syscall_mapping.get(syscall) {
        for req in requirements {
            // Process each requirement
            // This is where you'd generate or find the suitable gadgets
            println!("Register: {:?}, Value: {:?}", req.register, req.value);
        }
    } else {
        eprintln!("Syscall not found or not supported");
    }


    println!("ELF file: {}", elf_file.display());
    println!("Section: {}", section);
    println!("Syscall: {}", syscall);
    println!("Parameters: {}", parameters);

    let all_gadgets = find_gadgets(elf_file, section);
    let filtered_gadgets = filter_gadgets(all_gadgets, "xor ecx, ecx");

    for gadget in filtered_gadgets {
        println!("Gadget at address 0x{:x}", gadget.address);
        for instr in &gadget.instructions {
            println!("  {}", instr);
        }
        println!("-------------------");
    }


}



