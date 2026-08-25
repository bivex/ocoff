# `ocoff` — PE/COFF Binary Format Library for OCaml 5

[![Build & Test](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/ocoff/ocoff)
[![OCaml](https://img.shields.io/badge/OCaml-5.0+-orange.svg)](https://ocaml.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A pure, modern OCaml 5 library and CLI tool for parsing, inspecting, and serializing **Microsoft Portable Executable (PE)** and **Common Object File Format (COFF)** binaries (including `.exe`, `.dll`, `.obj`, and `.lib` archives) built using **Domain-Driven Design (DDD)** and **Hexagonal Architecture (Ports & Adapters)**.

---

## ✨ Features

- **Format Coverage**:
  - **PE32 (32-bit)** and **PE32+ (64-bit)** executable images and DLLs.
  - **COFF Object Files (`.obj`)**: headers, sections, symbols, auxiliary records, relocations, and string tables.
  - **COFF Static Libraries (`.lib`)**: Unix/Windows `!<arch>\n` archives with Linker Member 1 (big-endian offsets), Linker Member 2, and Longnames table (`//`).
  - **C# / .NET Managed Assemblies**: Full detection of CLR Runtime Headers (`IMAGE_COR20_HEADER` at Data Directory 14), `mscoree.dll` entry points (`_CorExeMain`, `_CorDllMain`), and Authenticode certificate tables.
- **Domain Services**:
  - **Import Resolution**: Complete 32-bit and 64-bit Import Lookup Table (ILT) and Import Address Table (IAT) parsing by name (with hint) or ordinal across sections.
  - **Export Resolution**: Parsing of Export Address Tables (EAT), Name Pointer Tables, and Ordinal Tables with forwarder chain detection (e.g. `NTDLL.RtlAllocateHeap`).
  - **Checksum Calculation**: Exact implementation of Windows `IMAGEHLP.DLL` PE image checksum algorithm.
- **Functional Architecture**:
  - **Zero Exceptions in Domain**: 100% railway-oriented monadic flow (`let* = Result.bind`) returning `( 'a, Error.t ) result`.
  - **Pure Tail-Recursive Traversals**: No mutable loops or references in parsing pipelines.
  - **Module Functors**: Generic bitmask flag set management via `Flag_set.Make`.
  - **Strict ADT Encapsulation**: Interface `.mli` contracts for all application services and adapters.
  - **Multicore Ready**: Re-entrant, pure functional parsing safe for concurrent execution across OCaml 5 domains (`Domain.spawn`).

---

## 🏛 Architecture Overview

```
ocoff/
├── lib/
│   ├── domain/                         # Pure business domain (no I/O, no exceptions)
│   │   ├── types/                      # Value objects, enums, bitmask flags
│   │   │   ├── flag_set.ml             # Generic bitmask flag set functor & helpers
│   │   │   ├── machine_type.ml         # Architecture constants (x86, x64, ARM64, RISC-V, etc.)
│   │   │   ├── characteristics.ml      # IMAGE_FILE_* characteristics (via Flag_set)
│   │   │   ├── subsystem.ml            # IMAGE_SUBSYSTEM_* subsystem codes
│   │   │   ├── dll_characteristics.ml  # IMAGE_DLLCHARACTERISTICS_* flags (via Flag_set)
│   │   │   ├── section_flags.ml        # IMAGE_SCN_* section flags & alignments
│   │   │   ├── relocation_type.ml      # Architecture-specific COFF relocation types
│   │   │   ├── storage_class.ml        # IMAGE_SYM_CLASS_* symbol storage classes
│   │   │   ├── section_number.ml       # Section number indicators (UNDEF, ABS, DEBUG)
│   │   │   └── error.ml                # Pure domain Error.t result monad
│   │   ├── model/                      # Entities & Aggregate Roots
│   │   │   ├── dos_stub.ml             # MS-DOS 2.0 MZ header & stub
│   │   │   ├── coff_header.ml          # IMAGE_FILE_HEADER (20 bytes)
│   │   │   ├── optional_header.ml      # IMAGE_OPTIONAL_HEADER (PE32 & PE32+)
│   │   │   ├── data_directory.ml       # IMAGE_DATA_DIRECTORY (16 directories)
│   │   │   ├── section_header.ml       # IMAGE_SECTION_HEADER (40 bytes)
│   │   │   ├── coff_relocation.ml      # COFF relocation records (10 bytes)
│   │   │   ├── symbol_name.ml          # Short inline name or string table reference
│   │   │   ├── coff_symbol.ml          # Symbol records & Auxiliary records (18 bytes)
│   │   │   ├── pe_file.ml              # Top-level PE/COFF aggregate root (with RVA lookups)
│   │   │   └── archive.ml              # COFF Library Archive (.lib / !<arch>\n)
│   │   └── services/                   # Pure domain calculation services
│   │       ├── checksum.ml             # IMAGEHLP.DLL PE image checksum algorithm
│   │       ├── export_resolver.ml      # .edata parsing, ordinals, forwarders, name lookup
│   │       └── import_resolver.ml      # .idata parsing, 32/64-bit ILT/IAT, ordinal & name imports
│   ├── ports/                          # Hexagonal Ports (Module Type Signatures)
│   │   ├── inbound/                    # Driving ports (Use case interfaces)
│   │   │   ├── pe_parser_port.ml       # Parser interface
│   │   │   └── pe_serializer_port.ml   # Serializer interface
│   │   └── outbound/                   # Driven ports (Infrastructure interfaces)
│   │       ├── binary_reader_port.ml   # Abstract binary reader
│   │       ├── binary_writer_port.ml   # Abstract binary writer
│   │       ├── file_reader_port.ml     # Abstract file reader
│   │       └── file_writer_port.ml     # Abstract file writer
│   ├── adapters/                       # Concrete adapter implementations
│   │   ├── binary/                     # In-memory binary cursor (Bytes.t / Buffer.t)
│   │   │   ├── binary_reader.ml(i)     # Bounds-checked LE & BE reader
│   │   │   └── binary_writer.ml(i)     # Buffer-backed serializer
│   │   ├── file/                       # File system I/O adapter
│   │   │   └── file_io.ml              # Channel-based read/write with Result.t
│   │   └── analysis/                   # Pretty-printing & inspection adapter
│   │       └── pe_printer.ml           # Diagnostic formatters
│   ├── application/                    # Application Layer / Orchestration
│   │   ├── pe_parser.ml(i)             # Core PE/COFF image parsing service
│   │   ├── pe_symbol_parser.ml(i)      # COFF symbol & string table parser
│   │   ├── archive_parser.ml(i)        # Static library archive parser
│   │   └── pe_serializer.ml(i)         # Binary emitter & serializer
│   └── ocoff.ml                        # Unified facade module
├── bin/
│   └── main.ml                         # ocoffdump CLI application
└── test/                               # Modular Alcotest test suite
    ├── test_binary_adapter.ml          # Low-level binary reader/writer tests
    ├── test_domain_types.ml            # Enums, characteristics, and flag set tests
    ├── test_coff.ml                    # COFF .obj parse & roundtrip serialize tests
    ├── test_pe_image.ml                # PE32+ image parsing & RVA section lookup tests
    ├── test_export_resolver.ml         # Export table, ordinal, and name resolution tests
    ├── test_checksum.ml                # Checksum algorithm tests
    ├── test_archive.ml                 # Static library archive tests
    ├── test_error_handling.ml          # Negative tests & invalid signature handling
    ├── test_real_binaries.ml           # Real binary tests (Windows GUI, DLLs, C# .NET 8/10)
    └── test_pe_parser.ml               # Root test runner
```

---

## 🚀 Quick Start

### Build with Dune
```bash
dune build
```

### Run All Tests
```bash
dune runtest
```

### Install into OPAM Switch
```bash
dune install
```

---

## 💻 CLI Usage (`ocoffdump`)

The `ocoffdump` CLI tool provides fast inspection, structural dumping, and disassembly-ready exports/imports exploration:

```bash
# Display quick file summary (machine, architecture, sections, entry point)
ocoffdump info my_program.exe

# Display complete PE header and section table
ocoffdump dump my_program.exe

# Dump with imported DLLs and functions (-i)
ocoffdump dump -i my_program.exe

# Dump with exported symbols and ordinals (-e)
ocoffdump dump -e my_library.dll

# Full dump: headers, sections, hex dumps (-s), imports (-i), and exports (-e)
ocoffdump dump -s -i -e my_binary.exe
```

### Example: Inspecting a C# .NET Assembly
```bash
$ ocoffdump dump -i Avalonia.Fonts.Inter.dll
=== MS-DOS Stub ===
  PE offset: 0x80
=== COFF File Header ===
  Machine:              x86
  NumberOfSections:     3
  Characteristics:      0x2022 [EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DLL]
=== Optional Header ===
  Magic:                    PE32 (0x10b)
  AddressOfEntryPoint:      0x001cf62e
  ImageBase:                0x0000000010000000
  --- Data Directories ---
    Import Table               va=0x001cf5dc size=0x0000004f
    CLR Runtime Header         va=0x00002008 size=0x00000048
=== Section Headers (3) ===
  .text    va=0x00002000 vsize=0x001cd634 raw=0x00000200 rawsize=0x001cd800 flags=0x60000020 [CNT_CODE | MEM_EXECUTE | MEM_READ]
  .rsrc    va=0x001d0000 vsize=0x00000420 raw=0x001cda00 rawsize=0x00000600 flags=0x40000040 [CNT_INITIALIZED_DATA | MEM_READ]
  .reloc   va=0x001d2000 vsize=0x0000000c raw=0x001ce000 rawsize=0x00000200 flags=0x42000040 [CNT_INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ]

=== Imports ===
1 imported DLLs:
DLL: mscoree.dll (1 functions)
    [hint    0] _CorDllMain
```

---

## 📖 OCaml Library API

### 1. Parsing a PE or COFF Binary
```ocaml
open Ocoff

match Ocoff.load_file "path/to/binary.exe" with
| Error e ->
  Format.eprintf "Parse error: %a\n" Error.pp e

| Ok (`Pe pe) ->
  let mach = Machine_type.of_uint16 pe.coff_header.machine |> Result.get_ok in
  Printf.printf "PE File: Architecture = %s\n" (Machine_type.to_string mach);
  Printf.printf "Sections count: %d\n" (List.length pe.sections);

  (* Resolve all imported DLLs and symbols *)
  (match Import_resolver.parse_pe_imports pe with
   | Ok imports ->
     List.iter (fun imp ->
       Printf.printf "Imports from %s: %d functions\n"
         imp.Import_resolver.dll_name
         (List.length imp.entries)
     ) imports
   | Error _ -> ());

  (* Resolve all exported functions *)
  (match Export_resolver.parse_pe_exports pe with
   | Ok exports ->
     List.iter (fun exp ->
       Printf.printf "Export [%d]: %s (RVA: 0x%lx)\n"
         exp.Export_resolver.ordinal
         (Option.value ~default:"<noname>" exp.name)
         exp.rva
     ) exports
   | Error _ -> ())

| Ok (`Coff obj) ->
  Printf.printf "COFF Object: %d symbols\n" (List.length obj.symbol_table)

| Ok (`Archive lib) ->
  Printf.printf "Static Library Archive: %d members\n" (List.length (Archive.members lib))
```

### 2. Computing Checksum
```ocaml
let raw_bytes = (* file bytes *) in
let checksum = Checksum.compute raw_bytes ~checksum_offset:0x118 in
Printf.printf "Computed PE Checksum: 0x%08lx\n" checksum
```

---

## 🧪 Test Suite

The test suite covers unit, roundtrip serialization, and integration tests across 18 test suites:

| Test Suite | Description |
| :--- | :--- |
| **`binary_adapter`** | Roundtrip LE/BE numbers, strings, and bounds-checking |
| **`domain_types`** | Architecture machine codes, characteristics, subsystems, and section flags |
| **`coff_object`** | COFF object file parsing and 100% roundtrip byte serialization |
| **`pe_image`** | 64-bit PE32+ parsing, header validation, and RVA-to-section resolution |
| **`export_resolver`** | `.edata` export table parsing, ordinal bias, and named symbol lookups |
| **`checksum_service`** | `IMAGEHLP.DLL` PE image checksum computation |
| **`archive_format`** | Static library archive member and COFF object embedding |
| **`error_handling`** | Defensive signature validation and bounds violation protection |
| **`real_binaries`** | Real-world binary parsing (Windows GUI PE32, OpenSSL 4000+ exports, C# .NET 8 & 10 assemblies) |

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
