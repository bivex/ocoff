# `ocoff` — PE/COFF OCaml Library

A pure OCaml library and CLI tool for parsing, inspecting, and serializing **Microsoft Portable Executable (PE)** and **Common Object File Format (COFF)** binaries (including `.exe`, `.dll`, `.obj`, and `.lib` archives) using **Domain-Driven Design (DDD)** and **Hexagonal Architecture (Ports & Adapters)**.

---

## 🏛 Architecture

`ocoff` strictly separates the pure domain model, interfaces (ports), and infrastructure/adapters:

```
ocoff/
├── lib/
│   ├── domain/                         # Pure business logic (no I/O, no exceptions)
│   │   ├── types/                      # Value objects, enums, bitmask flags
│   │   │   ├── machine_type.ml         # Architecture constants (x86, x64, ARM, ARM64, RISC-V, etc.)
│   │   │   ├── characteristics.ml      # IMAGE_FILE_* characteristics
│   │   │   ├── subsystem.ml            # IMAGE_SUBSYSTEM_* subsystem codes
│   │   │   ├── dll_characteristics.ml  # IMAGE_DLLCHARACTERISTICS_* flags
│   │   │   ├── section_flags.ml        # IMAGE_SCN_* section characteristics & alignments
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
│   │   │   ├── symbol_name.ml          # Short name (<8 bytes) or String Table ref
│   │   │   ├── coff_symbol.ml          # Symbol records & Auxiliary records (18 bytes)
│   │   │   ├── pe_file.ml              # Top-level PE/COFF aggregate root
│   │   │   └── archive.ml              # COFF Library Archive (.lib / !<arch>\n)
│   │   └── services/                   # Pure domain calculation services
│   │       ├── checksum.ml             # IMAGEHLP.DLL PE image checksum algorithm
│   │       ├── export_resolver.ml      # .edata parsing, ordinals, name resolution
│   │       └── import_resolver.ml      # .idata parsing, ILT/IAT, ordinal & name imports
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
│   │   │   ├── binary_reader.ml        # Bounds-checked LE & BE reader
│   │   │   └── binary_writer.ml        # Buffer-backed serializer
│   │   ├── file/                       # File system I/O adapter
│   │   │   └── file_io.ml              # Channel-based read/write with Result.t
│   │   └── analysis/                   # Pretty-printing & inspection adapter
│   │       └── pe_printer.ml           # Diagnostic formatters
│   ├── application/                    # Application Layer / Orchestration
│   │   ├── pe_parser.ml                # Core parsing implementation
│   │   └── pe_serializer.ml            # Binary emitter implementation
│   └── ocoff.ml                        # Unified facade module
├── bin/
│   └── main.ml                         # ocoffdump CLI application
└── test/
    └── test_pe_parser.ml               # Comprehensive Alcotest test suite
```

---

## 🚀 Getting Started

### Building
```bash
dune build
```

### Running Tests
```bash
dune runtest
```

### Installing
```bash
dune install
```

---

## 💻 CLI Usage (`ocoffdump`)

Inspect any PE/COFF executable, DLL, object file, or static library:

```bash
# High-level file summary
dune exec ocoffdump -- info my_program.exe

# Detailed structural dump
dune exec ocoffdump -- dump my_program.exe

# Dump with section hex dumps, exports, and imports
dune exec ocoffdump -- dump -s -i -e my_dll.dll
```

---

## 📖 Library Usage (OCaml API)

```ocaml
open Ocoff

(* 1. Load and parse from file *)
match Ocoff.load_file "path/to/binary.exe" with
| Error e -> Printf.eprintf "Error: %s\n" (Error.to_string e)
| Ok (`Pe pe) ->
  Printf.printf "Machine: %s\n"
    (Machine_type.to_string (Machine_type.of_uint16 pe.coff_header.machine |> Result.get_ok));
  Printf.printf "Sections: %d\n" (List.length pe.sections);
  List.iter (fun sec ->
    Printf.printf "  Section: %s (RVA: 0x%lx, Size: 0x%lx)\n"
      (Section_header.name_string sec)
      sec.virtual_address
      sec.virtual_size
  ) pe.sections

| Ok (`Coff obj) ->
  Printf.printf "COFF Object with %d symbols\n" (List.length obj.symbol_table)

| Ok (`Archive lib) ->
  Printf.printf "Library Archive with %d members\n" (List.length (Archive.members lib))
```

---

## 📄 License
MIT License
