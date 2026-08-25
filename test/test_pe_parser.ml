(** Comprehensive unit and integration tests for ocoff library. *)

open Ocoff

(* ========================================================================= *)
(* 1. Binary Reader / Writer Tests                                           *)
(* ========================================================================= *)

let test_binary_roundtrip () =
  let w = Binary_writer.create () in
  Binary_writer.write_u8 w 0x42;
  Binary_writer.write_u16_le w 0x1234;
  Binary_writer.write_i16_le w (-100);
  Binary_writer.write_u32_le w 0xdeadbeef_l;
  Binary_writer.write_u64_le w 0x0102030405060708L;
  Binary_writer.write_string w "Hello";
  Binary_writer.write_u8 w 0;
  let bytes = Binary_writer.to_bytes w in

  let r = Binary_reader.of_bytes bytes in
  Alcotest.(check int) "read_u8" 0x42 (Result.get_ok (Binary_reader.read_u8 r));
  Alcotest.(check int) "read_u16_le" 0x1234 (Result.get_ok (Binary_reader.read_u16_le r));
  Alcotest.(check int) "read_i16_le" (-100) (Result.get_ok (Binary_reader.read_i16_le r));
  Alcotest.(check int32) "read_u32_le" 0xdeadbeef_l (Result.get_ok (Binary_reader.read_u32_le r));
  Alcotest.(check int64) "read_u64_le" 0x0102030405060708L (Result.get_ok (Binary_reader.read_u64_le r));
  Alcotest.(check string) "read_cstring" "Hello" (Result.get_ok (Binary_reader.read_cstring r ()));
  Alcotest.(check int) "remaining is 0" 0 (Binary_reader.remaining r)

let test_binary_bounds () =
  let r = Binary_reader.of_bytes (Bytes.of_string "ab") in
  Alcotest.(check bool) "read 2 bytes ok" true (Result.is_ok (Binary_reader.read_bytes r 2));
  Alcotest.(check bool) "read past eof fails" true (Result.is_error (Binary_reader.read_u8 r))

(* ========================================================================= *)
(* 2. Machine Type, Characteristics, Subsystem Tests                         *)
(* ========================================================================= *)

let test_machine_types () =
  let check_mach name raw expected =
    match Machine_type.of_uint16 raw with
    | Ok m -> Alcotest.(check bool) name true (m = expected)
    | Error _ -> Alcotest.fail (name ^ " failed to decode")
  in
  check_mach "amd64" 0x8664 Machine_type.Amd64;
  check_mach "i386" 0x014c Machine_type.I386;
  check_mach "arm64" 0xaa64 Machine_type.Arm64;
  check_mach "armnt" 0x01c4 Machine_type.Armnt;
  check_mach "riscv64" 0x5064 Machine_type.RiscV64;
  check_mach "loongarch64" 0x6264 Machine_type.LoongArch64;
  Alcotest.(check int) "amd64 to_uint16" 0x8664 (Machine_type.to_uint16 Machine_type.Amd64)

let test_characteristics () =
  let raw = 0x2000 lor 0x0002 lor 0x0020 in (* DLL | EXECUTABLE | LARGE_ADDRESS_AWARE *)
  let flags = Characteristics.of_uint16 raw in
  Alcotest.(check bool) "has Dll" true (Characteristics.has flags Characteristics.Dll);
  Alcotest.(check bool) "has ExecutableImage" true (Characteristics.has flags Characteristics.ExecutableImage);
  Alcotest.(check bool) "has LargeAddressAware" true (Characteristics.has flags Characteristics.LargeAddressAware);
  Alcotest.(check bool) "not System" false (Characteristics.has flags Characteristics.System);
  Alcotest.(check int) "roundtrip uint16" raw (Characteristics.to_uint16 flags)

let test_subsystems () =
  let check_sub name raw expected =
    match Subsystem.of_uint16 raw with
    | Ok s -> Alcotest.(check bool) name true (s = expected)
    | Error _ -> Alcotest.fail (name ^ " failed to decode")
  in
  check_sub "WindowsGui" 2 Subsystem.WindowsGui;
  check_sub "WindowsCui" 3 Subsystem.WindowsCui;
  check_sub "Native" 1 Subsystem.Native;
  check_sub "EfiApplication" 10 Subsystem.EfiApplication;
  Alcotest.(check int) "WindowsCui to_uint16" 3 (Subsystem.to_uint16 Subsystem.WindowsCui)

let test_section_flags () =
  let raw = 0x60000020l in (* CODE | EXECUTE | READ *)
  let flags = Section_flags.of_uint32 raw in
  Alcotest.(check bool) "has CntCode" true (Section_flags.has flags Section_flags.CntCode);
  Alcotest.(check bool) "has MemExecute" true (Section_flags.has flags Section_flags.MemExecute);
  Alcotest.(check bool) "has MemRead" true (Section_flags.has flags Section_flags.MemRead);
  Alcotest.(check bool) "not MemWrite" false (Section_flags.has flags Section_flags.MemWrite);
  Alcotest.(check int32) "roundtrip uint32" raw (Section_flags.to_uint32 flags)

(* ========================================================================= *)
(* 3. Minimal COFF Object Parsing & Serialization                            *)
(* ========================================================================= *)

let build_sample_coff () =
  let w = Binary_writer.create () in
  Binary_writer.write_u16_le w 0x8664; (* Machine: AMD64 *)
  Binary_writer.write_u16_le w 1;      (* NumberOfSections: 1 *)
  Binary_writer.write_u32_le w 1700000000l; (* TimeDateStamp *)
  Binary_writer.write_u32_le w 60l;    (* PointerToSymbolTable: at offset 60 *)
  Binary_writer.write_u32_le w 2l;     (* NumberOfSymbols: 2 (1 sym + 1 aux) *)
  Binary_writer.write_u16_le w 0;      (* SizeOfOptionalHeader: 0 *)
  Binary_writer.write_u16_le w 0x0004; (* Characteristics *)

  (* Section Header: .text (offset 20..60 = 40 bytes) *)
  Binary_writer.write_string w ".text\x00\x00\x00";
  Binary_writer.write_u32_le w 16l;    (* VirtualSize *)
  Binary_writer.write_u32_le w 0l;     (* VirtualAddress (0 in obj) *)
  Binary_writer.write_u32_le w 16l;    (* SizeOfRawData *)
  Binary_writer.write_u32_le w 116l;   (* PointerToRawData *)
  Binary_writer.write_u32_le w 0l;     (* PointerToRelocations *)
  Binary_writer.write_u32_le w 0l;     (* PointerToLinenumbers *)
  Binary_writer.write_u16_le w 0;      (* NumberOfRelocations *)
  Binary_writer.write_u16_le w 0;      (* NumberOfLinenumbers *)
  Binary_writer.write_u32_le w 0x60000020l; (* Characteristics *)

  (* Primary Symbol Table Entry: 18 bytes at offset 60..78 *)
  Binary_writer.write_string w "main\x00\x00\x00\x00";
  Binary_writer.write_u32_le w 0l;     (* Value *)
  Binary_writer.write_u16_le w 1;      (* SectionNumber = 1 *)
  Binary_writer.write_u16_le w 0x20;   (* Type: Function *)
  Binary_writer.write_u8 w 2;          (* StorageClass: External *)
  Binary_writer.write_u8 w 1;          (* NumberOfAuxSymbols: 1 *)

  (* Auxiliary Record: Function Definition (18 bytes at offset 78..96) *)
  Binary_writer.write_u32_le w 0l;     (* TagIndex *)
  Binary_writer.write_u32_le w 16l;    (* TotalSize = 16 *)
  Binary_writer.write_u32_le w 0l;     (* PointerToLinenumber *)
  Binary_writer.write_u32_le w 0l;     (* PointerToNextFunction *)
  Binary_writer.write_u16_le w 0;      (* Unused *)

  (* String Table: 20 bytes at offset 96..116 *)
  Binary_writer.write_u32_le w 20l;    (* Size = 20 *)
  Binary_writer.write_string w "some_long_symbol_name\x00";

  (* Raw section data: 16 bytes at offset 116..132 *)
  Binary_writer.write_string w "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xc3";
  Binary_writer.to_bytes w

let test_coff_object_parse () =
  let raw = build_sample_coff () in
  let res = Pe_parser.parse_coff_object raw in
  Alcotest.(check bool) "parse coff ok" true (Result.is_ok res);
  let pf = Result.get_ok res in
  Alcotest.(check bool) "is object" true (Pe_file.is_object pf);
  Alcotest.(check int) "machine AMD64" 0x8664 pf.coff_header.machine;
  Alcotest.(check int) "1 section" 1 (List.length pf.sections);
  let sec = List.hd pf.sections in
  Alcotest.(check string) "section name .text" ".text" (Section_header.name_string sec);
  Alcotest.(check int) "1 symbol (with aux)" 1 (List.length pf.symbol_table);
  let sym = List.hd pf.symbol_table in
  Alcotest.(check string) "symbol name main" "main"
    (Symbol_name.resolve (Coff_symbol.name sym) ~string_table:pf.string_table);
  Alcotest.(check bool) "symbol is function" true (Coff_symbol.is_function sym);
  Alcotest.(check bool) "symbol is external" true (Coff_symbol.is_external sym);
  Alcotest.(check int) "has 1 aux record" 1 (List.length (Coff_symbol.aux_records sym));
  let sec_data = Pe_file.section_data pf sec in
  Alcotest.(check int) "section data length 16" 16 (Bytes.length sec_data)

let test_coff_serialization () =
  let raw = build_sample_coff () in
  let pf = Result.get_ok (Pe_parser.parse_coff_object raw) in
  let ser_res = Pe_serializer.serialize_coff_object pf in
  Alcotest.(check bool) "serialize ok" true (Result.is_ok ser_res);
  let ser_bytes = Result.get_ok ser_res in
  let pf2 = Result.get_ok (Pe_parser.parse_coff_object ser_bytes) in
  Alcotest.(check int) "re-parsed machine matches" pf.coff_header.machine pf2.coff_header.machine;
  Alcotest.(check int) "re-parsed sections count" (List.length pf.sections) (List.length pf2.sections)

(* ========================================================================= *)
(* 4. Minimal PE32+ (64-bit) Executable Parsing & Serialization              *)
(* ========================================================================= *)

let build_sample_pe32plus () =
  let w = Binary_writer.create () in
  Binary_writer.write_string w "MZ";
  Binary_writer.write_zero_pad w 58;
  Binary_writer.write_u32_le w 64l;

  Binary_writer.write_string w "PE\x00\x00";

  Binary_writer.write_u16_le w 0x8664; (* Machine: AMD64 *)
  Binary_writer.write_u16_le w 1;      (* NumberOfSections: 1 *)
  Binary_writer.write_u32_le w 0l;     (* TimeDateStamp *)
  Binary_writer.write_u32_le w 0l;     (* PointerToSymbolTable *)
  Binary_writer.write_u32_le w 0l;     (* NumberOfSymbols *)
  Binary_writer.write_u16_le w 240;    (* SizeOfOptionalHeader = 240 *)
  Binary_writer.write_u16_le w 0x0022; (* EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE *)

  Binary_writer.write_u16_le w 0x20b;  (* Magic: PE32+ *)
  Binary_writer.write_u8 w 14;
  Binary_writer.write_u8 w 0;
  Binary_writer.write_u32_le w 0x1000l;
  Binary_writer.write_u32_le w 0x1000l;
  Binary_writer.write_u32_le w 0l;
  Binary_writer.write_u32_le w 0x1000l;
  Binary_writer.write_u32_le w 0x1000l;
  Binary_writer.write_u64_le w 0x140000000L;
  Binary_writer.write_u32_le w 0x1000l;
  Binary_writer.write_u32_le w 0x200l;
  Binary_writer.write_u16_le w 6;
  Binary_writer.write_u16_le w 0;
  Binary_writer.write_u16_le w 0;
  Binary_writer.write_u16_le w 0;
  Binary_writer.write_u16_le w 6;
  Binary_writer.write_u16_le w 0;
  Binary_writer.write_u32_le w 0l;
  Binary_writer.write_u32_le w 0x3000l;
  Binary_writer.write_u32_le w 0x400l;
  Binary_writer.write_u32_le w 0l;
  Binary_writer.write_u16_le w 3;      (* Subsystem: Windows CUI *)
  Binary_writer.write_u16_le w 0x8160;
  Binary_writer.write_u64_le w 0x100000L;
  Binary_writer.write_u64_le w 0x1000L;
  Binary_writer.write_u64_le w 0x100000L;
  Binary_writer.write_u64_le w 0x1000L;
  Binary_writer.write_u32_le w 0l;
  Binary_writer.write_u32_le w 16l;

  for _ = 1 to 16 do
    Binary_writer.write_u32_le w 0l;
    Binary_writer.write_u32_le w 0l;
  done;

  Binary_writer.write_string w ".text\x00\x00\x00";
  Binary_writer.write_u32_le w 0x100l;
  Binary_writer.write_u32_le w 0x1000l;
  Binary_writer.write_u32_le w 0x200l;
  Binary_writer.write_u32_le w 0x400l;
  Binary_writer.write_u32_le w 0l;
  Binary_writer.write_u32_le w 0l;
  Binary_writer.write_u16_le w 0;
  Binary_writer.write_u16_le w 0;
  Binary_writer.write_u32_le w 0x60000020l;

  let cur = Binary_writer.pos w in
  Binary_writer.write_zero_pad w (0x400 - cur);

  Binary_writer.write_string w "\x48\x31\xc0\xc3";
  Binary_writer.write_zero_pad w (512 - 4);
  Binary_writer.to_bytes w

let test_pe32plus_parse () =
  let raw = build_sample_pe32plus () in
  let res = Pe_parser.parse_pe_file raw in
  Alcotest.(check bool) "parse pe32+ ok" true (Result.is_ok res);
  let pf = Result.get_ok res in
  Alcotest.(check bool) "is image" true (Pe_file.is_image pf);
  Alcotest.(check bool) "has dos stub" true (pf.dos_stub <> None);
  let oh = Option.get pf.optional_header in
  Alcotest.(check bool) "format is Pe32plus" true (oh.format = Optional_header.Pe32plus);
  Alcotest.(check int64) "image base 0x140000000" 0x140000000L oh.windows.image_base;
  Alcotest.(check int32) "entry point 0x1000" 0x1000l oh.standard.address_of_entry_point;
  Alcotest.(check int) "1 section" 1 (List.length pf.sections);
  let sec = List.hd pf.sections in
  Alcotest.(check string) ".text section" ".text" (Section_header.name_string sec);
  let sec_data = Pe_file.section_data pf sec in
  Alcotest.(check int) "section data size 512" 512 (Bytes.length sec_data)

let test_pe_lookups () =
  let raw = build_sample_pe32plus () in
  let pf = Result.get_ok (Pe_parser.parse_pe_file raw) in
  let found_by_name = Pe_file.find_section_by_name pf ".text" in
  Alcotest.(check bool) "found .text by name" true (found_by_name <> None);
  let found_by_rva = Pe_file.find_section_by_rva pf 0x1050 in
  Alcotest.(check bool) "found section by RVA 0x1050" true (found_by_rva <> None);
  let not_found_rva = Pe_file.find_section_by_rva pf 0x9000 in
  Alcotest.(check bool) "RVA 0x9000 not in section" true (not_found_rva = None)

(* ========================================================================= *)
(* 5. Export Resolver Tests                                                  *)
(* ========================================================================= *)

let build_sample_edata () =
  let w = Binary_writer.create () in
  (* Export Directory Table: 40 bytes at offset 0 *)
  Binary_writer.write_u32_le w 0l;     (* ExportFlags *)
  Binary_writer.write_u32_le w 0l;     (* TimeDateStamp *)
  Binary_writer.write_u16_le w 1;      (* MajorVersion *)
  Binary_writer.write_u16_le w 0;      (* MinorVersion *)
  Binary_writer.write_u32_le w 0x2050l;(* NameRVA ("test.dll" at offset 0x50) *)
  Binary_writer.write_u32_le w 1l;     (* OrdinalBase = 1 *)
  Binary_writer.write_u32_le w 2l;     (* AddressTableEntries = 2 *)
  Binary_writer.write_u32_le w 2l;     (* NumberOfNamePointers = 2 *)
  Binary_writer.write_u32_le w 0x2028l;(* ExportAddressTableRVA at offset 40 (0x28) *)
  Binary_writer.write_u32_le w 0x2030l;(* NamePointerTableRVA at offset 48 (0x30) *)
  Binary_writer.write_u32_le w 0x2038l;(* OrdinalTableRVA at offset 56 (0x38) *)

  (* Export Address Table (2 entries * 4 = 8 bytes at offset 40) *)
  Binary_writer.write_u32_le w 0x1000l; (* Export 1 RVA *)
  Binary_writer.write_u32_le w 0x1050l; (* Export 2 RVA *)

  (* Name Pointer Table (2 entries * 4 = 8 bytes at offset 48) *)
  Binary_writer.write_u32_le w 0x2060l; (* -> "fn_add" at offset 0x60 *)
  Binary_writer.write_u32_le w 0x2070l; (* -> "fn_sub" at offset 0x70 *)

  (* Ordinal Table (2 entries * 2 = 4 bytes at offset 56) *)
  Binary_writer.write_u16_le w 0;      (* fn_add -> index 0 *)
  Binary_writer.write_u16_le w 1;      (* fn_sub -> index 1 *)

  (* Pad to offset 0x50 (80 bytes) *)
  let cur = Binary_writer.pos w in
  Binary_writer.write_zero_pad w (0x50 - cur);
  Binary_writer.write_string w "test.dll\x00";

  (* Pad to offset 0x60 (96 bytes) *)
  let cur2 = Binary_writer.pos w in
  Binary_writer.write_zero_pad w (0x60 - cur2);
  Binary_writer.write_string w "fn_add\x00";

  (* Pad to offset 0x70 (112 bytes) *)
  let cur3 = Binary_writer.pos w in
  Binary_writer.write_zero_pad w (0x70 - cur3);
  Binary_writer.write_string w "fn_sub\x00";

  Binary_writer.to_bytes w

let test_export_resolver () =
  let edata_bytes = build_sample_edata () in
  let edata_rva = 0x2000l in
  let res = Export_resolver.parse_exports edata_bytes edata_rva in
  Alcotest.(check bool) "parse exports ok" true (Result.is_ok res);
  let entries = Result.get_ok res in
  Alcotest.(check int) "2 exports" 2 (List.length entries);

  let exp1 = Export_resolver.find_by_name entries "fn_add" in
  Alcotest.(check bool) "found fn_add" true (exp1 <> None);
  let e1 = Option.get exp1 in
  Alcotest.(check int) "fn_add ordinal is 1" 1 e1.ordinal;
  Alcotest.(check int32) "fn_add rva is 0x1000" 0x1000l e1.rva;

  let exp2 = Export_resolver.find_by_ordinal entries 2 in
  Alcotest.(check bool) "found ordinal 2" true (exp2 <> None);
  let e2 = Option.get exp2 in
  Alcotest.(check (option string)) "ordinal 2 is fn_sub" (Some "fn_sub") e2.name;
  Alcotest.(check int32) "fn_sub rva is 0x1050" 0x1050l e2.rva

(* ========================================================================= *)
(* 6. Checksum Service Tests                                                 *)
(* ========================================================================= *)

let test_checksum_computation () =
  let raw = Bytes.of_string "MZ\x00\x00\x00\x00\x00\x00" in
  let csum = Checksum.compute raw ~checksum_offset:4 in
  Alcotest.(check bool) "checksum is computed" true (Int32.compare csum 0l > 0)

(* ========================================================================= *)
(* 7. Archive Format Tests                                                   *)
(* ========================================================================= *)

let build_sample_archive () =
  let w = Binary_writer.create () in
  Binary_writer.write_string w "!<arch>\n";
  Binary_writer.write_string w "test.obj/       ";
  Binary_writer.write_string w "1700000000  ";
  Binary_writer.write_string w "      ";
  Binary_writer.write_string w "      ";
  Binary_writer.write_string w "0       ";
  let coff_obj = build_sample_coff () in
  let obj_len = Bytes.length coff_obj in
  Binary_writer.write_string w (Printf.sprintf "%-10d" obj_len);
  Binary_writer.write_string w "`\n";
  Binary_writer.write_bytes w coff_obj;
  if obj_len mod 2 = 1 then Binary_writer.write_string w "\n";
  Binary_writer.to_bytes w

let test_archive_parse () =
  let raw = build_sample_archive () in
  let res = Pe_parser.parse_archive raw in
  Alcotest.(check bool) "parse archive ok" true (Result.is_ok res);
  let arch = Result.get_ok res in
  Alcotest.(check int) "1 member" 1 (List.length (Archive.members arch));
  let objs = Archive.object_members arch in
  Alcotest.(check int) "1 object member" 1 (List.length objs);
  let (hdr, pf) = List.hd objs in
  Alcotest.(check string) "member name" "test.obj/" hdr.name;
  Alcotest.(check int) "object machine" 0x8664 pf.coff_header.machine

(* ========================================================================= *)
(* 8. Negative & Error Handling Tests                                        *)
(* ========================================================================= *)

let test_invalid_signatures () =
  let bad_pe = Bytes.of_string "NOT_A_PE_FILE" in
  Alcotest.(check bool) "bad pe rejected" true (Result.is_error (Pe_parser.parse_pe_file bad_pe));

  let bad_arch = Bytes.of_string "NOT_AN_ARCHIVE" in
  Alcotest.(check bool) "bad archive rejected" true (Result.is_error (Pe_parser.parse_archive bad_arch));

  let empty = Bytes.empty in
  Alcotest.(check bool) "empty coff rejected" true (Result.is_error (Pe_parser.parse_coff_object empty))

(* ========================================================================= *)
(* 9. Real Binary Integration Tests (if files exist on disk)                 *)
(* ========================================================================= *)

let test_real_guron_exe () =
  let path = "/Volumes/External/temppp1/source/Guron/Win32/Debug/Guron.exe" in
  if Sys.file_exists path then begin
    let res = Ocoff.load_file path in
    Alcotest.(check bool) "load Guron.exe ok" true (Result.is_ok res);
    match Result.get_ok res with
    | `Pe pf ->
      Alcotest.(check int) "x86 machine" 0x014c pf.coff_header.machine;
      Alcotest.(check int) "6 sections" 6 (List.length pf.sections);
      let imports = Result.get_ok (Import_resolver.parse_pe_imports pf) in
      Alcotest.(check bool) "has imports" true (List.length imports > 0)
    | _ -> Alcotest.fail "expected PE image"
  end

let test_real_libeay32_dll () =
  let path = "/Volumes/External/temppp1/source/Guron/Win32/Debug/libeay32.dll" in
  if Sys.file_exists path then begin
    let res = Ocoff.load_file path in
    Alcotest.(check bool) "load libeay32.dll ok" true (Result.is_ok res);
    match Result.get_ok res with
    | `Pe pf ->
      Alcotest.(check int) "x86 machine" 0x014c pf.coff_header.machine;
      let exports = Result.get_ok (Export_resolver.parse_pe_exports pf) in
      Alcotest.(check bool) "has 4000+ exports" true (List.length exports > 4000)
    | _ -> Alcotest.fail "expected PE DLL"
  end

let test_csharp_avalonia_dll () =
  let path = "/Users/password9090/.nuget/packages/avalonia.fonts.inter/12.1.0/lib/net10.0/Avalonia.Fonts.Inter.dll" in
  if Sys.file_exists path then begin
    let res = Ocoff.load_file path in
    Alcotest.(check bool) "load Avalonia .NET 10 DLL ok" true (Result.is_ok res);
    match Result.get_ok res with
    | `Pe pf ->
      let oh = Option.get pf.optional_header in
      let clr_dir = Optional_header.data_directory oh Data_directory.ClrRuntimeHeader in
      Alcotest.(check bool) "has CLR runtime header" true (clr_dir <> None && Data_directory.is_present (Option.get clr_dir));
      let imports = Result.get_ok (Import_resolver.parse_pe_imports pf) in
      Alcotest.(check int) "1 imported DLL (mscoree.dll)" 1 (List.length imports);
      let mscoree = List.hd imports in
      Alcotest.(check string) "mscoree.dll" "mscoree.dll" mscoree.dll_name
    | _ -> Alcotest.fail "expected PE DLL"
  end

let test_csharp_extensions_dll () =
  let path = "/Users/password9090/.nuget/packages/microsoft.extensions.caching.abstractions/10.0.10/lib/net8.0/Microsoft.Extensions.Caching.Abstractions.dll" in
  if Sys.file_exists path then begin
    let res = Ocoff.load_file path in
    Alcotest.(check bool) "load Extensions .NET 8 DLL ok" true (Result.is_ok res);
    match Result.get_ok res with
    | `Pe pf ->
      let oh = Option.get pf.optional_header in
      let clr_dir = Optional_header.data_directory oh Data_directory.ClrRuntimeHeader in
      Alcotest.(check bool) "has CLR runtime header" true (clr_dir <> None && Data_directory.is_present (Option.get clr_dir));
      let imports = Result.get_ok (Import_resolver.parse_pe_imports pf) in
      Alcotest.(check int) "1 imported DLL (mscoree.dll)" 1 (List.length imports)
    | _ -> Alcotest.fail "expected PE DLL"
  end

(* ========================================================================= *)
(* Test Runner                                                               *)
(* ========================================================================= *)

let () =
  Alcotest.run "ocoff" [
    "binary_adapter", [
      Alcotest.test_case "roundtrip" `Quick test_binary_roundtrip;
      Alcotest.test_case "bounds" `Quick test_binary_bounds;
    ];
    "domain_types", [
      Alcotest.test_case "machine_types" `Quick test_machine_types;
      Alcotest.test_case "characteristics" `Quick test_characteristics;
      Alcotest.test_case "subsystems" `Quick test_subsystems;
      Alcotest.test_case "section_flags" `Quick test_section_flags;
    ];
    "coff_object", [
      Alcotest.test_case "parse_sample_coff" `Quick test_coff_object_parse;
      Alcotest.test_case "serialize_coff" `Quick test_coff_serialization;
    ];
    "pe_image", [
      Alcotest.test_case "parse_sample_pe32plus" `Quick test_pe32plus_parse;
      Alcotest.test_case "section_and_rva_lookups" `Quick test_pe_lookups;
    ];
    "export_resolver", [
      Alcotest.test_case "parse_exports" `Quick test_export_resolver;
    ];
    "checksum_service", [
      Alcotest.test_case "compute_checksum" `Quick test_checksum_computation;
    ];
    "archive_format", [
      Alcotest.test_case "parse_sample_archive" `Quick test_archive_parse;
    ];
    "error_handling", [
      Alcotest.test_case "invalid_signatures" `Quick test_invalid_signatures;
    ];
    "real_binaries", [
      Alcotest.test_case "guron_exe" `Quick test_real_guron_exe;
      Alcotest.test_case "libeay32_dll" `Quick test_real_libeay32_dll;
      Alcotest.test_case "csharp_avalonia_dll" `Quick test_csharp_avalonia_dll;
      Alcotest.test_case "csharp_extensions_dll" `Quick test_csharp_extensions_dll;
    ];
  ]
