open Ocoff

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

let tests = [
  Alcotest.test_case "parse_sample_pe32plus" `Quick test_pe32plus_parse;
  Alcotest.test_case "section_and_rva_lookups" `Quick test_pe_lookups;
]
