open Ocoff

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
  let raw = 0x2000 lor 0x0002 lor 0x0020 in
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
  let raw = 0x60000020l in
  let flags = Section_flags.of_uint32 raw in
  Alcotest.(check bool) "has CntCode" true (Section_flags.has flags Section_flags.CntCode);
  Alcotest.(check bool) "has MemExecute" true (Section_flags.has flags Section_flags.MemExecute);
  Alcotest.(check bool) "has MemRead" true (Section_flags.has flags Section_flags.MemRead);
  Alcotest.(check bool) "not MemWrite" false (Section_flags.has flags Section_flags.MemWrite);
  Alcotest.(check int32) "roundtrip uint32" raw (Section_flags.to_uint32 flags)

let tests = [
  Alcotest.test_case "machine_types" `Quick test_machine_types;
  Alcotest.test_case "characteristics" `Quick test_characteristics;
  Alcotest.test_case "subsystems" `Quick test_subsystems;
  Alcotest.test_case "section_flags" `Quick test_section_flags;
]
