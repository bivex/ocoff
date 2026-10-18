(** COFF Relocation type indicators per machine architecture.

    Defined in section "Type Indicators" of the Microsoft PE/COFF specification. *)

type amd64_rel =
  | Amd64_Absolute
  | Amd64_Addr64
  | Amd64_Addr32
  | Amd64_Addr32nb
  | Amd64_Rel32
  | Amd64_Rel32_1
  | Amd64_Rel32_2
  | Amd64_Rel32_3
  | Amd64_Rel32_4
  | Amd64_Rel32_5
  | Amd64_Section
  | Amd64_Secrel
  | Amd64_Secrel7
  | Amd64_Token
  | Amd64_Srel32
  | Amd64_Pair
  | Amd64_Sspan32
  | Amd64_Unknown of int

type arm_rel =
  | Arm_Absolute
  | Arm_Addr32
  | Arm_Addr32nb
  | Arm_Branch24
  | Arm_Branch11
  | Arm_Rel32
  | Arm_Section
  | Arm_Secrel
  | Arm_Mov32
  | Arm_Thumb_Mov32
  | Arm_Thumb_Branch20
  | Arm_Thumb_Branch24
  | Arm_Thumb_Blx23
  | Arm_Pair
  | Arm_Unknown of int

type arm64_rel =
  | Arm64_Absolute
  | Arm64_Addr32
  | Arm64_Addr32nb
  | Arm64_Branch26
  | Arm64_Pagebase_Rel21
  | Arm64_Rel21
  | Arm64_Pageoffset_12a
  | Arm64_Pageoffset_12l
  | Arm64_Secrel
  | Arm64_Secrel_Low12a
  | Arm64_Secrel_High12a
  | Arm64_Secrel_Low12l
  | Arm64_Token
  | Arm64_Section
  | Arm64_Addr64
  | Arm64_Branch19
  | Arm64_Branch14
  | Arm64_Rel32
  | Arm64_Unknown of int

type i386_rel =
  | I386_Absolute
  | I386_Dir16
  | I386_Rel16
  | I386_Dir32
  | I386_Dir32nb
  | I386_Seg12
  | I386_Section
  | I386_Secrel
  | I386_Token
  | I386_Secrel7
  | I386_Rel32
  | I386_Unknown of int

type ppc_rel =
  | Ppc_Absolute
  | Ppc_Addr64
  | Ppc_Addr32
  | Ppc_Addr24
  | Ppc_Addr16
  | Ppc_Addr14
  | Ppc_Rel24
  | Ppc_Rel14
  | Ppc_Addr32nb
  | Ppc_Secrel
  | Ppc_Section
  | Ppc_Secrel16
  | Ppc_Refhi
  | Ppc_Reflo
  | Ppc_Pair
  | Ppc_Secrello
  | Ppc_Gprel
  | Ppc_Token
  | Ppc_Unknown of int

type mips_rel =
  | Mips_Absolute
  | Mips_Refhalf
  | Mips_Refword
  | Mips_Jmpaddr
  | Mips_Refhi
  | Mips_Reflo
  | Mips_Gprel
  | Mips_Literal
  | Mips_Section
  | Mips_Secrel
  | Mips_Secrello
  | Mips_Secrelhi
  | Mips_Jmpaddr16
  | Mips_Refwordnb
  | Mips_Pair
  | Mips_Unknown of int

type sh_rel =
  | Sh_Absolute
  | Sh_Direct16
  | Sh_Direct32
  | Sh_Direct8
  | Sh_Direct8_Word
  | Sh_Direct8_Long
  | Sh_Direct4
  | Sh_Direct4_Word
  | Sh_Direct4_Long
  | Sh_Pcrel8_Word
  | Sh_Pcrel8_Long
  | Sh_Pcrel12_Word
  | Sh_Startof_Section
  | Sh_Sizeof_Section
  | Sh_Section
  | Sh_Secrel
  | Sh_Direct32_Nb
  | Sh_Gprel4_Long
  | Sh_Token
  | Sh_Pcrelpt
  | Sh_Reflo
  | Sh_Refhalf
  | Sh_Rello
  | Sh_Relhalf
  | Sh_Pair
  | Sh_Nomode
  | Sh_Unknown of int

type m32r_rel =
  | M32r_Absolute
  | M32r_Addr32
  | M32r_Addr32nb
  | M32r_Addr24
  | M32r_Gprel16
  | M32r_Pcrel24
  | M32r_Pcrel16
  | M32r_Pcrel8
  | M32r_Refhalf
  | M32r_Refhi
  | M32r_Reflo
  | M32r_Pair
  | M32r_Section
  | M32r_Secrel
  | M32r_Token
  | M32r_Unknown of int

type ia64_rel =
  | Ia64_Absolute
  | Ia64_Imm14
  | Ia64_Imm22
  | Ia64_Imm64
  | Ia64_Dir32
  | Ia64_Dir64
  | Ia64_Pcrel21b
  | Ia64_Pcrel21m
  | Ia64_Pcrel21f
  | Ia64_Gprel22
  | Ia64_Ltoff22
  | Ia64_Section
  | Ia64_Secrel22
  | Ia64_Secrel64i
  | Ia64_Secrel32
  | Ia64_Dir32nb
  | Ia64_Srel14
  | Ia64_Srel22
  | Ia64_Srel32
  | Ia64_Urel32
  | Ia64_Pcrel60x
  | Ia64_Pcrel60b
  | Ia64_Pcrel60f
  | Ia64_Pcrel60i
  | Ia64_Pcrel60m
  | Ia64_Immgprel64
  | Ia64_Token
  | Ia64_Gprel32
  | Ia64_Addend
  | Ia64_Unknown of int

type t =
  | Amd64 of amd64_rel
  | Arm of arm_rel
  | Arm64 of arm64_rel
  | I386 of i386_rel
  | Ppc of ppc_rel
  | Mips of mips_rel
  | Sh of sh_rel
  | M32r of m32r_rel
  | Ia64 of ia64_rel
  | Generic of int

let amd64_table = [
  (0x0000, Amd64_Absolute, "AMD64_ABSOLUTE");
  (0x0001, Amd64_Addr64, "AMD64_ADDR64");
  (0x0002, Amd64_Addr32, "AMD64_ADDR32");
  (0x0003, Amd64_Addr32nb, "AMD64_ADDR32NB");
  (0x0004, Amd64_Rel32, "AMD64_REL32");
  (0x0005, Amd64_Rel32_1, "AMD64_REL32_1");
  (0x0006, Amd64_Rel32_2, "AMD64_REL32_2");
  (0x0007, Amd64_Rel32_3, "AMD64_REL32_3");
  (0x0008, Amd64_Rel32_4, "AMD64_REL32_4");
  (0x0009, Amd64_Rel32_5, "AMD64_REL32_5");
  (0x000A, Amd64_Section, "AMD64_SECTION");
  (0x000B, Amd64_Secrel, "AMD64_SECREL");
  (0x000C, Amd64_Secrel7, "AMD64_SECREL7");
  (0x000D, Amd64_Token, "AMD64_TOKEN");
  (0x000E, Amd64_Srel32, "AMD64_SREL32");
  (0x000F, Amd64_Pair, "AMD64_PAIR");
  (0x0010, Amd64_Sspan32, "AMD64_SSPAN32");
]

let i386_table = [
  (0x0000, I386_Absolute, "I386_ABSOLUTE");
  (0x0001, I386_Dir16, "I386_DIR16");
  (0x0002, I386_Rel16, "I386_REL16");
  (0x0006, I386_Dir32, "I386_DIR32");
  (0x0007, I386_Dir32nb, "I386_DIR32NB");
  (0x0009, I386_Seg12, "I386_SEG12");
  (0x000A, I386_Section, "I386_SECTION");
  (0x000B, I386_Secrel, "I386_SECREL");
  (0x000C, I386_Token, "I386_TOKEN");
  (0x000D, I386_Secrel7, "I386_SECREL7");
  (0x0014, I386_Rel32, "I386_REL32");
]

let arm64_table = [
  (0x0000, Arm64_Absolute, "ARM64_ABSOLUTE");
  (0x0001, Arm64_Addr32, "ARM64_ADDR32");
  (0x0002, Arm64_Addr32nb, "ARM64_ADDR32NB");
  (0x0003, Arm64_Branch26, "ARM64_BRANCH26");
  (0x0004, Arm64_Pagebase_Rel21, "ARM64_PAGEBASE_REL21");
  (0x0005, Arm64_Rel21, "ARM64_REL21");
  (0x0006, Arm64_Pageoffset_12a, "ARM64_PAGEOFFSET_12A");
  (0x0007, Arm64_Pageoffset_12l, "ARM64_PAGEOFFSET_12L");
  (0x0008, Arm64_Secrel, "ARM64_SECREL");
  (0x0009, Arm64_Secrel_Low12a, "ARM64_SECREL_LOW12A");
  (0x000A, Arm64_Secrel_High12a, "ARM64_SECREL_HIGH12A");
  (0x000B, Arm64_Secrel_Low12l, "ARM64_SECREL_LOW12L");
  (0x000C, Arm64_Token, "ARM64_TOKEN");
  (0x000D, Arm64_Section, "ARM64_SECTION");
  (0x000E, Arm64_Addr64, "ARM64_ADDR64");
  (0x000F, Arm64_Branch19, "ARM64_BRANCH19");
  (0x0010, Arm64_Branch14, "ARM64_BRANCH14");
  (0x0011, Arm64_Rel32, "ARM64_REL32");
]

let arm_table = [
  (0x0000, Arm_Absolute, "ARM_ABSOLUTE");
  (0x0001, Arm_Addr32, "ARM_ADDR32");
  (0x0002, Arm_Addr32nb, "ARM_ADDR32NB");
  (0x0003, Arm_Branch24, "ARM_BRANCH24");
  (0x0004, Arm_Branch11, "ARM_BRANCH11");
  (0x000A, Arm_Rel32, "ARM_REL32");
  (0x000E, Arm_Section, "ARM_SECTION");
  (0x000F, Arm_Secrel, "ARM_SECREL");
  (0x0010, Arm_Mov32, "ARM_MOV32");
  (0x0011, Arm_Thumb_Mov32, "ARM_THUMB_MOV32");
  (0x0012, Arm_Thumb_Branch20, "ARM_THUMB_BRANCH20");
  (0x0014, Arm_Thumb_Branch24, "ARM_THUMB_BRANCH24");
  (0x0015, Arm_Thumb_Blx23, "ARM_THUMB_BLX23");
  (0x0016, Arm_Pair, "ARM_PAIR");
]

let lookup_code code table =
  List.find_map (fun (c, r, _) -> if c = code then Some r else None) table

let lookup_rel rel table =
  List.find_map (fun (c, r, _) -> if r = rel then Some c else None) table

let lookup_name rel table =
  List.find_map (fun (_, r, s) -> if r = rel then Some s else None) table

let amd64_of_uint16 n =
  match lookup_code n amd64_table with
  | Some r -> r
  | None -> Amd64_Unknown n

let amd64_to_uint16 = function
  | Amd64_Unknown n -> n
  | r -> Option.value (lookup_rel r amd64_table) ~default:0

let amd64_to_string = function
  | Amd64_Unknown n -> Printf.sprintf "AMD64_UNKNOWN(0x%04x)" n
  | r -> Option.value (lookup_name r amd64_table) ~default:"AMD64_UNKNOWN"

let i386_of_uint16 n =
  match lookup_code n i386_table with
  | Some r -> r
  | None -> I386_Unknown n

let i386_to_uint16 = function
  | I386_Unknown n -> n
  | r -> Option.value (lookup_rel r i386_table) ~default:0

let i386_to_string = function
  | I386_Unknown n -> Printf.sprintf "I386_UNKNOWN(0x%04x)" n
  | r -> Option.value (lookup_name r i386_table) ~default:"I386_UNKNOWN"

let arm64_of_uint16 n =
  match lookup_code n arm64_table with
  | Some r -> r
  | None -> Arm64_Unknown n

let arm64_to_uint16 = function
  | Arm64_Unknown n -> n
  | r -> Option.value (lookup_rel r arm64_table) ~default:0

let arm64_to_string = function
  | Arm64_Unknown n -> Printf.sprintf "ARM64_UNKNOWN(0x%04x)" n
  | r -> Option.value (lookup_name r arm64_table) ~default:"ARM64_UNKNOWN"

let arm_of_uint16 n =
  match lookup_code n arm_table with
  | Some r -> r
  | None -> Arm_Unknown n

let arm_to_uint16 = function
  | Arm_Unknown n -> n
  | r -> Option.value (lookup_rel r arm_table) ~default:0

let arm_to_string = function
  | Arm_Unknown n -> Printf.sprintf "ARM_UNKNOWN(0x%04x)" n
  | r -> Option.value (lookup_name r arm_table) ~default:"ARM_UNKNOWN"

let of_uint16_arm machine n =
  match machine with
  | Machine_type.Arm64 | Machine_type.Arm64ec | Machine_type.Arm64x ->
    Arm64 (arm64_of_uint16 n)
  | Machine_type.Arm | Machine_type.Armnt | Machine_type.Thumb ->
    Arm (arm_of_uint16 n)
  | _ -> Generic n

let of_uint16 ~(machine : Machine_type.t) n =
  match machine with
  | Machine_type.Amd64 -> Amd64 (amd64_of_uint16 n)
  | Machine_type.I386 -> I386 (i386_of_uint16 n)
  | other -> of_uint16_arm other n

let to_uint16_other = function
  | Ppc _ | Mips _ | Sh _ | M32r _ | Ia64 _ -> 0
  | Generic n -> n
  | _ -> 0

let to_uint16 = function
  | Amd64 r -> amd64_to_uint16 r
  | I386 r -> i386_to_uint16 r
  | Arm64 r -> arm64_to_uint16 r
  | Arm r -> arm_to_uint16 r
  | other -> to_uint16_other other

let to_string_other = function
  | Ppc _ -> "PPC_RELOC"
  | Mips _ -> "MIPS_RELOC"
  | Sh _ -> "SH_RELOC"
  | M32r _ -> "M32R_RELOC"
  | Ia64 _ -> "IA64_RELOC"
  | Generic n -> Printf.sprintf "RELOC(0x%04x)" n
  | _ -> "UNKNOWN_RELOC"

let to_string = function
  | Amd64 r -> amd64_to_string r
  | I386 r -> i386_to_string r
  | Arm64 r -> arm64_to_string r
  | Arm r -> arm_to_string r
  | other -> to_string_other other

let pp fmt t = Format.pp_print_string fmt (to_string t)
