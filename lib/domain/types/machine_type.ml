(** CPU architecture identifiers stored in the COFF file header.

    Values correspond to the [Machine] field of [IMAGE_FILE_HEADER] as
    defined in the Microsoft PE/COFF specification, revision 11. *)

(** All machine-type constants recognised by the PE/COFF specification. *)
type t =
  | Unknown       (** 0x0000 – content is applicable to any machine type *)
  | Alpha         (** 0x0184 – Alpha AXP, 32-bit address space *)
  | Alpha64       (** 0x0284 – Alpha AXP, 64-bit address space *)
  | Am33          (** 0x01d3 – Matsushita AM33 *)
  | Amd64         (** 0x8664 – x86-64 / AMD64 *)
  | Arm           (** 0x01c0 – ARM little-endian *)
  | Arm64         (** 0xaa64 – ARM64 little-endian *)
  | Arm64ec       (** 0xa641 – ARM64EC (emulation-compatible) *)
  | Arm64x        (** 0xa64e – ARM64X (hybrid) *)
  | Armnt         (** 0x01c4 – ARM Thumb-2 little-endian *)
  | Axp64         (** 0x0284 – AXP 64 (alias for Alpha64) *)
  | Ebc           (** 0x0ebc – EFI byte code *)
  | I386          (** 0x014c – Intel 386 and later, x86 compatible *)
  | Ia64          (** 0x0200 – Intel Itanium *)
  | LoongArch32   (** 0x6232 – LoongArch 32-bit *)
  | LoongArch64   (** 0x6264 – LoongArch 64-bit *)
  | M32r          (** 0x9041 – Mitsubishi M32R little-endian *)
  | Mips16        (** 0x0266 – MIPS16 *)
  | MipsFpu       (** 0x0366 – MIPS with FPU *)
  | MipsFpu16     (** 0x0466 – MIPS16 with FPU *)
  | PowerPc       (** 0x01f0 – Power PC little-endian *)
  | PowerPcFp     (** 0x01f1 – Power PC with floating-point support *)
  | R3000be       (** 0x0160 – MIPS R3000 big-endian (MIPSEB) *)
  | R3000         (** 0x0162 – MIPS R3000 little-endian *)
  | R4000         (** 0x0166 – MIPS R4000 little-endian *)
  | R10000        (** 0x0168 – MIPS R10000 little-endian *)
  | RiscV32       (** 0x5032 – RISC-V 32-bit address space *)
  | RiscV64       (** 0x5064 – RISC-V 64-bit address space *)
  | RiscV128      (** 0x5128 – RISC-V 128-bit address space *)
  | Sh3           (** 0x01a2 – Hitachi SH3 *)
  | Sh3dsp        (** 0x01a3 – Hitachi SH3 DSP *)
  | Sh4           (** 0x01a6 – Hitachi SH4 *)
  | Sh5           (** 0x01a8 – Hitachi SH5 *)
  | Thumb         (** 0x01c2 – Thumb *)
  | WceMipsV2     (** 0x0169 – MIPS little-endian WCE v2 *)

(** [of_uint16 n] decodes the 16-bit integer [n] read from a COFF file
    header into the corresponding [t] value.

    Returns [Error (`Unknown_machine n)] when [n] does not match any
    constant known to this implementation. *)
let of_uint16 = function
  | 0x0000 -> Ok Unknown
  | 0x0184 -> Ok Alpha
  | 0x0284 -> Ok Alpha64   (* Alpha64 and Axp64 share this value *)
  | 0x01d3 -> Ok Am33
  | 0x8664 -> Ok Amd64
  | 0x01c0 -> Ok Arm
  | 0xaa64 -> Ok Arm64
  | 0xa641 -> Ok Arm64ec
  | 0xa64e -> Ok Arm64x
  | 0x01c4 -> Ok Armnt
  | 0x0ebc -> Ok Ebc
  | 0x014c -> Ok I386
  | 0x0200 -> Ok Ia64
  | 0x6232 -> Ok LoongArch32
  | 0x6264 -> Ok LoongArch64
  | 0x9041 -> Ok M32r
  | 0x0266 -> Ok Mips16
  | 0x0366 -> Ok MipsFpu
  | 0x0466 -> Ok MipsFpu16
  | 0x01f0 -> Ok PowerPc
  | 0x01f1 -> Ok PowerPcFp
  | 0x0160 -> Ok R3000be
  | 0x0162 -> Ok R3000
  | 0x0166 -> Ok R4000
  | 0x0168 -> Ok R10000
  | 0x5032 -> Ok RiscV32
  | 0x5064 -> Ok RiscV64
  | 0x5128 -> Ok RiscV128
  | 0x01a2 -> Ok Sh3
  | 0x01a3 -> Ok Sh3dsp
  | 0x01a6 -> Ok Sh4
  | 0x01a8 -> Ok Sh5
  | 0x01c2 -> Ok Thumb
  | 0x0169 -> Ok WceMipsV2
  | n -> Error (`Unknown_machine n)

(** [to_uint16 t] encodes machine type [t] as its 16-bit wire value. *)
let to_uint16 = function
  | Unknown     -> 0x0000
  | Alpha       -> 0x0184
  | Alpha64     -> 0x0284
  | Am33        -> 0x01d3
  | Amd64       -> 0x8664
  | Arm         -> 0x01c0
  | Arm64       -> 0xaa64
  | Arm64ec     -> 0xa641
  | Arm64x      -> 0xa64e
  | Armnt       -> 0x01c4
  | Axp64       -> 0x0284
  | Ebc         -> 0x0ebc
  | I386        -> 0x014c
  | Ia64        -> 0x0200
  | LoongArch32 -> 0x6232
  | LoongArch64 -> 0x6264
  | M32r        -> 0x9041
  | Mips16      -> 0x0266
  | MipsFpu     -> 0x0366
  | MipsFpu16   -> 0x0466
  | PowerPc     -> 0x01f0
  | PowerPcFp   -> 0x01f1
  | R3000be     -> 0x0160
  | R3000       -> 0x0162
  | R4000       -> 0x0166
  | R10000      -> 0x0168
  | RiscV32     -> 0x5032
  | RiscV64     -> 0x5064
  | RiscV128    -> 0x5128
  | Sh3         -> 0x01a2
  | Sh3dsp      -> 0x01a3
  | Sh4         -> 0x01a6
  | Sh5         -> 0x01a8
  | Thumb       -> 0x01c2
  | WceMipsV2   -> 0x0169

(** [to_string t] returns a concise, human-readable name for machine
    type [t] suitable for display in diagnostic output. *)
let to_string = function
  | Unknown     -> "Unknown"
  | Alpha       -> "Alpha AXP (32-bit)"
  | Alpha64     -> "Alpha AXP (64-bit)"
  | Am33        -> "Matsushita AM33"
  | Amd64       -> "x86-64"
  | Arm         -> "ARM (little-endian)"
  | Arm64       -> "ARM64"
  | Arm64ec     -> "ARM64EC"
  | Arm64x      -> "ARM64X"
  | Armnt       -> "ARM Thumb-2 (little-endian)"
  | Axp64       -> "AXP 64"
  | Ebc         -> "EFI Byte Code"
  | I386        -> "x86"
  | Ia64        -> "Itanium"
  | LoongArch32 -> "LoongArch32"
  | LoongArch64 -> "LoongArch64"
  | M32r        -> "Mitsubishi M32R (little-endian)"
  | Mips16      -> "MIPS16"
  | MipsFpu     -> "MIPS with FPU"
  | MipsFpu16   -> "MIPS16 with FPU"
  | PowerPc     -> "Power PC (little-endian)"
  | PowerPcFp   -> "Power PC with FP"
  | R3000be     -> "MIPS R3000 (big-endian)"
  | R3000       -> "MIPS R3000"
  | R4000       -> "MIPS R4000"
  | R10000      -> "MIPS R10000"
  | RiscV32     -> "RISC-V 32-bit"
  | RiscV64     -> "RISC-V 64-bit"
  | RiscV128    -> "RISC-V 128-bit"
  | Sh3         -> "Hitachi SH3"
  | Sh3dsp      -> "Hitachi SH3 DSP"
  | Sh4         -> "Hitachi SH4"
  | Sh5         -> "Hitachi SH5"
  | Thumb       -> "Thumb"
  | WceMipsV2   -> "MIPS little-endian WCE v2"

(** [pp fmt t] pretty-prints machine type [t] to formatter [fmt]. *)
let pp fmt t = Format.pp_print_string fmt (to_string t)
