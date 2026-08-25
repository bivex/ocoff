(** PE/COFF file characteristics flags.
    Encodes the [Characteristics] field of [IMAGE_FILE_HEADER]. *)

type flag =
  | RelocsStripped        (** 0x0001 – relocations stripped; must be loaded at preferred base *)
  | ExecutableImage       (** 0x0002 – file can be run *)
  | LineNumsStripped      (** 0x0004 – COFF line-number info stripped *)
  | LocalSymsStripped     (** 0x0008 – COFF local symbol table stripped *)
  | AggressiveWsTrim      (** 0x0010 – aggressively trim working set (obsolete) *)
  | LargeAddressAware     (** 0x0020 – can handle addresses > 2 GB *)
  | BytesReversedLo       (** 0x0080 – little-endian word (deprecated) *)
  | Machine32bit          (** 0x0100 – 32-bit word machine *)
  | DebugStripped         (** 0x0200 – debug info stripped, lives in separate .DBG file *)
  | RemovableRunFromSwap  (** 0x0400 – copy to swap before run if on removable media *)
  | NetRunFromSwap        (** 0x0800 – copy to swap before run if on network media *)
  | System                (** 0x1000 – system file, not a user program *)
  | Dll                   (** 0x2000 – DLL *)
  | UpSystemOnly          (** 0x4000 – run only on uniprocessor system *)
  | BytesReversedHi       (** 0x8000 – big-endian word (deprecated) *)

let flag_to_string = function
  | RelocsStripped        -> "RELOCS_STRIPPED"
  | ExecutableImage       -> "EXECUTABLE_IMAGE"
  | LineNumsStripped      -> "LINE_NUMS_STRIPPED"
  | LocalSymsStripped     -> "LOCAL_SYMS_STRIPPED"
  | AggressiveWsTrim      -> "AGGRESSIVE_WS_TRIM"
  | LargeAddressAware     -> "LARGE_ADDRESS_AWARE"
  | BytesReversedLo       -> "BYTES_REVERSED_LO"
  | Machine32bit          -> "32BIT_MACHINE"
  | DebugStripped         -> "DEBUG_STRIPPED"
  | RemovableRunFromSwap  -> "REMOVABLE_RUN_FROM_SWAP"
  | NetRunFromSwap        -> "NET_RUN_FROM_SWAP"
  | System                -> "SYSTEM"
  | Dll                   -> "DLL"
  | UpSystemOnly          -> "UP_SYSTEM_ONLY"
  | BytesReversedHi       -> "BYTES_REVERSED_HI"

let flag_bits : (flag * int) list = [
  (RelocsStripped,       0x0001);
  (ExecutableImage,      0x0002);
  (LineNumsStripped,     0x0004);
  (LocalSymsStripped,    0x0008);
  (AggressiveWsTrim,     0x0010);
  (LargeAddressAware,    0x0020);
  (BytesReversedLo,      0x0080);
  (Machine32bit,         0x0100);
  (DebugStripped,        0x0200);
  (RemovableRunFromSwap, 0x0400);
  (NetRunFromSwap,       0x0800);
  (System,               0x1000);
  (Dll,                  0x2000);
  (UpSystemOnly,         0x4000);
  (BytesReversedHi,      0x8000);
]

include Flag_set.Make(struct
  type nonrec flag = flag
  let flag_bits = flag_bits
  let flag_to_string = flag_to_string
end)
