(** PE/COFF file characteristics flags.

    Encodes the [Characteristics] field of [IMAGE_FILE_HEADER].  Each bit
    corresponds to a named [IMAGE_FILE_*] constant from the PE/COFF
    specification. *)

(** A single file-characteristics flag bit. *)
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

(** A set of file-characteristics flags, represented as a list of all
    flags whose corresponding bit is set.  Ordering is from
    least-significant to most-significant bit. *)
type t = flag list

(** Association between each flag and its bit mask. *)
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

(** [of_uint16 n] decodes the 16-bit integer [n] read from a COFF file
    header into the list of set [flag] values. *)
let of_uint16 n =
  List.filter_map
    (fun (flag, bit) -> if n land bit <> 0 then Some flag else None)
    flag_bits

(** [to_uint16 flags] encodes the flag list [flags] back to a 16-bit
    integer suitable for writing to a COFF file header. *)
let to_uint16 flags =
  List.fold_left
    (fun acc flag ->
       match List.assoc_opt flag flag_bits with
       | Some bit -> acc lor bit
       | None -> acc)
    0
    flags

(** [has t flag] is [true] iff [flag] is present in the flag set [t]. *)
let has t flag = List.mem flag t

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

(** [pp fmt t] pretty-prints the flag set [t] to formatter [fmt] as a
    pipe-separated list of flag names. *)
let pp fmt flags =
  match flags with
  | [] -> Format.pp_print_string fmt "(none)"
  | _ ->
    let strs = List.map flag_to_string flags in
    Format.pp_print_string fmt (String.concat " | " strs)
