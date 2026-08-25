(** Section characteristics flags.

    Encodes the [Characteristics] field of [IMAGE_SECTION_HEADER] as
    defined in the PE/COFF specification.  Each bit indicates a property
    or permission of the section.  The [IMAGE_SCN_ALIGN_*] family of bits
    encodes a power-of-two alignment rather than a simple flag. *)

(** A single section-characteristics flag or alignment selector. *)
type flag =
  (* Content-type flags *)
  | TypeNoPad            (** 0x00000008 – obsolete; do not pad to next boundary *)
  | CntCode              (** 0x00000020 – contains executable code *)
  | CntInitializedData   (** 0x00000040 – contains initialised data *)
  | CntUninitializedData (** 0x00000080 – contains uninitialised data (BSS) *)
  (* Link-order and special flags *)
  | LnkOther             (** 0x00000100 – reserved *)
  | LnkInfo              (** 0x00000200 – contains comments or other info (.drectve) *)
  | LnkRemove            (** 0x00000800 – will not become part of the image *)
  | LnkComdat            (** 0x00001000 – contains COMDAT data *)
  | GpRel                (** 0x00008000 – contains data referenced through GP *)
  | MemPurgeable         (** 0x00020000 – reserved (Memory Purgeable) *)
  | MemLocked            (** 0x00040000 – reserved (Memory Locked) *)
  | MemPreload           (** 0x00080000 – reserved (Memory Preload) *)
  (* Alignment – mutually exclusive; use [alignment_of] to decode *)
  | Align1Bytes          (** 0x00100000 – align data on a 1-byte boundary *)
  | Align2Bytes          (** 0x00200000 – align data on a 2-byte boundary *)
  | Align4Bytes          (** 0x00300000 – align data on a 4-byte boundary *)
  | Align8Bytes          (** 0x00400000 – align data on an 8-byte boundary *)
  | Align16Bytes         (** 0x00500000 – align data on a 16-byte boundary (default) *)
  | Align32Bytes         (** 0x00600000 – align data on a 32-byte boundary *)
  | Align64Bytes         (** 0x00700000 – align data on a 64-byte boundary *)
  | Align128Bytes        (** 0x00800000 – align data on a 128-byte boundary *)
  | Align256Bytes        (** 0x00900000 – align data on a 256-byte boundary *)
  | Align512Bytes        (** 0x00a00000 – align data on a 512-byte boundary *)
  | Align1024Bytes       (** 0x00b00000 – align data on a 1024-byte boundary *)
  | Align2048Bytes       (** 0x00c00000 – align data on a 2048-byte boundary *)
  | Align4096Bytes       (** 0x00d00000 – align data on a 4096-byte boundary *)
  | Align8192Bytes       (** 0x00e00000 – align data on an 8192-byte boundary *)
  (* Extended relocation and run-time flags *)
  | LnkNrelocOvfl       (** 0x01000000 – section contains extended relocations *)
  | MemDiscardable       (** 0x02000000 – can be discarded from the loaded image *)
  | MemNotCached         (** 0x04000000 – cannot be cached *)
  | MemNotPaged          (** 0x08000000 – cannot be paged *)
  | MemShared            (** 0x10000000 – can be shared in memory *)
  | MemExecute           (** 0x20000000 – can be executed as code *)
  | MemRead              (** 0x40000000 – can be read *)
  | MemWrite             (** 0x80000000 – can be written to *)

(** Mask that covers all four alignment nibble bits [0x00f00000]. *)
let align_mask = 0x00f00000l

(** Association between each non-alignment flag and its 32-bit mask. *)
let flag_bits : (flag * int32) list = [
  (TypeNoPad,            0x00000008l);
  (CntCode,              0x00000020l);
  (CntInitializedData,   0x00000040l);
  (CntUninitializedData, 0x00000080l);
  (LnkOther,             0x00000100l);
  (LnkInfo,              0x00000200l);
  (LnkRemove,            0x00000800l);
  (LnkComdat,            0x00001000l);
  (GpRel,                0x00008000l);
  (MemPurgeable,         0x00020000l);
  (MemLocked,            0x00040000l);
  (MemPreload,           0x00080000l);
  (Align1Bytes,          0x00100000l);
  (Align2Bytes,          0x00200000l);
  (Align4Bytes,          0x00300000l);
  (Align8Bytes,          0x00400000l);
  (Align16Bytes,         0x00500000l);
  (Align32Bytes,         0x00600000l);
  (Align64Bytes,         0x00700000l);
  (Align128Bytes,        0x00800000l);
  (Align256Bytes,        0x00900000l);
  (Align512Bytes,        0x00a00000l);
  (Align1024Bytes,       0x00b00000l);
  (Align2048Bytes,       0x00c00000l);
  (Align4096Bytes,       0x00d00000l);
  (Align8192Bytes,       0x00e00000l);
  (LnkNrelocOvfl,        0x01000000l);
  (MemDiscardable,       0x02000000l);
  (MemNotCached,         0x04000000l);
  (MemNotPaged,          0x08000000l);
  (MemShared,            0x10000000l);
  (MemExecute,           0x20000000l);
  (MemRead,              0x40000000l);
  (MemWrite,             0x80000000l);
]

(** The ALIGN_* flags occupy nibble bits [23:20] as a 4-bit field where the
    value is one-based (0x1 = 1-byte, 0xe = 8192-byte).  We match the
    entire masked word so that an alignment field of 0 (no alignment
    specified) does not emit a spurious flag. *)
let align_flags : (flag * int32) list = [
  (Align1Bytes,    0x00100000l);
  (Align2Bytes,    0x00200000l);
  (Align4Bytes,    0x00300000l);
  (Align8Bytes,    0x00400000l);
  (Align16Bytes,   0x00500000l);
  (Align32Bytes,   0x00600000l);
  (Align64Bytes,   0x00700000l);
  (Align128Bytes,  0x00800000l);
  (Align256Bytes,  0x00900000l);
  (Align512Bytes,  0x00a00000l);
  (Align1024Bytes, 0x00b00000l);
  (Align2048Bytes, 0x00c00000l);
  (Align4096Bytes, 0x00d00000l);
  (Align8192Bytes, 0x00e00000l);
]

(** [of_uint32 n] decodes the 32-bit section characteristics word [n] into
    the list of all set [flag] values, including the alignment selector. *)
let of_uint32 n =
  (* Non-alignment flags: test individual bits. *)
  let non_align_flags = [
    TypeNoPad; CntCode; CntInitializedData; CntUninitializedData;
    LnkOther; LnkInfo; LnkRemove; LnkComdat; GpRel;
    MemPurgeable; MemLocked; MemPreload;
    LnkNrelocOvfl; MemDiscardable; MemNotCached; MemNotPaged;
    MemShared; MemExecute; MemRead; MemWrite;
  ] in
  let simple =
    List.filter_map (fun flag ->
      match List.assoc_opt flag flag_bits with
      | Some bit ->
        if Int32.logand n bit <> 0l then Some flag else None
      | None -> None
    ) non_align_flags
  in
  (* Alignment flags: match the masked nibble word exactly. *)
  let align_nibble = Int32.logand n align_mask in
  let align_flag =
    if align_nibble = 0l then []
    else
      match List.assoc_opt align_nibble (List.map (fun (f, v) -> (v, f)) align_flags) with
      | Some f -> [f]
      | None -> []
  in
  simple @ align_flag

(** [to_uint32 flags] encodes the flag list [flags] back to a 32-bit
    characteristics word. *)
let to_uint32 flags =
  List.fold_left
    (fun acc flag ->
       match List.assoc_opt flag flag_bits with
       | Some bit -> Int32.logor acc bit
       | None -> acc)
    0l
    flags

(** [has flags flag] is [true] iff [flag] is present in [flags]. *)
let has flags flag = List.mem flag flags

(** [alignment_of flags] extracts the alignment in bytes encoded by the
    [ALIGN_*] flag present in [flags], or [None] if no alignment flag is
    set. *)
let alignment_of flags =
  (* Map each align flag to its byte count. *)
  let align_bytes = function
    | Align1Bytes    -> Some 1
    | Align2Bytes    -> Some 2
    | Align4Bytes    -> Some 4
    | Align8Bytes    -> Some 8
    | Align16Bytes   -> Some 16
    | Align32Bytes   -> Some 32
    | Align64Bytes   -> Some 64
    | Align128Bytes  -> Some 128
    | Align256Bytes  -> Some 256
    | Align512Bytes  -> Some 512
    | Align1024Bytes -> Some 1024
    | Align2048Bytes -> Some 2048
    | Align4096Bytes -> Some 4096
    | Align8192Bytes -> Some 8192
    | _ -> None
  in
  List.find_map align_bytes flags

let flag_to_string = function
  | TypeNoPad            -> "TYPE_NO_PAD"
  | CntCode              -> "CNT_CODE"
  | CntInitializedData   -> "CNT_INITIALIZED_DATA"
  | CntUninitializedData -> "CNT_UNINITIALIZED_DATA"
  | LnkOther             -> "LNK_OTHER"
  | LnkInfo              -> "LNK_INFO"
  | LnkRemove            -> "LNK_REMOVE"
  | LnkComdat            -> "LNK_COMDAT"
  | GpRel                -> "GPREL"
  | MemPurgeable         -> "MEM_PURGEABLE"
  | MemLocked            -> "MEM_LOCKED"
  | MemPreload           -> "MEM_PRELOAD"
  | Align1Bytes          -> "ALIGN_1BYTES"
  | Align2Bytes          -> "ALIGN_2BYTES"
  | Align4Bytes          -> "ALIGN_4BYTES"
  | Align8Bytes          -> "ALIGN_8BYTES"
  | Align16Bytes         -> "ALIGN_16BYTES"
  | Align32Bytes         -> "ALIGN_32BYTES"
  | Align64Bytes         -> "ALIGN_64BYTES"
  | Align128Bytes        -> "ALIGN_128BYTES"
  | Align256Bytes        -> "ALIGN_256BYTES"
  | Align512Bytes        -> "ALIGN_512BYTES"
  | Align1024Bytes       -> "ALIGN_1024BYTES"
  | Align2048Bytes       -> "ALIGN_2048BYTES"
  | Align4096Bytes       -> "ALIGN_4096BYTES"
  | Align8192Bytes       -> "ALIGN_8192BYTES"
  | LnkNrelocOvfl       -> "LNK_NRELOC_OVFL"
  | MemDiscardable       -> "MEM_DISCARDABLE"
  | MemNotCached         -> "MEM_NOT_CACHED"
  | MemNotPaged          -> "MEM_NOT_PAGED"
  | MemShared            -> "MEM_SHARED"
  | MemExecute           -> "MEM_EXECUTE"
  | MemRead              -> "MEM_READ"
  | MemWrite             -> "MEM_WRITE"

(** [pp fmt flags] pretty-prints the flag list [flags] to formatter [fmt]
    as a pipe-separated list of flag names. *)
let pp fmt flags =
  match flags with
  | [] -> Format.pp_print_string fmt "(none)"
  | _ ->
    let strs = List.map flag_to_string flags in
    Format.pp_print_string fmt (String.concat " | " strs)
