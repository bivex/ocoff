(** An 8-byte IMAGE_DATA_DIRECTORY entry: virtual_address + size.

    The PE optional header contains an array of up to 16 of these entries
    (indexed 0–15), each describing the location and size of an important
    data structure within the image. *)

(** The logical role of a data-directory slot. *)
type kind =
  | ExportTable           (** Index 0: export directory *)
  | ImportTable           (** Index 1: import directory *)
  | ResourceTable         (** Index 2: resource directory *)
  | ExceptionTable        (** Index 3: exception directory (.pdata) *)
  | CertificateTable      (** Index 4: attribute certificate table *)
  | BaseRelocationTable   (** Index 5: base relocation table *)
  | Debug                 (** Index 6: debug directory *)
  | Architecture          (** Index 7: architecture-specific data (reserved, zero) *)
  | GlobalPtr             (** Index 8: RVA of the value to be stored in the global pointer register *)
  | TlsTable              (** Index 9: thread-local storage directory *)
  | LoadConfigTable       (** Index 10: load configuration directory *)
  | BoundImport           (** Index 11: bound import directory *)
  | Iat                   (** Index 12: import address table *)
  | DelayImportDescriptor (** Index 13: delay-load import descriptor *)
  | ClrRuntimeHeader      (** Index 14: CLR (.NET) runtime header *)
  | Reserved              (** Index 15 and any unrecognised index *)

(** Map a 0-based data-directory index to its [kind]. *)
let kind_of_index = function
  | 0  -> ExportTable
  | 1  -> ImportTable
  | 2  -> ResourceTable
  | 3  -> ExceptionTable
  | 4  -> CertificateTable
  | 5  -> BaseRelocationTable
  | 6  -> Debug
  | 7  -> Architecture
  | 8  -> GlobalPtr
  | 9  -> TlsTable
  | 10 -> LoadConfigTable
  | 11 -> BoundImport
  | 12 -> Iat
  | 13 -> DelayImportDescriptor
  | 14 -> ClrRuntimeHeader
  | _  -> Reserved

(** Human-readable name for a [kind]. *)
let kind_to_string = function
  | ExportTable           -> "Export Table"
  | ImportTable           -> "Import Table"
  | ResourceTable         -> "Resource Table"
  | ExceptionTable        -> "Exception Table"
  | CertificateTable      -> "Certificate Table"
  | BaseRelocationTable   -> "Base Relocation Table"
  | Debug                 -> "Debug"
  | Architecture          -> "Architecture"
  | GlobalPtr             -> "Global Ptr"
  | TlsTable              -> "TLS Table"
  | LoadConfigTable       -> "Load Config Table"
  | BoundImport           -> "Bound Import"
  | Iat                   -> "IAT"
  | DelayImportDescriptor -> "Delay Import Descriptor"
  | ClrRuntimeHeader      -> "CLR Runtime Header"
  | Reserved              -> "Reserved"

(** A single IMAGE_DATA_DIRECTORY record. *)
type t = {
  kind: kind;
  (** Logical role of this directory entry. *)
  virtual_address: int32;
  (** RVA of the structure this entry describes, or 0 if absent. *)
  size: int32;
  (** Size in bytes of the structure, or 0 if absent. *)
}

(** Construct a data directory entry. *)
let make ~kind ~virtual_address ~size = { kind; virtual_address; size }

let kind t = t.kind
let virtual_address t = t.virtual_address
let size t = t.size

(** Return [true] when either [virtual_address] or [size] is non-zero,
    indicating the directory entry is populated. *)
let is_present t =
  Int32.compare t.virtual_address 0l <> 0 ||
  Int32.compare t.size 0l <> 0

let pp fmt t =
  Format.fprintf fmt "%s: va=0x%lx size=0x%lx"
    (kind_to_string t.kind) t.virtual_address t.size
