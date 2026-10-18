(** COFF Symbol Storage Class.

    Defined in section "Storage Class" of the Microsoft PE/COFF specification. *)

type t =
  | EndOfFunction      (** -1 / 0xFF *)
  | Null               (** 0 *)
  | Automatic          (** 1 *)
  | External           (** 2 *)
  | Static             (** 3 *)
  | Register           (** 4 *)
  | ExternalDef        (** 5 *)
  | Label              (** 6 *)
  | UndefinedLabel     (** 7 *)
  | MemberOfStruct     (** 8 *)
  | Argument           (** 9 *)
  | StructTag          (** 10 *)
  | MemberOfUnion      (** 11 *)
  | UnionTag           (** 12 *)
  | TypeDefinition     (** 13 *)
  | UndefinedStatic    (** 14 *)
  | EnumTag            (** 15 *)
  | MemberOfEnum       (** 16 *)
  | RegisterParam      (** 17 *)
  | BitField           (** 18 *)
  | Block              (** 100 *)
  | Function           (** 101 *)
  | EndOfStruct        (** 102 *)
  | File               (** 103 *)
  | Section            (** 104 *)
  | WeakExternal       (** 105 *)
  | ClrToken           (** 107 *)
  | Unknown of int

let of_uint8_special = function
  | 0xFF -> EndOfFunction
  | 100 -> Block
  | 101 -> Function
  | 102 -> EndOfStruct
  | 103 -> File
  | 104 -> Section
  | 105 -> WeakExternal
  | 107 -> ClrToken
  | n -> Unknown n

let of_uint8_tags = function
  | 14 -> UndefinedStatic
  | 15 -> EnumTag
  | 16 -> MemberOfEnum
  | 17 -> RegisterParam
  | 18 -> BitField
  | n -> of_uint8_special n

let of_uint8_types = function
  | 8 -> MemberOfStruct
  | 9 -> Argument
  | 10 -> StructTag
  | 11 -> MemberOfUnion
  | 12 -> UnionTag
  | 13 -> TypeDefinition
  | n -> of_uint8_tags n

let of_uint8 = function
  | 0 -> Null
  | 1 -> Automatic
  | 2 -> External
  | 3 -> Static
  | 4 -> Register
  | 5 -> ExternalDef
  | 6 -> Label
  | 7 -> UndefinedLabel
  | n -> of_uint8_types n

let to_uint8_special = function
  | EndOfFunction -> 0xFF
  | Block -> 100
  | Function -> 101
  | EndOfStruct -> 102
  | File -> 103
  | Section -> 104
  | Unknown n -> n
  | _ -> 0

let to_uint8_tags = function
  | WeakExternal -> 105
  | ClrToken -> 107
  | UndefinedStatic -> 14
  | EnumTag -> 15
  | MemberOfEnum -> 16
  | RegisterParam -> 17
  | BitField -> 18
  | other -> to_uint8_special other

let to_uint8_types = function
  | MemberOfStruct -> 8
  | Argument -> 9
  | StructTag -> 10
  | MemberOfUnion -> 11
  | UnionTag -> 12
  | TypeDefinition -> 13
  | other -> to_uint8_tags other

let to_uint8 = function
  | Null -> 0
  | Automatic -> 1
  | External -> 2
  | Static -> 3
  | Register -> 4
  | ExternalDef -> 5
  | Label -> 6
  | UndefinedLabel -> 7
  | other -> to_uint8_types other

let to_string_special = function
  | EndOfFunction -> "END_OF_FUNCTION"
  | Block -> "BLOCK"
  | Function -> "FUNCTION"
  | EndOfStruct -> "END_OF_STRUCT"
  | File -> "FILE"
  | Section -> "SECTION"
  | Unknown n -> Printf.sprintf "UNKNOWN(%d)" n
  | _ -> "UNKNOWN"

let to_string_tags = function
  | WeakExternal -> "WEAK_EXTERNAL"
  | ClrToken -> "CLR_TOKEN"
  | UndefinedStatic -> "UNDEFINED_STATIC"
  | EnumTag -> "ENUM_TAG"
  | MemberOfEnum -> "MEMBER_OF_ENUM"
  | RegisterParam -> "REGISTER_PARAM"
  | BitField -> "BIT_FIELD"
  | other -> to_string_special other

let to_string_types = function
  | MemberOfStruct -> "MEMBER_OF_STRUCT"
  | Argument -> "ARGUMENT"
  | StructTag -> "STRUCT_TAG"
  | MemberOfUnion -> "MEMBER_OF_UNION"
  | UnionTag -> "UNION_TAG"
  | TypeDefinition -> "TYPE_DEFINITION"
  | other -> to_string_tags other

let to_string = function
  | Null -> "NULL"
  | Automatic -> "AUTOMATIC"
  | External -> "EXTERNAL"
  | Static -> "STATIC"
  | Register -> "REGISTER"
  | ExternalDef -> "EXTERNAL_DEF"
  | Label -> "LABEL"
  | UndefinedLabel -> "UNDEFINED_LABEL"
  | other -> to_string_types other

let pp fmt t = Format.pp_print_string fmt (to_string t)
