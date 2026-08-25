(** Main Test Runner for ocoff library. *)

let () =
  Alcotest.run "ocoff" [
    "binary_adapter", Test_binary_adapter.tests;
    "domain_types", Test_domain_types.tests;
    "coff_object", Test_coff.tests;
    "pe_image", Test_pe_image.tests;
    "export_resolver", Test_export_resolver.tests;
    "checksum_service", Test_checksum.tests;
    "archive_format", Test_archive.tests;
    "error_handling", Test_error_handling.tests;
    "real_binaries", Test_real_binaries.tests;
  ]
