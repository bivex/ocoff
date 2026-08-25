(** Main Test Runner for ocoff library. *)

let () =
  Alcotest.run "ocoff" [
    "binary_adapter", Test_binary_adapter.tests;
    "domain_types", Test_domain_types.tests;
    "coff_object", Test_coff.tests;
    "pe_image", Test_pe.pe_image_tests;
    "export_resolver", Test_pe.export_tests;
    "checksum_service", Test_pe.checksum_tests;
    "archive_format", Test_pe.archive_tests;
    "error_handling", Test_pe.error_tests;
    "real_binaries", Test_real_binaries.tests;
  ]
