fn main() {
    protobuf_codegen::Codegen
        ::new()
        .include("src/protos")
        .input("src/protos/apple.proto")
        .input("src/protos/google.proto")
        .cargo_out_dir("protos")
        .run_from_script();
}
