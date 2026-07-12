fn main() {
    // 编译前终止所有运行中的旧进程，防止二进制文件被锁定导致编译失败
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/f", "/im", "rustdesk-sos.exe"])
            .output();
    }

    // 嵌入 Windows 可执行文件图标
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("../res/icon.ico");
        res.compile().unwrap();
    }
    // 编译 protobuf
    let out_dir = format!("{}/protos", std::env::var("OUT_DIR").unwrap());
    std::fs::create_dir_all(&out_dir).unwrap();

    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(out_dir)
        .inputs(["protos/rendezvous.proto", "protos/message.proto"])
        .include("protos")
        .customize(protobuf_codegen::Customize::default().tokio_bytes(true))
        .run()
        .expect("Protobuf codegen failed.");

    // 编译 Windows 平台 C++ 辅助代码
    #[cfg(windows)]
    {
        let file = "platform/windows.cc";
        cc::Build::new()
            .file(file)
            .compile("sos_windows");
        println!("cargo:rustc-link-lib=WtsApi32");
        println!("cargo:rerun-if-changed={}", file);
    }
}
