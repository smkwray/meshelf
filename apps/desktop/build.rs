fn main() {
    slint_build::compile("ui/main.slint").expect("compile Slint UI");

    #[cfg(windows)]
    {
        println!("cargo:rerun-if-changed=../../assets/meshelf.ico");
        let mut resource = winresource::WindowsResource::new();
        resource.set_icon("../../assets/meshelf.ico");
        resource
            .compile()
            .expect("compile meshelf Windows icon resource");
    }
}
