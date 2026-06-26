fn main() {
    // WinFSP só suporta delay-load; emite as flags de link necessárias.
    #[cfg(windows)]
    winfsp::build::winfsp_link_delayload();
}
