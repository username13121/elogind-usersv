#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = elogind_usersvd::app::run().await {
        eprintln!("elogind-usersvd: fatal: {error:#}");
        std::process::exit(1);
    }
}
