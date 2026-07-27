use std::{net::SocketAddr, path::PathBuf};

use anyhow::Result;
use clap::Parser;
use sing_box_ser_mini::config::Config;

#[derive(Debug, Parser)]
#[command(about = "Hysteria 2 server-only implementation")]
struct Args {
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
    #[arg(long, help = "Validate configuration without opening a UDP socket")]
    check: bool,
    #[arg(long, default_value = "127.0.0.1:9080")]
    admin_listen: SocketAddr,
    #[arg(long)]
    admin_token_file: Option<PathBuf>,
    #[arg(long, default_value = ".admin-credentials.toml")]
    admin_credentials_file: PathBuf,
    #[arg(long, default_value = "admin")]
    admin_username: String,
    #[arg(long, help = "Generate a new password for the admin WebUI and exit")]
    reset_admin_password: bool,
    #[arg(long)]
    no_admin: bool,
    #[arg(long, help = "Tokio runtime worker threads (default: up to 4)")]
    worker_threads: Option<usize>,
}

fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("install rustls ring crypto provider"))?;
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let worker_threads = args.worker_threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map_or(1, std::num::NonZeroUsize::get)
            .min(4)
    });
    anyhow::ensure!(
        worker_threads > 0,
        "worker thread count must be greater than zero"
    );
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()?
        .block_on(run(args, worker_threads))
}

async fn run(args: Args, worker_threads: usize) -> Result<()> {
    if args.reset_admin_password {
        let credentials = sing_box_ser_mini::admin::reset_credentials(
            &args.admin_credentials_file,
            &args.admin_username,
        )?;
        println!("Admin username: {}", credentials.username);
        println!("Admin password: {}", credentials.password);
        println!(
            "Credentials written to {}",
            args.admin_credentials_file.display()
        );
        return Ok(());
    }
    let config = Config::load(&args.config)?;
    if args.check {
        println!(
            "HY2 server configuration is valid: listen={}, users={}",
            config.listen,
            config.users.len()
        );
        return Ok(());
    }
    if args.no_admin {
        return sing_box_ser_mini::server::run(config).await;
    }
    let admin_token_file = args.admin_token_file.clone();
    let token = if let Some(path) = &admin_token_file {
        Some(std::fs::read_to_string(path)?.trim().to_owned())
    } else {
        std::env::var("SING_BOX_SER_MINI_ADMIN_TOKEN").ok()
    };
    let (credentials, created) = sing_box_ser_mini::admin::load_or_create_credentials(
        &args.admin_credentials_file,
        &args.admin_username,
    )?;
    if created {
        println!("Generated WebUI credentials");
        println!("Admin username: {}", credentials.username);
        println!("Admin password: {}", credentials.password);
        println!(
            "Credentials written to {}",
            args.admin_credentials_file.display()
        );
    }
    sing_box_ser_mini::admin::run(
        args.config,
        args.admin_listen,
        token,
        args.admin_credentials_file,
        admin_token_file,
        worker_threads,
    )
    .await
}
