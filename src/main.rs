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
        .block_on(run(args))
}

async fn run(args: Args) -> Result<()> {
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
    let token = if let Some(path) = args.admin_token_file {
        Some(std::fs::read_to_string(&path)?.trim().to_owned())
    } else {
        std::env::var("SING_BOX_SER_MINI_ADMIN_TOKEN").ok()
    };
    sing_box_ser_mini::admin::run(args.config, args.admin_listen, token).await
}
