use std::fmt::Debug;

use clap::Parser;
use clap::Subcommand;
use trufflescan::default_ike_v2_scan;
use trufflescan::ikev2::key_exchange_data::generate_key_exchange_data_modp_groups;
use trufflescan::scan;
use trufflescan::scan_aggr;
use trufflescan::scan_v2;
//use trufflescan::test_version;

/// Bike-Scan Commands
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Scan IKE Version 1
    #[command(subcommand)]
    scan: Commands,
}
#[derive(Subcommand, Debug, Clone)]
enum Commands {
    v1 { ip: String },
}
#[tokio::main]
async fn main() {
    //generate_key_exchange_data_modp_groups().expect("can't create Data");
    //scan(ip).await.unwrap();
    //scan_v2().await.unwrap();
    //test_version().await.unwrap()
    //default_ike_v2_scan().await.unwrap()

    //scan_aggr().await.unwrap();

    let cli = Args::parse();
    match cli.scan {
        Commands::v1 { ip } => scan(ip).await.unwrap(),
    }
}
