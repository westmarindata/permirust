use std::path::PathBuf;

use clap::{Parser, Subcommand};
use log::info;
use permirust::adapters::fakedb::FakeDb;
use permirust::adapters::postgres::PostgresClient;
use permirust::generate::generate_spec;

#[derive(Parser)]
#[command(
    author = "Pedram Navid",
    version = "0.0.1",
    about = "A simple CLI for generating SQL grants"
)]
struct Cli {
    #[arg(short, long, value_name = "FILE")]
    spec: Option<PathBuf>,

    #[arg(short, long, default_value = "postgres")]
    adapter: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Generate {},
}

fn main() {
    env_logger::builder().format_timestamp(None).init();
    let cli = Cli::parse();

    if let Some(spec) = cli.spec.as_deref() {
        info!("Using config file: {}", spec.display());
    }

    match &cli.command {
        Some(Commands::Generate {}) => {
            info!("Generating...");
            let res = match cli.adapter.as_str() {
                "postgres" => {
                    let conn_str = "host=localhost port=54321 user=postgres password=password";
                    let db = PostgresClient::new(&conn_str);
                    generate_spec(db).expect("Failed to generate spec")
                }
                "fake" => {
                    let db = FakeDb {};
                    generate_spec(db).expect("Failed to generate spec")
                }
                _ => panic!("Unknown adapter"),
            };

            println!("Result: {}", res);
        }
        None => println!("No subcommand was used"),
    }
}
