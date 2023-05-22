use std::path::PathBuf;

use clap::{Parser, Subcommand};
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

    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    adapter: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Generate {},
    Test {
        #[arg(short, long)]
        list: bool,
    },
}

fn main() {
    env_logger::builder().format_timestamp(None).init();
    let cli = Cli::parse();

    if let Some(spec) = cli.spec.as_deref() {
        println!("Using config file: {}", spec.display());
    }

    match cli.debug {
        0 => println!("Debug mode is off"),
        1 => println!("Debug mode is kind of on"),
        _ => println!("Debug mode is on"),
    }

    match &cli.command {
        Some(Commands::Test { list }) => {
            if *list {
                println!("Listing...");
            } else {
                println!("Testing...");
            }
        }
        Some(Commands::Generate {}) => {
            println!("Generating...");
        }

        None => {
            println!("No subcommand was used");
            println!("Generating...");
            if match cli.adapter.as_str() {
                "postgres" => {
                    let conn_str = "host=localhost port=54321 user=postgres password=password";
                    let db = PostgresClient::new(&conn_str);
                    let res = generate_spec(db);
                    assert!(res.is_ok());
                    true
                }
                "fake" => {
                    let db = FakeDb {};
                    let res = generate_spec(db);
                    assert!(res.is_ok());
                    true
                }
                _ => false,
            } {
                println!("Done!");
            } else {
                println!("Unknown adapter: {}", cli.adapter);
            }
        }
    }
}
