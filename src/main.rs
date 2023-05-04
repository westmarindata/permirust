use std::path::PathBuf;

use clap::{Parser, Subcommand};
use permirust::generate::generate_spec;
use postgres::{Client, NoTls};

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
    let cli = Cli::parse();

    if let Some(spec) = cli.spec.as_deref() {
        println!("Using config file: {}", spec.display());
    }

    match cli.debug {
        0 => println!("Debug mode is off"),
        1 => println!("Debug mode is kind of on"),
        2 | _ => println!("Debug mode is on"),
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
            let mut client = Client::connect(
                "host=localhost port=54321 user=postgres password=password",
                NoTls,
            )
            .unwrap();
            // TODO: Quit more gracefully when client fails
            println!("Generating...");
            generate_spec(&mut client).unwrap();
        }
        None => println!("No subcommand was used"),
    }
}
