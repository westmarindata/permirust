use std::path::PathBuf;
use std::process::exit;

use clap::{Parser, Subcommand};
use log::error;
use log::info;
use permirust::adapters::fakedb::FakeDb;
use permirust::adapters::postgres::PostgresClient;
use permirust::analyzer::role_analyzer;
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
    Configure {},
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
            match cli.adapter.as_str() {
                "postgres" => {
                    let conn_str = "host=localhost port=54321 user=postgres password=password";
                    match PostgresClient::new(conn_str) {
                        Ok(db) => {
                            let spec = generate_spec(db).expect("Failed to generate spec");
                            info!("Successfully generated spec {}", spec);
                        }
                        Err(e) => {
                            error!("Failed to connect to database: {}", e);
                            error!("Please check your connection string and try again");
                            exit(1);
                        }
                    }
                }
                "fake" => {
                    let db = FakeDb {};
                    generate_spec(db).expect("Failed to generate spec");
                }
                _ => panic!("Unknown adapter"),
            };
        }

        Some(Commands::Configure {}) => {
            info!("Configuring...");
            let fpath = "./resources/spec.yml";
            let mut spec = match permirust::spec::DatabaseSpec::read_file(fpath) {
                Ok(spec) => {
                    info!("Successfully read spec");
                    spec
                }
                Err(e) => panic!("Failed to read spec file: {}", e),
            };

            let mut sql: Vec<String> = vec![];

            match spec.adapter.as_str() {
                "postgres" => {
                    let conn_str = "host=localhost port=54321 user=postgres password=password";

                    match PostgresClient::new(conn_str) {
                        Ok(db) => {
                            info!("Successfully connected to database");
                            role_analyzer(&mut sql, db, &mut spec)
                                .expect("Failed to analyze roles");
                            info!("Successfully analyzed roles");
                            println!("Sql: {:?}", sql)
                        }
                        Err(e) => {
                            error!("Failed to connect to database: {}", e);
                            error!("Please check your connection string and try again");
                            exit(1);
                        }
                    }
                }
                _ => panic!("Unknown adapter"),
            }
        }
        None => println!("No subcommand was used"),
    }
}
