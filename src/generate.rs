#![allow(dead_code)]
use anyhow::Result;
use chrono::{DateTime, Utc};
use postgres::Client;

pub fn generate_spec(client: &mut Client) -> Result<()> {
    // Get roles and role attributes
    get_role_attributes(client);
    // Get memberships
    // Get ownerships
    // Get privileges
    // Return spec
    return Ok(());
}

#[derive(Debug)]
pub struct PostgresRole {
    name: String,
    bypassrls: bool,
    canlogin: bool,
    connlimit: i32,
    createdb: bool,
    createrole: bool,
    inherit: bool,
    replication: bool,
    superuser: bool,
    validuntil: Option<DateTime<Utc>>,
}

fn get_role_attributes(client: &mut Client) -> Vec<PostgresRole> {
    let query = "SELECT
                rolname,
                rolbypassrls,
                rolcanlogin,
                rolconnlimit,
                rolcreatedb,
                rolcreaterole,
                rolinherit,
                rolreplication,
                rolsuper,
                rolvaliduntil
            FROM pg_authid
            WHERE rolname != 'pg_signal_backend'
    ";
    let rows = client.query(query, &[]).unwrap();

    rows.iter()
        .map(|row| PostgresRole {
            name: row.get(0),
            bypassrls: row.get(1),
            canlogin: row.get(2),
            connlimit: row.get(3),
            createdb: row.get(4),
            createrole: row.get(5),
            inherit: row.get(6),
            replication: row.get(7),
            superuser: row.get(8),
            validuntil: row.get(9),
        })
        .collect()
}
