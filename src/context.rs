#![allow(dead_code)]
use chrono::{DateTime, Utc};
use core::fmt;
use postgres::NoTls;

use crate::generate::PostgresMembership;
#[derive(Debug, Clone)]
pub struct PostgresRoleAttributes {
    pub name: String,
    bypassrls: bool,
    pub canlogin: bool,
    connlimit: i32,
    createdb: bool,
    createrole: bool,
    inherit: bool,
    replication: bool,
    pub superuser: bool,
    validuntil: Option<DateTime<Utc>>,
}

impl PostgresRoleAttributes {
    pub(crate) fn new(name: String) -> Self {
        PostgresRoleAttributes {
            name,
            bypassrls: false,
            canlogin: false,
            connlimit: 0,
            createdb: false,
            createrole: false,
            inherit: false,
            replication: false,
            superuser: false,
            validuntil: None,
        }
    }
}

pub trait Context {
    fn get_role_attributes(&mut self) -> Vec<PostgresRoleAttributes>;
    fn get_all_memberships(&mut self) -> Vec<PostgresMembership>;
}

pub struct PostgresContext {
    client: postgres::Client,
}

impl fmt::Display for PostgresRoleAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<Role> {} enabled: {} superuser: {}",
            self.name, self.canlogin, self.superuser
        )
    }
}

impl PostgresContext {
    pub fn new() -> Self {
        let client = postgres::Client::connect(
            "host=localhost port=54321 user=postgres password=password",
            NoTls,
        )
        .unwrap();
        PostgresContext { client }
    }
}

impl Context for PostgresContext {
    fn get_role_attributes(&mut self) -> Vec<PostgresRoleAttributes> {
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
        let rows = self.client.query(query, &[]).unwrap();

        rows.iter()
            .map(|row| PostgresRoleAttributes {
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

    fn get_all_memberships(&mut self) -> Vec<PostgresMembership> {
        let query = "SELECT
            auth_member.rolname AS member,
            auth_group.rolname AS group
        FROM pg_auth_members link_table
        JOIN pg_authid auth_member ON link_table.member = auth_member.oid
        JOIN pg_authid auth_group ON link_table.roleid = auth_group.oid
    ";

        let rows = &self.client.query(query, &[]).unwrap();

        rows.iter()
            .map(|row| PostgresMembership {
                member: row.get(0),
                group: row.get(1),
            })
            .collect()
    }
}
