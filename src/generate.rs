#![allow(dead_code)]
use core::fmt;

use anyhow::Result;
use chrono::{DateTime, Utc};
use postgres::Client;

pub fn generate_spec(client: &mut Client) -> Result<()> {
    // Get roles and role attributes
    let roles = get_role_attributes(client);
    let memberships = get_all_memberships(client);
    let obj_permissions = get_obj_permissions_by_role(client);

    roles.iter().for_each(|role| println!("{}", role));
    memberships
        .iter()
        .for_each(|membership| println!("{}", membership));
    obj_permissions
        .iter()
        .for_each(|obj_permission| println!("{}", obj_permission));

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

impl fmt::Display for PostgresRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<Role> {} enabled: {} superuser: {}",
            self.name, self.canlogin, self.superuser
        )
    }
}

#[derive(Debug)]
pub struct PostgresMembership {
    member: String,
    group: String,
}

impl fmt::Display for PostgresMembership {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<Membership> {}->{}", self.member, self.group)
    }
}

#[derive(Debug)]
pub struct GranteePrivileges {
    grantee: String,
    objkind: String,
    schema: String,
    unqualified_name: Option<String>,
    privilege_type: String,
}

impl fmt::Display for GranteePrivileges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<GranteePrivileges> {} {} {} {} {}",
            self.grantee,
            self.objkind,
            self.schema,
            self.unqualified_name.as_ref().unwrap_or(&"".to_string()),
            self.privilege_type
        )
    }
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

fn get_all_memberships(client: &mut Client) -> Vec<PostgresMembership> {
    let query = "SELECT
            auth_member.rolname AS member,
            auth_group.rolname AS group
        FROM pg_auth_members link_table
        JOIN pg_authid auth_member ON link_table.member = auth_member.oid
        JOIN pg_authid auth_group ON link_table.roleid = auth_group.oid
    ";

    let rows = client.query(query, &[]).unwrap();

    rows.iter()
        .map(|row| PostgresMembership {
            member: row.get(0),
            group: row.get(1),
        })
        .collect()
}

fn get_obj_permissions_by_role(client: &mut Client) -> Vec<GranteePrivileges> {
    let query = "WITH
    relkind_mapping (objkey, objkind) AS (
        VALUES ('r', 'tables'),
               ('v', 'tables'),
               ('m', 'tables'),
               ('f', 'tables'),
               ('S', 'sequences')
    ), tables_and_sequences AS (
        SELECT
            nsp.nspname AS schema,
            c.relname AS unqualified_name,
            map.objkind,
            (aclexplode(c.relacl)).grantee AS grantee_oid,
            t_owner.rolname AS owner,
            (aclexplode(c.relacl)).privilege_type
        FROM
            pg_class c
            JOIN pg_authid t_owner ON c.relowner = t_owner.OID
            JOIN pg_namespace nsp ON c.relnamespace = nsp.oid
            JOIN relkind_mapping map ON c.relkind = map.objkey
        WHERE
            nsp.nspname NOT LIKE 'pg\\_t%'
            AND c.relacl IS NOT NULL
    ), schemas AS (
        SELECT
             nsp.nspname AS schema,
             NULL::TEXT AS unqualified_name,
             'schemas'::TEXT AS objkind,
             (aclexplode(nsp.nspacl)).grantee AS grantee_oid,
             t_owner.rolname AS owner,
             (aclexplode(nsp.nspacl)).privilege_type
        FROM pg_namespace nsp
        JOIN pg_authid t_owner
            ON nsp.nspowner = t_owner.OID
    ), combined AS (
        SELECT * FROM tables_and_sequences
        UNION ALL
        SELECT * FROM schemas
    )
    SELECT
        t_grantee.rolname AS grantee,
        combined.objkind,
        combined.schema,
        combined.unqualified_name,
        combined.privilege_type
    FROM
        combined
        JOIN pg_authid t_grantee ON combined.grantee_oid = t_grantee.oid
        WHERE combined.owner != t_grantee.rolname
       ";

    let rows = client.query(query, &[]).unwrap();

    rows.iter()
        .map(|row| GranteePrivileges {
            grantee: row.get(0),
            objkind: row.get(1),
            schema: row.get(2),
            unqualified_name: row.get(3),
            privilege_type: row.get(4),
        })
        .collect()
}
