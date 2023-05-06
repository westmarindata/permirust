#![allow(dead_code)]
use crate::context::Context;
use crate::context::PostgresContext;
use crate::context::PostgresRoleAttributes;
use core::fmt;
use log::debug;
use std::collections::HashMap;

use anyhow::Result;
use postgres::Client;

#[derive(Debug)]
pub struct ReadWritePermissions {
    read: Vec<String>,
    write: Vec<String>,
}

#[derive(Debug)]
pub struct RoleSpec {
    name: String,
    enabled: bool,
    superuser: bool,
    attributes: PostgresRoleAttributes,
    memberships: Vec<String>,
    owns: Vec<ObjectSpec>,
    privileges: HashMap<String, Vec<ReadWritePermissions>>,
}

impl RoleSpec {
    fn new(name: String) -> Self {
        RoleSpec {
            name: name.clone(),
            enabled: false,
            superuser: false,
            attributes: PostgresRoleAttributes::new(name.clone()),
            memberships: Vec::new(),
            owns: Vec::new(),
            privileges: HashMap::new(),
        }
    }
}

#[derive(Debug)]
pub struct ObjectSpec {
    objkind: String,
    name: String,
}

pub fn generate_spec(_client: &mut Client) -> Result<()> {
    return Ok(());
}

fn add_attributes(
    mut role_spec: HashMap<String, RoleSpec>,
    context: &mut impl Context,
) -> HashMap<String, RoleSpec> {
    let attributes = context.get_role_attributes();
    for attribute in attributes {
        let mut role = RoleSpec::new(attribute.name.clone());
        role.enabled = attribute.canlogin;
        role.superuser = attribute.superuser;
        role.attributes = attribute;
        debug!("Added attributes for role {}", &role.name);
        role_spec.insert(role.name.clone(), role);
    }
    role_spec
}

fn add_memberships(
    mut role_spec: HashMap<String, RoleSpec>,
    context: &mut impl Context,
) -> HashMap<String, RoleSpec> {
    let memberships = context.get_all_memberships();
    for membership in memberships {
        debug!("Adding membership for role {}", &membership);
        let role = role_spec.get_mut(&membership.member).unwrap();
        role.memberships.push(membership.group);
    }
    role_spec
}

#[derive(Debug, Clone)]
pub struct PostgresMembership {
    pub member: String,
    pub group: String,
}

impl PostgresMembership {
    fn new(member: String, group: String) -> Self {
        PostgresMembership { member, group }
    }
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
            "<GranteePrivileges> {} has {} ON {} {}.{}",
            self.grantee,
            self.privilege_type,
            self.objkind,
            self.schema,
            self.unqualified_name.as_ref().unwrap_or(&"".to_string()),
        )
    }
}

#[derive(Debug)]
pub struct DefaultAccessPrivileges {
    grantee: String,
    objkind: String,
    grantor: String,
    schema: String,
    privilege_type: String,
}

impl fmt::Display for DefaultAccessPrivileges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<DefaultAccessPrivileges> {} has {} ON FUTURE {} in {} FROM {}",
            self.grantee, self.privilege_type, self.objkind, self.schema, self.grantor
        )
    }
}

pub struct RawObjectAttribute {
    kind: String,
    schema: String,
    unqualified_name: Option<String>,
    owner: String,
    is_dependent: bool,
}

fn get_role_attributes(context: &mut PostgresContext) -> Vec<PostgresRoleAttributes> {
    context.get_role_attributes()
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

fn get_default_permissions(client: &mut Client) -> Vec<DefaultAccessPrivileges> {
    let query = " WITH relkind_mapping (objkey, objkind) AS (
        VALUES ('f', 'functions'),
               ('r', 'tables'),
               ('S', 'sequences'),
               ('T', 'types')
    ), subq AS (
        SELECT
            auth.rolname AS grantor,
            auth.oid AS grantor_oid,
            (aclexplode(def.defaclacl)).grantee AS grantee_oid,
            nsp.nspname,
            map.objkind,
            (aclexplode(def.defaclacl)).privilege_type
        FROM
            pg_default_acl def
            JOIN pg_authid auth
                    ON def.defaclrole = auth.oid
            JOIN pg_namespace nsp
                    ON def.defaclnamespace = nsp.oid
            JOIN relkind_mapping map
                    ON def.defaclobjtype = map.objkey
        WHERE
            def.defaclacl IS NOT NULL
    )
    SELECT
        t_grantee.rolname AS grantee,
        subq.objkind,
        subq.grantor,
        subq.nspname AS schema,
        subq.privilege_type
    FROM
        subq
        JOIN pg_authid t_grantee
            ON subq.grantee_oid = t_grantee.oid
    WHERE
        subq.grantor_oid != subq.grantee_oid
    ";

    let rows = client.query(query, &[]).unwrap();

    rows.iter()
        .map(|row| DefaultAccessPrivileges {
            grantee: row.get(0),
            objkind: row.get(1),
            grantor: row.get(2),
            schema: row.get(3),
            privilege_type: row.get(4),
        })
        .collect()
}

fn get_raw_object_attributes(client: &mut Client) -> Vec<RawObjectAttribute> {
    let query = "
    WITH relkind_mapping (objkey, kind) AS (
        VALUES ('r', 'tables'),
               ('v', 'tables'),
               ('m', 'tables'),
               ('f', 'tables'),
               ('S', 'sequences')
    ), tables_and_sequences AS (
        SELECT
            map.kind,
            nsp.nspname AS schema,
            c.relname AS unqualified_name,
            c.relowner AS owner_id,
            -- Auto-dependency means that a sequence is linked to a table. Ownership of
            -- that sequence automatically derives from the table's ownership
            COUNT(deps.refobjid) > 0 AS is_dependent
        FROM
            pg_class c
            JOIN relkind_mapping map
                ON c.relkind = map.objkey
            JOIN pg_namespace nsp
                ON c.relnamespace = nsp.OID
            LEFT JOIN pg_depend deps
                ON deps.objid = c.oid
                AND deps.classid = 'pg_class'::REGCLASS
                AND deps.refclassid = 'pg_class'::REGCLASS
                AND deps.deptype = 'a'
        GROUP BY
            map.kind,
            schema,
            unqualified_name,
            owner_id
    ), schemas AS (
        SELECT
            'schemas'::TEXT AS kind,
            nsp.nspname AS schema,
            NULL::TEXT AS unqualified_name,
            nsp.nspowner AS owner_id,
            FALSE AS is_dependent
        FROM pg_namespace nsp
    ), combined AS (
        SELECT *
        FROM tables_and_sequences
        UNION ALL
        SELECT *
        FROM schemas
    )
    SELECT
        co.kind,
        co.schema,
        co.unqualified_name,
        t_owner.rolname AS owner,
        co.is_dependent
    FROM combined AS co
    JOIN pg_authid t_owner
        ON co.owner_id = t_owner.OID
    WHERE
        co.schema NOT LIKE 'pg\\_t%'
    ;
    ";

    let rows = client.query(query, &[]).unwrap();

    rows.iter()
        .map(|row| RawObjectAttribute {
            kind: row.get(0),
            schema: row.get(1),
            unqualified_name: row.get(2),
            owner: row.get(3),
            is_dependent: row.get(4),
        })
        .collect()
}

// tests
#[cfg(test)]
mod tests {
    use postgres::NoTls;

    use super::*;
    use test_log::test;

    fn client() -> Client {
        Client::connect(
            "host=localhost port=54321 user=postgres password=password",
            NoTls,
        )
        .unwrap()
    }

    struct MockContext {
        roles: Vec<RoleSpec>,
        members: Vec<PostgresMembership>,
    }

    impl MockContext {
        fn new(roles: Vec<RoleSpec>, members: Vec<PostgresMembership>) -> Self {
            MockContext { roles, members }
        }
    }

    impl Context for MockContext {
        fn get_role_attributes(&mut self) -> Vec<PostgresRoleAttributes> {
            self.roles
                .iter()
                .map(|role| PostgresRoleAttributes::new(role.name.clone()))
                .collect()
        }

        fn get_all_memberships(&mut self) -> Vec<PostgresMembership> {
            self.members.clone()
        }
    }

    #[test]
    fn test_add_attributes() {
        let context = &mut PostgresContext::new();
        let spec = HashMap::new();
        let res = add_attributes(spec, context);
        let jdoe = res.get("jdoe").unwrap();

        assert!(jdoe.enabled);
        assert!(!jdoe.superuser);
    }

    #[test]
    fn test_add_memberships() {
        let context = &mut PostgresContext::new();
        let spec = HashMap::new();
        let spec = add_attributes(spec, context);
        let res = add_memberships(spec, context);
        let jdoe = res.get("jdoe").unwrap();
        assert!(jdoe.memberships[0].contains(&"analyst".to_string()));
    }

    #[test]
    fn test_add_memberships_mock() {
        let roles = vec![
            RoleSpec::new("foo".to_string()),
            RoleSpec::new("bar".to_string()),
            RoleSpec::new("baz".to_string()),
        ];

        let memberships = vec![
            PostgresMembership::new("foo".into(), "bar".into()),
            PostgresMembership::new("foo".into(), "baz".into()),
            PostgresMembership::new("bar".into(), "baz".into()),
        ];

        let spec = HashMap::new();
        let context = &mut MockContext::new(roles, memberships);
        let spec = add_attributes(spec, context);
        let spec = add_memberships(spec, context);
        assert!(spec.get("foo").unwrap().memberships[0].contains(&"bar".to_string()));
        assert!(spec.get("foo").unwrap().memberships[1].contains(&"baz".to_string()));
        assert!(spec.get("bar").unwrap().memberships[0].contains(&"baz".to_string()));
    }
}
