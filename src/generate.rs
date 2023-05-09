#![allow(dead_code)]
use crate::context::Context;
use crate::context::PostgresContext;
use crate::context::PostgresRoleAttributes;
use crate::spec::DatabasePermission;
use crate::spec::Ownership;
use crate::spec::Privileges;
use crate::spec::Role;
use log::{debug, error};
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

pub fn generate_spec(_client: &mut Client) -> Result<DatabasePermission> {
    let mut db_spec = DatabasePermission {
        version: 1,
        adapter: "postgres".to_string(),
        roles: HashMap::new(),
    };
    println!("Generated spec: {:?}", db_spec.roles);
    let context = &mut PostgresContext::new();
    db_spec.roles = add_attributes(db_spec.roles, context);
    db_spec.roles = add_memberships(db_spec.roles, context);
    db_spec.roles = add_ownerships(db_spec.roles, context);

    match db_spec.to_yaml() {
        Ok(yaml) => println!("{}", yaml),
        Err(e) => {
            error!("Error serializing spec: {}", e);
        }
    };

    return Ok(db_spec);
}

fn add_attributes(
    mut role_spec: HashMap<String, Role>,
    context: &mut impl Context,
) -> HashMap<String, Role> {
    let attributes = context.get_role_attributes();
    for attribute in attributes {
        role_spec.insert(
            attribute.name.clone(),
            Role {
                can_login: attribute.canlogin,
                is_superuser: attribute.superuser,
                member_of: vec![],
                owns: Ownership::new(),
                privileges: Privileges::new(),
            },
        );
        debug!(
            "Added attributes for role {:#?}",
            &role_spec.get(&attribute.name).unwrap()
        );
    }
    role_spec
}

fn add_memberships(
    mut role_spec: HashMap<String, Role>,
    context: &mut impl Context,
) -> HashMap<String, Role> {
    let memberships = context.get_all_memberships();
    for membership in memberships {
        debug!("Adding membership for role {}", &membership);
        let role = role_spec.get_mut(&membership.role).unwrap();
        role.member_of.push(membership.member_of);
    }
    role_spec
}

fn add_ownerships(
    mut role_spec: HashMap<String, Role>,
    context: &mut impl Context,
) -> HashMap<String, Role> {
    let ownerships = context.get_ownerships();
    for ownership in ownerships {
        debug!("Adding ownership for role {}", &ownership.owner);
        let role = role_spec.get_mut(&ownership.owner).unwrap();
        match ownership.objkind.as_str() {
            "schemas" => {
                role.owns
                    .schemas
                    .push(ownership.unqualified_name.unwrap_or(ownership.schema));
            }
            "tables" => {
                role.owns.tables.push(ownership.unqualified_name.unwrap());
            }
            "sequences" => {
                role.owns
                    .sequences
                    .push(ownership.unqualified_name.unwrap());
            }
            _ => {
                error!("Unknown object kind: {}", ownership.objkind);
            }
        }
    }
    role_spec
}

// tests
#[cfg(test)]
mod tests {
    use postgres::NoTls;

    use crate::context::PostgresMembership;

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

        fn get_obj_permissions_by_role(&mut self) -> Vec<crate::context::GranteePrivileges> {
            vec![]
        }

        fn get_default_permissions(&mut self) -> Vec<crate::context::DefaultAccessPrivileges> {
            vec![]
        }

        fn get_raw_object_attributes(&mut self) -> Vec<crate::context::RawObjectAttribute> {
            vec![]
        }

        fn get_ownerships(&mut self) -> Vec<crate::context::PostgresOwnership> {
            vec![]
        }
    }

    #[test]
    fn test_add_attributes() {
        let context = &mut PostgresContext::new();
        let spec = HashMap::new();
        let res = add_attributes(spec, context);
        let jdoe = res.get("jdoe").unwrap();

        assert!(jdoe.can_login);
        assert!(!jdoe.is_superuser);
    }

    #[test]
    fn test_add_memberships() {
        let context = &mut PostgresContext::new();
        let spec = HashMap::new();
        let spec = add_attributes(spec, context);
        let res = add_memberships(spec, context);
        let jdoe = res.get("jdoe").unwrap();
        assert!(jdoe.member_of[0].contains(&"analyst".to_string()));
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
        assert!(spec.get("foo").unwrap().member_of[0].contains(&"bar".to_string()));
        assert!(spec.get("foo").unwrap().member_of[1].contains(&"baz".to_string()));
        assert!(spec.get("bar").unwrap().member_of[0].contains(&"baz".to_string()));
    }

    #[test]
    fn test_add_ownerships() {
        let context = &mut PostgresContext::new();
        let spec = HashMap::new();
        let spec = add_attributes(spec, context);
        let res = add_ownerships(spec, context);
        let jdoe = res.get("jdoe").unwrap();
        assert_eq!(jdoe.owns.schemas.len(), 0);
        assert_eq!(jdoe.owns.tables.len(), 0);
        let analyst = res.get("analyst").unwrap();
        assert_eq!(analyst.owns.schemas, vec!["finance", "marketing"]);
        let postgres = res.get("postgres").unwrap();
        assert!(postgres.owns.sequences[0].contains(&"q2_revenue_seq".to_string()));
    }
}
