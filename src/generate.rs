//! This module contains the logic for generating a spec from a database.
use crate::context::Context;
use crate::context::PostgresContext;
use crate::spec::DatabasePermission;
use crate::spec::Ownership;
use crate::spec::Privileges;
use crate::spec::Role;
use crate::spec::RoleSpec;
use log::{debug, error, info};
use std::collections::HashMap;

use anyhow::Result;

/// Generate a spec from the current state of a database.
///
pub fn generate_spec() -> Result<DatabasePermission> {
    let mut db_spec = DatabasePermission {
        version: 1,
        adapter: "postgres".to_string(),
        roles: HashMap::new(),
    };
    let mut context = match db_spec.adapter.as_str() {
        "postgres" => {
            info!("Generating spec for postgres.");
            PostgresContext::new()
        }
        _ => {
            error!("Unsupported adapter: {}", db_spec.adapter);
            panic!();
        }
    };
    db_spec.roles = add_attributes(db_spec.roles, &mut context);
    db_spec.roles = add_memberships(db_spec.roles, &mut context);
    db_spec.roles = add_ownerships(db_spec.roles, &mut context);
    db_spec.roles = add_privileges(db_spec.roles, &mut context);

    match db_spec.to_yaml() {
        Ok(yaml) => println!("{}", yaml),
        Err(e) => {
            error!("Error serializing spec: {}", e);
        }
    };

    Ok(db_spec)
}

/// Add role attributes to the spec. These are the attributes that are
/// defined on the role itself, such as whether it can login or is a
/// superuser.
fn add_attributes(mut role_spec: RoleSpec, context: &mut impl Context) -> RoleSpec {
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

/// Add role memberships to the spec. Every user/role can be a member of
/// another role
fn add_memberships(mut role_spec: RoleSpec, context: &mut impl Context) -> RoleSpec {
    let memberships = context.get_all_memberships();
    for membership in memberships {
        debug!("Adding membership for role {}", &membership);
        let role = role_spec.get_mut(&membership.role).unwrap();
        role.member_of.push(membership.member_of);
    }
    role_spec
}

/// Add role ownerships to the spec. Every user/role can own schemas,
/// tables, and sequences.
fn add_ownerships(mut role_spec: RoleSpec, context: &mut impl Context) -> RoleSpec {
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

fn add_privileges(mut role_spec: RoleSpec, context: &mut impl Context) -> RoleSpec {
    for role in role_spec.keys() {
        let privileges = context.get_privileges(role);
        debug!("Got privileges for role {}: {:#?}", role, privileges);
    }
    role_spec
}

// tests
#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;

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
