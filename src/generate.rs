#![allow(dead_code)]
#![allow(unused_variables)]
//! This module contains the logic for generating a spec from a database.
use crate::context::Context;
use crate::context::PostgresContext;
use crate::spec::DatabasePermission;
use log::{error, info};
use std::collections::HashMap;
use std::fmt;

use anyhow::Result;

#[derive(Debug)]
struct DatabaseRole {
    name: String,
    enabled: bool,
    superuser: bool,
    memberships: Vec<String>,
    owns: Vec<NamedObjects>,
    reads: Vec<NamedObjects>,
    writes: Vec<NamedObjects>,
}

pub struct NamedObjects {
    pub schema: String,
    pub objkind: String,
    pub unqualified_name: Option<String>,
}

impl fmt::Debug for NamedObjects {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = self.to_qualified_name();
        write!(f, "{}", name)
    }
}

impl NamedObjects {
    // TODO: Actually handle quoted identifiers.
    fn to_qualified_name(&self) -> String {
        match &self.unqualified_name {
            Some(name) => format!("{}.{}", self.schema, name),
            None => self.schema.clone(),
        }
    }
}

/// Generate a spec from the current state of a database.
///
pub fn generate_spec() -> Result<DatabasePermission> {
    let db_spec = DatabasePermission {
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

    let roles = add_attributes(&mut context);
    let roles = add_memberships(&mut context, roles);
    let roles = add_ownerships(&mut context, roles);

    println!("Roles: {:#?}", roles);
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
fn add_attributes(context: &mut impl Context) -> Vec<DatabaseRole> {
    let attributes = context.get_role_attributes();
    let mut roles = Vec::new();
    for attr in attributes {
        roles.push(DatabaseRole {
            name: attr.name,
            enabled: attr.canlogin,
            superuser: attr.superuser,
            memberships: Vec::new(),
            owns: Vec::new(),
            reads: Vec::new(),
            writes: Vec::new(),
        });
    }
    roles.sort_by_key(|a| a.name.clone());
    roles
}

fn add_memberships(context: &mut impl Context, mut roles: Vec<DatabaseRole>) -> Vec<DatabaseRole> {
    let memberships = context.get_all_memberships();
    roles.iter_mut().for_each(|role| {
        let mut memberships = memberships
            .iter()
            .filter(|&m| m.role == role.name)
            .map(|m| m.member_of.clone())
            .collect::<Vec<String>>();
        memberships.sort();
        role.memberships = memberships;
    });

    roles
}

fn add_ownerships(context: &mut impl Context, mut roles: Vec<DatabaseRole>) -> Vec<DatabaseRole> {
    let ownerships = context.get_ownerships();

    roles.iter_mut().for_each(|role| {
        let mut owns = ownerships
            .iter()
            .filter(|&o| o.owner == role.name)
            .map(|o| NamedObjects {
                schema: o.schema.clone(),
                objkind: o.objkind.clone(),
                unqualified_name: o.unqualified_name.clone(),
            })
            .collect::<Vec<NamedObjects>>();
        owns.sort_by_key(|a| a.to_qualified_name());
        role.owns = owns;
    });

    roles
}

fn add_privileges(context: &mut impl Context, roles: Vec<DatabaseRole>) -> Vec<DatabaseRole> {
    let privileges = context.get_privileges();
    roles
}
#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;

    #[test]
    fn test_add_attributes() {
        let context = &mut PostgresContext::new();
        let res = add_attributes(context);

        let jdoe = res.iter().find(|&r| r.name == "jdoe").unwrap();
        assert_eq!(jdoe.name, "jdoe");
        assert!(jdoe.enabled);
        assert!(!jdoe.superuser);
    }

    #[test]
    fn test_add_memberships() {
        let context = &mut PostgresContext::new();
        let roles = add_attributes(context);
        let members = add_memberships(context, roles);
        let jdoe = members.iter().find(|&r| r.name == "jdoe").unwrap();
        assert_eq!(jdoe.memberships, vec!["analyst", "postgres"]);
    }

    /*
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
    */
}
