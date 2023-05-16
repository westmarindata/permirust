use crate::context::{Context, DatabaseObject, FakeDb, Privilege, RoleAttribute, RoleMembership};
use crate::spec::{DatabasePermission, Ownership, Privileges};
use log::{error, info};

use anyhow::Result;

pub fn generate_spec() -> Result<DatabasePermission> {
    let mut db_spec = DatabasePermission {
        version: 1,
        adapter: "fakedb".to_string(),
        roles: Default::default(),
    };
    let mut context = match db_spec.adapter.as_str() {
        "fakedb" => {
            info!("Generating spec for fakedb.");
            let db = FakeDb::new();
            Box::new(db) as Box<dyn Context>
        }
        _ => {
            error!("Unsupported adapter: {}", db_spec.adapter);
            panic!();
        }
    };

    let roles = context.get_roles();
    info!("Roles: {:?}", roles);
    let attrs: Vec<RoleAttribute> = roles
        .iter()
        .map(|r| context.get_role_attributes(r))
        .collect();
    let memberships: Vec<RoleMembership> = roles
        .iter()
        .map(|r| context.get_role_memberships(r))
        .collect();
    let owners: Vec<Vec<DatabaseObject>> = roles
        .iter()
        .map(|r| context.get_role_ownerships(r))
        .collect();
    let privs: Vec<Vec<Privilege>> = roles
        .iter()
        .map(|r| context.get_role_permissions(r))
        .collect();

    for (i, role) in roles.iter().enumerate() {
        // TODO: Offload these to a separate function.
        // Create member, owns, and privileges from the above for each role
        let spec = crate::spec::Role {
            can_login: attrs[i].can_login,
            is_superuser: attrs[i].is_superuser,
            member_of: vec![],
            owns: Ownership::new(),
            privileges: Privileges::new(),
        };
        db_spec.insert_roles(role.0.clone(), spec);
    }

    match db_spec.to_yaml() {
        Ok(yaml) => println!("{}", yaml),
        Err(e) => {
            error!("Error serializing spec: {}", e);
        }
    };

    Ok(db_spec)
}
