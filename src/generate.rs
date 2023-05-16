use crate::context::{Context, DatabaseObject, FakeDb, Privilege, RoleAttribute, RoleMembership};
use crate::spec::DatabaseSpec;
use log::{error, info};

use anyhow::Result;

pub fn generate_spec() -> Result<DatabaseSpec> {
    let mut spec = DatabaseSpec {
        version: 1,
        adapter: "fakedb".to_string(),
        roles: Default::default(),
    };
    let mut context = match spec.adapter.as_str() {
        "fakedb" => {
            info!("Generating spec for fakedb.");
            let db = FakeDb::new();
            Box::new(db) as Box<dyn Context>
        }
        _ => {
            error!("Unsupported adapter: {}", spec.adapter);
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
        // Create member, owns, and privileges from the above for each role
        //
        spec.add_role(&role.0, &attrs[i]);
        spec.add_memberships(&role.0, &memberships[i]);
    }

    match spec.to_yaml() {
        Ok(yaml) => println!("{}", yaml),
        Err(e) => {
            error!("Error serializing spec: {}", e);
        }
    };

    Ok(spec)
}
