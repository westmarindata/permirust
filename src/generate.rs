use crate::context::{Context, DatabaseObject, Privilege, RoleAttribute, RoleMembership};
use crate::spec::DatabaseSpec;
use log::{error, info};

use anyhow::Result;

pub fn generate_spec<T: Context>(mut context: T) -> Result<DatabaseSpec>
where
    <T as crate::context::Context>::RoleAttribute: RoleAttribute,
{
    let mut spec = DatabaseSpec::new();
    let roles = context.get_roles();

    info!("Roles: {:?}", roles);

    let attrs: Vec<T::RoleAttribute> = roles
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
        spec.add_role(&role, &attrs[i]);
        spec.add_memberships(&role, &memberships[i]);
        spec.add_ownerships(&role, &owners[i]);
        spec.add_privileges(&role, &privs[i]);
    }

    match spec.to_yaml() {
        Ok(yaml) => println!("{}", yaml),
        Err(e) => {
            error!("Error serializing spec: {}", e);
        }
    };

    Ok(spec)
}
