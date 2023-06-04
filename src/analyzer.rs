use anyhow::Error;

use crate::{context::Context, spec::DatabaseSpec};

pub fn role_analyzer<T: Context>(
    sql: &mut Vec<String>,
    mut context: T,
    spec: &mut DatabaseSpec,
) -> Result<(), Error> {
    for (name, role) in spec.roles.iter() {
        println!("Processing role: {}", name);
        sql.extend(context.analyze_attributes(name, role));
        sql.extend(context.analyze_memberships(name, role));
    }
    Ok(())
}
