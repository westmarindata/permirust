use permirust::grants::{PostgresPrivileges, TableGrant};

fn main() {
    let table_grant = TableGrant::new(
        PostgresPrivileges::Select,
        Some("users".into()),
        "public".into(),
        vec!["user".into()],
        false,
    );

    let sql: String = table_grant.unwrap().into();
    println!("{}", sql);
}
