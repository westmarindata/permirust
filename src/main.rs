use permirust::{DatabaseGrant, GrantType, TableGrant};

fn main() {
    let table_grant = TableGrant::new(
        GrantType::Read,
        Some("users"),
        "public",
        vec!["user"],
        false,
    );

    let sql = table_grant.to_sql();
    println!("{}", sql);

    let table_grant = TableGrant::new(GrantType::Write, None, "public", vec!["user"], true);

    let sql = table_grant.to_sql();
    println!("{}", sql);

    let db_grant = DatabaseGrant::new(
        GrantType::Read,
        "my_database",
        vec!["user_1", "user_2"],
        false,
    );
    println!("{}", db_grant.to_sql());
}
