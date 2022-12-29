pub enum GrantType {
    Read,
    Write,
    All,
}

impl GrantType {
    fn to_postgres_table_permission(&self) -> &'static str {
        match self {
            GrantType::Read => "SELECT",
            GrantType::Write => "SELECT, INSERT, UPDATE, DELETE",
            GrantType::All => "ALL",
        }
    }

    fn to_postgres_database_permission(&self) -> &'static str {
        match self {
            GrantType::Read => "CONNECT",
            GrantType::Write => "CONNECT, TEMPORARY, CREATE",
            GrantType::All => "ALL",
        }
    }
}

pub struct TableGrant<'a> {
    grant_type: GrantType,
    table_name: Option<&'a str>,
    schema_name: &'a str,
    roles: Vec<&'a str>,
    with_grant_option: bool,
}

pub struct DatabaseGrant<'a> {
    grant_type: GrantType,
    database_name: &'a str,
    roles: Vec<&'a str>,
    with_grant_option: bool,
}

impl<'a> DatabaseGrant<'a> {
    pub fn new(
        grant_type: GrantType,
        database_name: &'a str,
        roles: Vec<&'a str>,
        with_grant_option: bool,
    ) -> Self {
        Self {
            grant_type,
            database_name,
            roles,
            with_grant_option,
        }
    }

    pub fn to_sql(&self) -> String {
        let mut sql = format!(
            "GRANT {} ON DATABASE {} TO {}",
            self.grant_type.to_postgres_database_permission(),
            self.database_name,
            self.roles.join(", ")
        );

        if self.with_grant_option {
            sql.push_str(" WITH GRANT OPTION");
        }

        sql
    }
}

impl<'a> TableGrant<'a> {
    pub fn new(
        grant_type: GrantType,
        table_name: Option<&'a str>,
        schema_name: &'a str,
        roles: Vec<&'a str>,
        with_grant_option: bool,
    ) -> Self {
        Self {
            grant_type,
            table_name,
            schema_name,
            roles,
            with_grant_option,
        }
    }
    pub fn to_sql(&self) -> String {
        let mut query = match self.table_name {
            Some(ref table_name) => format!(
                "GRANT {} ON TABLE {}.{} TO {}",
                self.grant_type.to_postgres_table_permission(),
                self.schema_name,
                table_name,
                self.roles.join(", "),
            ),
            None => format!(
                "GRANT {} ON ALL TABLES IN SCHEMA {} TO {}",
                self.grant_type.to_postgres_table_permission(),
                self.schema_name,
                self.roles.join(", "),
            ),
        };

        if self.with_grant_option {
            query.push_str(" WITH GRANT OPTION");
        }

        query
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_grant() {
        let grant = TableGrant::new(
            GrantType::Read,
            Some("users"),
            "public",
            vec!["user"],
            false,
        );

        assert_eq!(grant.to_sql(), "GRANT SELECT ON TABLE public.users TO user");
    }

    #[test]
    fn test_table_grant_all() {
        let grant = TableGrant::new(GrantType::Read, None, "public", vec!["user"], false);

        assert_eq!(
            grant.to_sql(),
            "GRANT SELECT ON ALL TABLES IN SCHEMA public TO user"
        );
    }

    #[test]
    fn test_table_grant_with_grant_option() {
        let grant = TableGrant::new(
            GrantType::Read,
            Some("users"),
            "public",
            vec!["user_1", "user_2"],
            true,
        );

        assert_eq!(
            grant.to_sql(),
            "GRANT SELECT ON TABLE public.users TO user_1, user_2 WITH GRANT OPTION"
        );
    }

    #[test]
    fn test_database_grant() {
        let grant = DatabaseGrant::new(
            GrantType::Read,
            "my_database",
            vec!["user_1", "user_2"],
            false,
        );

        assert_eq!(
            grant.to_sql(),
            "GRANT CONNECT ON DATABASE my_database TO user_1, user_2"
        );
    }

    #[test]
    fn test_database_grant_with_grant_option() {
        let grant = DatabaseGrant::new(
            GrantType::Write,
            "my_database",
            vec!["user_1", "user_2"],
            true,
        );

        assert_eq!(
            grant.to_sql(),
            "GRANT CONNECT, TEMPORARY, CREATE ON DATABASE my_database TO user_1, user_2 WITH GRANT OPTION"
        );
    }

    #[test]
    fn test_database_grant_all() {
        let grant = DatabaseGrant::new(GrantType::All, "my_database", vec!["user"], false);

        assert_eq!(grant.to_sql(), "GRANT ALL ON DATABASE my_database TO user");
    }
}
