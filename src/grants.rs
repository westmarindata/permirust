use std::{borrow::Cow, fmt, str::FromStr};

type Sql = String;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PostgresPrivileges {
    // TODO: Break apart grants into types by object
    AlterSystem,
    Connect,
    Create,
    Delete,
    Execute,
    Insert,
    References,
    Select,
    Set,
    Temporary,
    Trigger,
    Truncate,
    Update,
    Usage,
    All,
}

impl fmt::Display for PostgresPrivileges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PostgresPrivileges::AlterSystem => write!(f, "ALTER SYSTEM"),
            PostgresPrivileges::Connect => write!(f, "CONNECT"),
            PostgresPrivileges::Create => write!(f, "CREATE"),
            PostgresPrivileges::Delete => write!(f, "DELETE"),
            PostgresPrivileges::Execute => write!(f, "EXECUTE"),
            PostgresPrivileges::Insert => write!(f, "INSERT"),
            PostgresPrivileges::References => write!(f, "REFERENCES"),
            PostgresPrivileges::Select => write!(f, "SELECT"),
            PostgresPrivileges::Set => write!(f, "SET"),
            PostgresPrivileges::Temporary => write!(f, "TEMPORARY"),
            PostgresPrivileges::Trigger => write!(f, "TRIGGER"),
            PostgresPrivileges::Truncate => write!(f, "TRUNCATE"),
            PostgresPrivileges::Update => write!(f, "UPDATE"),
            PostgresPrivileges::Usage => write!(f, "USAGE"),
            PostgresPrivileges::All => write!(f, "ALL"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PostgresObjectType {
    Database,
    ForeignDataWrapper,
    ForeignServer,
    Function,
    Procedure,
    Role,
    Schema,
    Sequence,
    Table,
    Type,
    View,
}

impl FromStr for PostgresObjectType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "DATABASE" => Ok(PostgresObjectType::Database),
            "FOREIGN DATA WRAPPER" => Ok(PostgresObjectType::ForeignDataWrapper),
            "FOREIGN SERVER" => Ok(PostgresObjectType::ForeignServer),
            "FUNCTION" => Ok(PostgresObjectType::Function),
            "PROCEDURE" => Ok(PostgresObjectType::Procedure),
            "ROLE" => Ok(PostgresObjectType::Role),
            "SCHEMA" => Ok(PostgresObjectType::Schema),
            "SEQUENCE" => Ok(PostgresObjectType::Sequence),
            "TABLE" => Ok(PostgresObjectType::Table),
            "TYPE" => Ok(PostgresObjectType::Type),
            "VIEW" => Ok(PostgresObjectType::View),
            _ => Err(format!("Unknown object type: {}", s)),
        }
    }
}

impl fmt::Display for PostgresObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PostgresObjectType::Database => write!(f, "DATABASE"),
            PostgresObjectType::ForeignDataWrapper => write!(f, "FOREIGN DATA WRAPPER"),
            PostgresObjectType::ForeignServer => write!(f, "FOREIGN SERVER"),
            PostgresObjectType::Function => write!(f, "FUNCTION"),
            PostgresObjectType::Procedure => write!(f, "PROCEDURE"),
            PostgresObjectType::Role => write!(f, "ROLE"),
            PostgresObjectType::Schema => write!(f, "SCHEMA"),
            PostgresObjectType::Sequence => write!(f, "SEQUENCE"),
            PostgresObjectType::Table => write!(f, "TABLE"),
            PostgresObjectType::Type => write!(f, "TYPE"),
            PostgresObjectType::View => write!(f, "VIEW"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DatabaseGrant {
    grant_type: PostgresPrivileges,
    database_name: String,
    roles: Vec<String>,
    with_grant_option: bool,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TableGrant {
    grant_type: PostgresPrivileges,
    table_name: Option<String>,
    schema_name: String,
    roles: Vec<String>,
    with_grant_option: bool,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SchemaGrant {
    grant_type: PostgresPrivileges,
    schema_name: String,
    roles: Vec<String>,
    with_grant_option: bool,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RoleGrant {
    role_name: String,
    roles: Vec<String>,
    with_admin_option: bool,
}

impl DatabaseGrant {
    const VALID_PERMISSIONS: &'static [PostgresPrivileges] = &[
        PostgresPrivileges::Connect,
        PostgresPrivileges::Create,
        PostgresPrivileges::Temporary,
        PostgresPrivileges::All,
    ];
    pub fn new(
        grant_type: PostgresPrivileges,
        database_name: String,
        roles: Vec<String>,
        with_grant_option: bool,
    ) -> Self {
        if !Self::VALID_PERMISSIONS.contains(&grant_type) {
            panic!("Invalid permission for database grant: {}", grant_type);
        }
        Self {
            grant_type,
            database_name,
            roles,
            with_grant_option,
        }
    }
}

impl TableGrant {
    const VALID_PERMISSIONS: &'static [PostgresPrivileges] = &[
        PostgresPrivileges::Select,
        PostgresPrivileges::Insert,
        PostgresPrivileges::Update,
        PostgresPrivileges::Delete,
        PostgresPrivileges::Truncate,
        PostgresPrivileges::References,
        PostgresPrivileges::Trigger,
        PostgresPrivileges::All,
    ];
    pub fn new(
        grant_type: PostgresPrivileges,
        table_name: Option<Cow<'static, str>>,
        schema_name: Cow<'static, str>,
        roles: Vec<Cow<'static, str>>,
        with_grant_option: bool,
    ) -> Self {
        {
            if !Self::VALID_PERMISSIONS.contains(&grant_type) {
                panic!("Invalid permission for table grant: {}", grant_type);
            }
            Self {
                grant_type,
                table_name: table_name.map(|t| t.into_owned()),
                schema_name: schema_name.into_owned(),
                roles: roles.into_iter().map(|r| r.into_owned()).collect(),
                with_grant_option,
            }
        }
    }
}

impl From<DatabaseGrant> for Sql {
    fn from(grant: DatabaseGrant) -> Self {
        let mut sql = format!(
            "GRANT {} ON DATABASE {} TO {}",
            grant.grant_type,
            grant.database_name,
            grant.roles.join(", ")
        );

        if grant.with_grant_option {
            sql.push_str(" WITH GRANT OPTION");
        };

        sql
    }
}

impl From<TableGrant> for Sql {
    fn from(grant: TableGrant) -> Self {
        let mut sql = match grant.table_name {
            Some(table) => format!(
                "GRANT {} ON TABLE {}.{} TO {}",
                grant.grant_type,
                grant.schema_name,
                table,
                grant.roles.join(", ")
            ),
            None => format!(
                "GRANT {} ON ALL TABLES IN SCHEMA {} TO {}",
                grant.grant_type,
                grant.schema_name,
                grant.roles.join(", ")
            ),
        };

        if grant.with_grant_option {
            sql.push_str(" WITH GRANT OPTION");
        };

        sql
    }
}

impl From<SchemaGrant> for Sql {
    fn from(grant: SchemaGrant) -> Self {
        let mut sql = format!(
            "GRANT {} ON SCHEMA {} TO {}",
            grant.grant_type,
            grant.schema_name,
            grant.roles.join(", ")
        );

        if grant.with_grant_option {
            sql.push_str(" WITH GRANT OPTION");
        };

        sql
    }
}

impl From<RoleGrant> for Sql {
    fn from(grant: RoleGrant) -> Self {
        let mut sql = format!(
            "GRANT {} TO ROLE {}",
            grant.role_name,
            grant.roles.join(", ")
        );

        if grant.with_admin_option {
            sql.push_str(" WITH ADMIN OPTION");
        };

        sql
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_grant() {
        let grant = TableGrant::new(
            PostgresPrivileges::Select,
            Some("users".into()),
            "public".into(),
            vec!["user".into()],
            false,
        );

        assert_eq!(
            Sql::from(grant),
            "GRANT SELECT ON TABLE public.users TO user"
        );
    }

    #[test]
    fn test_table_grant_select_to_all() {
        let grant = TableGrant::new(
            PostgresPrivileges::Select,
            None,
            "public".into(),
            vec!["user".into()],
            false,
        );

        assert_eq!(
            Sql::from(grant),
            "GRANT SELECT ON ALL TABLES IN SCHEMA public TO user"
        );
    }

    #[test]
    fn test_table_grant_with_grant_option() {
        let grant = TableGrant::new(
            PostgresPrivileges::Select,
            Some("users".into()),
            "public".into(),
            vec!["user_1".into(), "user_2".into()],
            true,
        );

        assert_eq!(
            Sql::from(grant),
            "GRANT SELECT ON TABLE public.users TO user_1, user_2 WITH GRANT OPTION"
        );
    }

    #[test]
    fn test_database_grant() {
        let grant = DatabaseGrant::new(
            PostgresPrivileges::Connect,
            "my_database".into(),
            vec!["user_1".into(), "user_2".into()],
            false,
        );

        assert_eq!(
            Sql::from(grant),
            "GRANT CONNECT ON DATABASE my_database TO user_1, user_2"
        );
    }

    #[test]
    fn test_database_grant_with_grant_option() {
        let grant = DatabaseGrant::new(
            PostgresPrivileges::Connect,
            "my_database".into(),
            vec!["user_1".into(), "user_2".into()],
            true,
        );

        assert_eq!(
            Sql::from(grant),
            "GRANT CONNECT ON DATABASE my_database TO user_1, user_2 WITH GRANT OPTION"
        );
    }

    #[test]
    fn test_database_grant_all() {
        let grant = DatabaseGrant::new(
            PostgresPrivileges::All,
            "my_database".into(),
            vec!["user".into()],
            false,
        );

        assert_eq!(
            Sql::from(grant),
            "GRANT ALL ON DATABASE my_database TO user"
        );
    }
}
