use chrono::{DateTime, Utc};
use core::fmt;
use postgres::NoTls;

#[derive(Clone)]
pub struct PostgresRoleAttributes {
    pub name: String,
    bypassrls: bool,
    pub canlogin: bool,
    connlimit: i32,
    createdb: bool,
    createrole: bool,
    inherit: bool,
    replication: bool,
    pub superuser: bool,
    validuntil: Option<DateTime<Utc>>,
}

impl fmt::Debug for PostgresRoleAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<{}> enabled: {} superuser: {}",
            self.name, self.canlogin, self.superuser
        )
    }
}
impl PostgresRoleAttributes {
    pub(crate) fn new(name: String) -> Self {
        PostgresRoleAttributes {
            name,
            bypassrls: false,
            canlogin: false,
            connlimit: 0,
            createdb: false,
            createrole: false,
            inherit: false,
            replication: false,
            superuser: false,
            validuntil: None,
        }
    }
}
