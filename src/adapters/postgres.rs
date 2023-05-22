//! Postgres context implementation
use crate::context::{
    Context, DatabaseObject, ObjectKind, Privilege, PrivilegeType, RoleAttribute,
};
use itertools::Itertools;
use log::debug;
use postgres::NoTls;
use std::collections::HashMap;

pub struct PostgresClient {
    client: postgres::Client,
}

impl PostgresClient {
    /// Create a new PostgresClient. This uses the Postgres crate
    /// to connect, the connection string uses the format
    /// specied by the [Postgres::Config](https://docs.rs/postgres/latest/src/postgres/client.rs.html#34-42)
    ///
    /// Example
    ///
    /// ```
    /// use permirust::adapters::postgres::PostgresClient;
    /// let client = PostgresClient::new("host=localhost user=postgres password=password port=54321");
    /// ```
    pub fn new(connection_str: &str) -> Self {
        let client = postgres::Client::connect(connection_str, NoTls).unwrap();
        PostgresClient { client }
    }
}

pub struct PostgresRoleAttributes {
    enabled: bool,
    superuser: bool,
    createdb: bool,
}
impl RoleAttribute for PostgresRoleAttributes {
    fn get_attributes(&self) -> Vec<crate::context::Attributes> {
        let mut attrs = vec![];
        if self.enabled {
            attrs.push(crate::context::Attributes::Enabled);
        }
        if self.superuser {
            attrs.push(crate::context::Attributes::Superuser);
        }
        if self.createdb {
            attrs.push(crate::context::Attributes::CreateDb);
        }
        attrs
    }
}

impl Context for PostgresClient {
    type RoleAttribute = PostgresRoleAttributes;
    fn database_name(&self) -> &str {
        "postgres"
    }
    fn get_roles(&mut self) -> Vec<String> {
        let rows = &self
            .client
            .query(crate::queries::Q_GET_ROLE_ATTRIBUTES, &[])
            .unwrap();
        rows.iter().map(|row| row.get(0)).collect()
    }

    fn get_role_attributes(&mut self, role: &str) -> PostgresRoleAttributes {
        let rows = &self
            .client
            .query(crate::queries::Q_GET_ROLE_ATTRIBUTES, &[])
            .unwrap();

        let row = rows
            .iter()
            .find(|row| row.get::<_, String>(0) == role)
            .unwrap();

        PostgresRoleAttributes {
            enabled: row.get(2),
            superuser: row.get(8),
            createdb: row.get(4),
        }
    }

    fn get_role_memberships(&mut self, role: &str) -> crate::context::RoleMembership {
        let members = self
            .client
            .query(crate::queries::Q_ALL_MEMBERSHIPS, &[])
            .unwrap()
            .iter()
            .filter_map(|row| {
                if row.get::<_, String>(0) == role {
                    Some(row.get(1))
                } else {
                    None
                }
            })
            .collect();

        crate::context::RoleMembership {
            memberships: members,
        }
    }

    fn get_role_ownerships(&mut self, role: &str) -> Vec<DatabaseObject> {
        self.client
            .query(crate::queries::Q_RAW_OBJECT_ATTRIBUTES, &[])
            .unwrap()
            .iter()
            .filter_map(|row| {
                if row.get::<_, String>(3) == role {
                    let kind = ObjectKind::from(row.get::<_, String>(0).as_str());
                    Some(DatabaseObject {
                        kind,
                        schema: row.get(1),
                        unqualified_name: row.get(2),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_role_permissions(&mut self, _role: &str) -> Vec<Privilege> {
        let rows = self
            .client
            .query(crate::queries::Q_OBJ_PERMISSIONS_BY_ROLE, &[])
            .unwrap();

        // Each database object can have 1+ privileges
        let grouped_rows: HashMap<_, Vec<_>> = rows
            .iter()
            .filter(|row| row.get::<_, String>(0) == _role)
            .group_by(|row| {
                let kind = ObjectKind::from(row.get::<_, String>(1).as_str());
                let schema = row.get::<_, String>(2);
                let unqualified_name = row.get::<_, Option<String>>(3);
                DatabaseObject {
                    kind,
                    schema,
                    unqualified_name,
                }
            })
            .into_iter()
            .map(|(key, group)| (key, group.collect()))
            .collect();

        // For each group, create a privilege
        let mut permissions = vec![];
        for (object, grp) in grouped_rows {
            debug!("Processing object {:?}", object);
            let privs = grp
                .into_iter()
                .map(|row| match row.get::<_, String>(4).as_str() {
                    "SELECT" => PrivilegeType::Read,
                    "INSERT" => PrivilegeType::Write,
                    _ => PrivilegeType::Write,
                })
                .collect();
            debug!("Privs: {:?}", privs);
            permissions.push(Privilege { object, privs });
        }
        permissions
    }
}
