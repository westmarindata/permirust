use crate::context::{Context, RoleAttribute};
use postgres::NoTls;

pub struct PostgresClient {
    client: postgres::Client,
}

impl PostgresClient {
    pub fn new() -> Self {
        let client = postgres::Client::connect(
            "host=localhost port=54321 user=postgres password=password",
            NoTls,
        )
        .unwrap();
        PostgresClient { client }
    }
}

impl Default for PostgresClient {
    fn default() -> Self {
        Self::new()
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

    fn get_role_ownerships(&mut self, role: &str) -> Vec<crate::context::DatabaseObject> {
        self.client
            .query(crate::queries::Q_RAW_OBJECT_ATTRIBUTES, &[])
            .unwrap()
            .iter()
            .filter_map(|row| {
                if row.get::<_, String>(3) == role {
                    let kind = crate::context::ObjectKind::from(row.get::<_, String>(0).as_str());
                    Some(crate::context::DatabaseObject {
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

    fn get_role_permissions(&mut self, role: &str) -> Vec<crate::context::Privilege> {
        vec![]
    }
}
