use crate::context::Context;
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

pub struct PostgresRoleAttributes {
    pub can_login: bool,
    pub is_superuser: bool,
}

impl Context for PostgresClient {
    type RoleAttribute = PostgresRoleAttributes;
    fn get_roles(&mut self) -> Vec<crate::context::Role> {
        panic!();
    }

    fn get_role_attributes(&mut self, role: &crate::context::Role) -> PostgresRoleAttributes {
        panic!();
    }

    fn get_role_memberships(
        &mut self,
        role: &crate::context::Role,
    ) -> crate::context::RoleMembership {
        panic!();
    }

    fn get_role_ownerships(
        &mut self,
        role: &crate::context::Role,
    ) -> Vec<crate::context::DatabaseObject> {
        panic!();
    }

    fn get_role_permissions(
        &mut self,
        role: &crate::context::Role,
    ) -> Vec<crate::context::Privilege> {
        panic!();
    }
}
