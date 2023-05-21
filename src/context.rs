#![allow(dead_code)]
use std::fmt::{self, Debug, Display};

pub trait Context {
    type RoleAttribute;
    fn database_name(&self) -> &str;
    fn get_roles(&mut self) -> Vec<String>;
    fn get_role_attributes(&mut self, role: &str) -> Self::RoleAttribute;
    fn get_role_memberships(&mut self, role: &str) -> RoleMembership;
    fn get_role_ownerships(&mut self, role: &str) -> Vec<DatabaseObject>;
    fn get_role_permissions(&mut self, role: &str) -> Vec<Privilege>;
}

pub trait RoleAttribute {
    fn get_attributes(&self) -> Vec<Attributes>;
    fn is_enabled(&self) -> bool {
        self.get_attributes().contains(&Attributes::Enabled)
    }
}

#[derive(Debug, PartialEq)]
pub enum Attributes {
    Enabled,
    Superuser,
    CreateDb,
    CreateRole,
    Inherit,
    Login,
    Replication,
    BypassRls,
    ConnectionLimit(i32),
}

#[derive(Debug, Clone)]
pub struct Role(pub String);

impl Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug)]
pub struct RoleMembership {
    pub memberships: Vec<String>,
}

impl RoleMembership {
    pub fn new(memberships: Vec<String>) -> Self {
        RoleMembership { memberships }
    }
}

pub enum ObjectKind {
    Schema,
    Table,
    View,
    Sequence,
}

impl From<&str> for ObjectKind {
    fn from(s: &str) -> Self {
        match s {
            "schemas" => ObjectKind::Schema,
            "tables" => ObjectKind::Table,
            "views" => ObjectKind::View,
            "sequences" => ObjectKind::Sequence,
            _ => panic!("Unknown object kind: {}", s),
        }
    }
}

impl fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObjectKind::Schema => f.write_str("schema"),
            ObjectKind::Table => f.write_str("table"),
            ObjectKind::View => f.write_str("view"),
            ObjectKind::Sequence => f.write_str("sequence"),
        }
    }
}

pub struct DatabaseObject {
    pub kind: ObjectKind,
    pub schema: String,
    pub unqualified_name: Option<String>,
}

impl fmt::Debug for DatabaseObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.unqualified_name {
            Some(name) => write!(f, "<{}>{}.{}", self.kind, self.schema, name),
            None => write!(f, "<{}> {}", self.kind, self.schema),
        }
    }
}
impl DatabaseObject {
    fn new(kind: ObjectKind, schema: String, unqualified_name: Option<String>) -> Self {
        DatabaseObject {
            kind,
            schema,
            unqualified_name,
        }
    }

    pub fn fqn(&self) -> String {
        match &self.unqualified_name {
            Some(name) => format!("{}.{}", self.schema, name),
            None => self.schema.clone(),
        }
    }
}

#[derive(Debug)]
pub enum PrivilegeType {
    Read,
    Write,
}

#[derive(Debug)]
pub struct Privilege {
    pub object: DatabaseObject,
    pub privs: Vec<PrivilegeType>,
}

pub mod fake_db {
    use super::*;
    pub struct FakeDb {}
    pub struct FakeDbAttribute {
        enabled: bool,
        superuser: bool,
    }

    impl Context for FakeDb {
        type RoleAttribute = FakeDbAttribute;

        fn database_name(&self) -> &str {
            "fake_db"
        }

        fn get_roles(&mut self) -> Vec<String> {
            vec!["alice".to_string(), "bob".to_string(), "carol".to_string()]
        }

        fn get_role_attributes(&mut self, _role: &str) -> Self::RoleAttribute {
            FakeDbAttribute {
                enabled: true,
                superuser: false,
            }
        }

        fn get_role_memberships(&mut self, _role: &str) -> RoleMembership {
            RoleMembership::new(vec!["analyst".to_string(), "developer".to_string()])
        }

        fn get_role_ownerships(&mut self, _role: &str) -> Vec<DatabaseObject> {
            vec![
                DatabaseObject::new(ObjectKind::Schema, "marketing".to_string(), None),
                DatabaseObject::new(ObjectKind::Schema, "finance".to_string(), None),
                DatabaseObject::new(
                    ObjectKind::Table,
                    "finance".to_string(),
                    Some("q2_results".to_string()),
                ),
            ]
        }

        fn get_role_permissions(&mut self, role: &str) -> Vec<Privilege> {
            use PrivilegeType::*;
            match role {
                "alice" => vec![
                    Privilege {
                        object: DatabaseObject::new(
                            ObjectKind::Schema,
                            "marketing".to_string(),
                            None,
                        ),
                        privs: vec![Read],
                    },
                    Privilege {
                        object: DatabaseObject::new(
                            ObjectKind::Schema,
                            "finance".to_string(),
                            None,
                        ),
                        privs: vec![Read, Write],
                    },
                    Privilege {
                        object: DatabaseObject::new(
                            ObjectKind::Table,
                            "finance".to_string(),
                            Some("q2_results".to_string()),
                        ),
                        privs: vec![Read],
                    },
                ],

                "bob" => vec![
                    Privilege {
                        object: DatabaseObject::new(
                            ObjectKind::Schema,
                            "marketing".to_string(),
                            None,
                        ),
                        privs: vec![Read],
                    },
                    Privilege {
                        object: DatabaseObject::new(
                            ObjectKind::Schema,
                            "finance".to_string(),
                            None,
                        ),
                        privs: vec![Read],
                    },
                    Privilege {
                        object: DatabaseObject::new(
                            ObjectKind::Table,
                            "finance".to_string(),
                            Some("q2_results".to_string()),
                        ),
                        privs: vec![Read, Write],
                    },
                ],
                "carol" => vec![
                    Privilege {
                        object: DatabaseObject::new(
                            ObjectKind::Schema,
                            "marketing".to_string(),
                            None,
                        ),
                        privs: vec![Read],
                    },
                    Privilege {
                        object: DatabaseObject::new(
                            ObjectKind::Schema,
                            "finance".to_string(),
                            None,
                        ),
                        privs: vec![Read],
                    },
                    Privilege {
                        object: DatabaseObject::new(
                            ObjectKind::Table,
                            "finance".to_string(),
                            Some("q2_results".to_string()),
                        ),
                        privs: vec![Read],
                    },
                ],
                _ => vec![],
            }
        }
    }

    impl RoleAttribute for FakeDbAttribute {
        fn get_attributes(&self) -> Vec<Attributes> {
            let mut attrs = vec![];
            if self.enabled {
                attrs.push(Attributes::Enabled);
            }
            if self.superuser {
                attrs.push(Attributes::Superuser);
            }
            attrs
        }
    }
}
