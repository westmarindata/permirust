#![allow(dead_code)]
use std::{
    collections::HashMap,
    fmt::{self, Debug},
};

pub trait Context {
    fn get_roles(&mut self) -> Vec<Role>;
    fn get_role_attributes(&mut self, role: &Role) -> RoleAttribute;
    fn get_role_memberships(&mut self, role: &Role) -> RoleMembership;
    fn get_role_ownerships(&mut self, role: &Role) -> Vec<DatabaseObject>;
    fn get_role_permissions(&mut self, role: &Role) -> Vec<Privilege>;
}

#[derive(Debug, Clone)]
pub struct Role(pub String);

// TODO: Make this generic
#[derive(Debug)]
pub struct RoleAttribute {
    pub can_login: bool,
    pub is_superuser: bool,
}

#[derive(Debug)]
pub struct RoleMembership(Vec<String>);

enum ObjectKind {
    Schema,
    Table,
    View,
    Sequence,
}

impl From<&str> for ObjectKind {
    fn from(s: &str) -> Self {
        match s {
            "schema" => ObjectKind::Schema,
            "table" => ObjectKind::Table,
            "view" => ObjectKind::View,
            "sequence" => ObjectKind::Sequence,
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
    kind: ObjectKind,
    schema: String,
    unqualified_name: Option<String>,
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

    fn _fqn(&self) -> String {
        match &self.unqualified_name {
            Some(name) => format!("{}.{}", self.schema, name),
            None => self.schema.clone(),
        }
    }
}

#[derive(Debug)]
enum PrivilegeType {
    Read,
    Write,
}

#[derive(Debug)]
pub struct Privilege {
    object: DatabaseObject,
    privs: Vec<PrivilegeType>,
}

pub struct FakeDb;

impl FakeDb {
    pub fn new() -> Self {
        FakeDb
    }
}

impl Context for FakeDb {
    fn get_roles(&mut self) -> Vec<Role> {
        vec![
            Role("alice".to_string()),
            Role("bob".to_string()),
            Role("carol".to_string()),
        ]
    }

    fn get_role_attributes(&mut self, _role: &Role) -> RoleAttribute {
        RoleAttribute {
            can_login: true,
            is_superuser: false,
        }
    }

    fn get_role_memberships(&mut self, _role: &Role) -> RoleMembership {
        RoleMembership(vec!["analyst".to_string(), "developer".to_string()])
    }

    fn get_role_ownerships(&mut self, _role: &Role) -> Vec<DatabaseObject> {
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

    fn get_role_permissions(&mut self, role: &Role) -> Vec<Privilege> {
        use PrivilegeType::*;
        match role.0.as_str() {
            "alice" => vec![
                Privilege {
                    object: DatabaseObject::new(ObjectKind::Schema, "marketing".to_string(), None),
                    privs: vec![Read],
                },
                Privilege {
                    object: DatabaseObject::new(ObjectKind::Schema, "finance".to_string(), None),
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
                    object: DatabaseObject::new(ObjectKind::Schema, "marketing".to_string(), None),
                    privs: vec![Read],
                },
                Privilege {
                    object: DatabaseObject::new(ObjectKind::Schema, "finance".to_string(), None),
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
                    object: DatabaseObject::new(ObjectKind::Schema, "marketing".to_string(), None),
                    privs: vec![Read],
                },
                Privilege {
                    object: DatabaseObject::new(ObjectKind::Schema, "finance".to_string(), None),
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
