use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type RoleSpec = HashMap<String, Role>;

#[derive(Debug, Deserialize, Serialize)]
pub struct DatabasePermission {
    pub version: u32,
    pub adapter: String,
    pub roles: HashMap<String, Role>,
}

impl DatabasePermission {
    pub fn insert_roles(&mut self, name: String, role: Role) {
        self.roles.insert(name, role);
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Role {
    pub can_login: bool,
    pub is_superuser: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub member_of: Vec<String>,
    pub owns: Ownership,
    pub privileges: Privileges,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Ownership {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tables: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sequences: Vec<String>,
}

impl Default for Ownership {
    fn default() -> Self {
        Self::new()
    }
}
impl Ownership {
    pub fn new() -> Self {
        Ownership {
            schemas: vec![],
            tables: vec![],
            sequences: vec![],
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Privileges {
    #[serde(skip_serializing_if = "SchemaPrivileges::is_empty")]
    pub schemas: SchemaPrivileges,
    #[serde(skip_serializing_if = "TablePrivileges::is_empty")]
    pub tables: TablePrivileges,
    #[serde(skip_serializing_if = "SequencePrivileges::is_empty")]
    pub sequences: SequencePrivileges,
}

impl Default for Privileges {
    fn default() -> Self {
        Self::new()
    }
}

impl Privileges {
    pub fn new() -> Self {
        Privileges {
            schemas: SchemaPrivileges {
                read: vec![],
                write: vec![],
            },
            tables: TablePrivileges {
                read: vec![],
                write: vec![],
            },
            sequences: SequencePrivileges {
                read: vec![],
                write: vec![],
            },
        }
    }
}

trait ObjectPrivileges {
    fn read(&self) -> &Vec<String>;
    fn write(&self) -> &Vec<String>;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SchemaPrivileges {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub read: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub write: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TablePrivileges {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub read: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub write: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SequencePrivileges {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub read: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub write: Vec<String>,
}

pub trait IsEmpty {
    fn is_empty(&self) -> bool;
}

impl IsEmpty for SchemaPrivileges {
    fn is_empty(&self) -> bool {
        self.read.is_empty() && self.write.is_empty()
    }
}

impl IsEmpty for TablePrivileges {
    fn is_empty(&self) -> bool {
        self.read.is_empty() && self.write.is_empty()
    }
}

impl IsEmpty for SequencePrivileges {
    fn is_empty(&self) -> bool {
        self.read.is_empty() && self.write.is_empty()
    }
}
impl DatabasePermission {
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(&self)
    }
}
