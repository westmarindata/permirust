use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::context::{
    Attributes, DatabaseObject, ObjectKind, Privilege, RoleAttribute, RoleMembership,
};

pub type RoleSpec = HashMap<String, Role>;

#[derive(Debug, Deserialize, Serialize)]
pub struct DatabaseSpec {
    pub version: u8,
    pub adapter: String,
    pub roles: RoleSpec,
}

impl DatabaseSpec {
    pub fn new(adapter: &str) -> DatabaseSpec {
        DatabaseSpec {
            version: 1,
            adapter: adapter.to_string(),
            roles: Default::default(),
        }
    }

    pub fn add_role(&mut self, name: &str, role: &impl RoleAttribute) {
        let role = Role {
            can_login: role.is_enabled(),
            is_superuser: role.get_attributes().contains(&Attributes::Superuser),
            member_of: vec![],
            owns: Ownership::new(),
            privileges: Privileges::new(),
        };
        self.roles.insert(name.to_string(), role);
    }

    pub fn add_memberships(&mut self, name: &str, memberships: &RoleMembership) {
        let role = self.roles.get_mut(name).unwrap();
        memberships.memberships.iter().for_each(|m| {
            role.member_of.push(m.to_string());
        });
    }

    pub fn add_ownerships(&mut self, name: &str, ownership: &[DatabaseObject]) {
        let role = self.roles.get_mut(name).unwrap();
        ownership.iter().for_each(|o| match o.kind {
            ObjectKind::Schema => {
                role.owns.schemas.push(o.fqn());
            }
            ObjectKind::Table => {
                role.owns.tables.push(o.fqn());
            }
            ObjectKind::Sequence => {
                role.owns.sequences.push(o.fqn());
            }
            _ => panic!("Unknown object kind: {}", o.kind),
        });
    }

    pub fn add_privileges(&mut self, name: &str, privileges: &[Privilege]) {
        let role = self.roles.get_mut(name).unwrap();
        privileges.iter().for_each(|p| match p.object.kind {
            ObjectKind::Schema => {
                role.privileges.schemas.read.push(p.object.fqn());
            }
            ObjectKind::Table => {
                role.privileges.tables.read.push(p.object.fqn());
            }
            ObjectKind::Sequence => {
                role.privileges.sequences.read.push(p.object.fqn());
            }
            _ => panic!("Unknown object kind: {}", p.object.kind),
        });
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
impl DatabaseSpec {
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(&self)
    }
}
