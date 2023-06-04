use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::HashMap, fmt::Display};

use crate::context::{
    Attributes, DatabaseObject, DefaultPrivilege, ObjectKind, Privilege, RoleAttribute,
    RoleMembership,
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

    pub fn read_file(path: &str) -> Result<DatabaseSpec> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("Failed to open spec file: {}", path))?;
        serde_yaml::from_reader(file).map_err(|e| e.into())
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
            // TODO: Abstract this out. Maybe each ObjectKind has a
            // from_privilege(privilege) method? That way each object
            // owns its own Read/Write definitions
            ObjectKind::Schema => {
                if p.privs.contains(&crate::context::PrivilegeType::Write) {
                    role.privileges.schemas.write.push(p.object.fqn());
                }
                if p.privs.contains(&crate::context::PrivilegeType::Read) {
                    role.privileges.schemas.read.push(p.object.fqn());
                }
            }
            ObjectKind::Table => {
                if p.privs.contains(&crate::context::PrivilegeType::Write) {
                    role.privileges.tables.write.push(p.object.fqn());
                }
                if p.privs.contains(&crate::context::PrivilegeType::Read) {
                    role.privileges.tables.read.push(p.object.fqn());
                }
            }
            ObjectKind::Sequence => {
                if p.privs.contains(&crate::context::PrivilegeType::Write) {
                    role.privileges.sequences.write.push(p.object.fqn());
                }
                if p.privs.contains(&crate::context::PrivilegeType::Read) {
                    role.privileges.sequences.read.push(p.object.fqn());
                }
            }
            _ => panic!("Unknown object kind: {}", p.object.kind),
        });
    }

    pub fn add_defaults(&mut self, name: &str, defaults: &[DefaultPrivilege]) {
        let role = self.roles.get_mut(name).unwrap();
    }
}

fn deserialize_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    match s.as_ref() {
        "yes" => Ok(true),
        "no" => Ok(false),
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(serde::de::Error::custom("expected yes or no")),
    }
}

fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct Role {
    #[serde(deserialize_with = "crate::spec::deserialize_bool")]
    #[serde(default = "yes")]
    pub can_login: bool,
    #[serde(deserialize_with = "crate::spec::deserialize_bool")]
    #[serde(default)]
    pub is_superuser: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub member_of: Vec<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Ownership::is_empty")]
    pub owns: Ownership,
    #[serde(default)]
    #[serde(skip_serializing_if = "Privileges::is_empty")]
    pub privileges: Privileges,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct Ownership {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub tables: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub sequences: Vec<String>,
}

impl Default for Ownership {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for Ownership {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();
        if !self.schemas.is_empty() {
            s.push_str(&format!("SC: {}. ", self.schemas.join(", ")));
        }
        if !self.tables.is_empty() {
            s.push_str(&format!("TB: {}. ", self.tables.join(", ")));
        }
        if !self.sequences.is_empty() {
            s.push_str(&format!("SQ: {}. ", self.sequences.join(", ")));
        }
        write!(f, "{}", s)
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

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct Privileges {
    #[serde(skip_serializing_if = "SchemaPrivileges::is_empty")]
    #[serde(default)]
    pub schemas: SchemaPrivileges,
    #[serde(skip_serializing_if = "TablePrivileges::is_empty")]
    #[serde(default)]
    pub tables: TablePrivileges,
    #[serde(skip_serializing_if = "SequencePrivileges::is_empty")]
    #[serde(default)]
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

#[derive(Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub struct SchemaPrivileges {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub write: Vec<String>,
}

#[derive(Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub struct TablePrivileges {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub write: Vec<String>,
}

#[derive(Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub struct SequencePrivileges {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
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

impl IsEmpty for Ownership {
    fn is_empty(&self) -> bool {
        self.schemas.is_empty() && self.tables.is_empty() && self.sequences.is_empty()
    }
}

impl IsEmpty for Privileges {
    fn is_empty(&self) -> bool {
        self.schemas.is_empty() && self.tables.is_empty() && self.sequences.is_empty()
    }
}

impl DatabaseSpec {
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(&self)
    }
}
