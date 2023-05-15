#![allow(dead_code)]
use chrono::{DateTime, Utc};
use core::fmt;
use std::{collections::HashMap, str::FromStr};

enum PrivilegeType {
    Read,
    Write,
}
#[derive(Hash, Eq, PartialEq, Debug, Clone)]
enum ObjectKind {
    Table,
    View,
    Sequence,
    Function,
    Procedure,
    Type,
}

impl FromStr for ObjectKind {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "table" => Ok(ObjectKind::Table),
            "view" => Ok(ObjectKind::View),
            "sequence" => Ok(ObjectKind::Sequence),
            "function" => Ok(ObjectKind::Function),
            "procedure" => Ok(ObjectKind::Procedure),
            "type" => Ok(ObjectKind::Type),
            _ => Err(()),
        }
    }
}

struct ObjectPermissions {
    pub objkind: ObjectKind,
    pub read: Vec<String>,
    pub write: Vec<String>,
}

pub struct RolePermissions {
    pub role: String,
    pub permissions: HashMap<ObjectKind, ObjectPermissions>,
}

impl RolePermissions {
    pub fn add_read_permission(&self, grantee: GranteePrivileges) {
        if self.permissions.contains_key(&grantee.objkind) {
            let mut obj = self.permissions.get_mut(&grantee.objkind).unwrap();
            obj.read.push(grantee.grantee);
        } else {
            let mut obj = ObjectPermissions {
                objkind: grantee.objkind,
                read: vec![grantee.grantee],
                write: vec![],
            };
            self.permissions.insert(grantee.objkind, obj);
        }
    }

    pub fn add_write_permission(&self, grantee: GranteePrivileges) {
        if self.permissions.contains_key(&grantee.objkind) {
            let mut obj = self.permissions.get_mut(&grantee.objkind).unwrap();
            obj.write.push(grantee.grantee);
        } else {
            let mut obj = ObjectPermissions {
                objkind: grantee.objkind,
                read: vec![],
                write: vec![grantee.grantee],
            };
            self.permissions.insert(grantee.objkind, obj);
        }
    }
}

#[derive(Debug, Clone)]
pub struct RoleMembership {
    pub role: String,
    pub member_of: String,
}

impl RoleMembership {
    pub fn new(role: String, member_of: String) -> Self {
        RoleMembership { role, member_of }
    }
}

impl fmt::Display for RoleMembership {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<Membership> {}->{}", self.role, self.member_of)
    }
}
pub struct ObjectOwnership {
    pub owner: String,
    pub objkind: String,
    pub schema: String,
    pub unqualified_name: Option<String>,
}
#[derive(Debug)]
pub struct GranteePrivileges {
    grantee: String,
    objkind: ObjectKind,
    schema: String,
    unqualified_name: Option<String>,
    privilege_type: String,
}

impl fmt::Display for GranteePrivileges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<GranteePrivileges> {} has {} ON {:?} {}.{}",
            self.grantee,
            self.privilege_type,
            self.objkind,
            self.schema,
            self.unqualified_name.as_ref().unwrap_or(&"".to_string()),
        )
    }
}
#[derive(Debug)]
pub struct DefaultAccessPrivileges {
    grantee: String,
    objkind: String,
    grantor: String,
    schema: String,
    privilege_type: String,
}

impl fmt::Display for DefaultAccessPrivileges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<DefaultAccessPrivileges> {} has {} ON FUTURE {} in {} FROM {}",
            self.grantee, self.privilege_type, self.objkind, self.schema, self.grantor
        )
    }
}

pub struct RawObjectAttribute {
    kind: String,
    schema: String,
    unqualified_name: Option<String>,
    owner: String,
    is_dependent: bool,
}

pub trait Context {
    fn get_role_attributes(&mut self) -> Vec<PostgresRoleAttributes>;
    fn get_all_memberships(&mut self) -> Vec<RoleMembership>;
    fn get_obj_permissions_by_role(&mut self) -> Vec<GranteePrivileges>;
    fn get_default_permissions(&mut self) -> Vec<DefaultAccessPrivileges>;
    fn get_raw_object_attributes(&mut self) -> Vec<RawObjectAttribute>;
    fn get_ownerships(&mut self) -> Vec<ObjectOwnership>;
    fn get_privileges(&mut self, role: &str);
}

pub struct PostgresContext {
    client: postgres::Client,
}

impl fmt::Display for PostgresRoleAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<Role> {} enabled: {} superuser: {}",
            self.name, self.canlogin, self.superuser
        )
    }
}

impl PostgresContext {
    pub fn new() -> Self {
        let client = postgres::Client::connect(
            "host=localhost port=54321 user=postgres password=password",
            NoTls,
        )
        .unwrap();
        PostgresContext { client }
    }
}

impl PostgresContext {
    fn get_schema_privileges(&mut self, _role: &str) {
        // Get write privileges
        // Get read privileges
        // Get owned schemas
        // Add owned schemas to read and write privileges
        // Get read-only schemas (no write privileges)
        // Return schema privileges
    }

    // HashMap<ObjectKind, ObjectPermissions>

    fn get_all_current_nondefaults(&mut self) -> HashMap<String, RolePermissions> {
        let rows = &self
            .client
            .query(crate::queries::Q_GET_ALL_CURRENT_NONDEFAULTS, &[])
            .unwrap();

        let grantees: Vec<GranteePrivileges> = rows
            .iter()
            .map(|row| GranteePrivileges {
                grantee: row.get(0),
                objkind: ObjectKind::from_str(row.get(1)).unwrap(),
                schema: row.get(2),
                unqualified_name: row.get(3),
                privilege_type: row.get(4),
            })
            .collect();

        let mut perms: HashMap<String, HashMap<ObjectKind, ObjectPermissions>> = HashMap::new();

        for grantee in grantees {
            perms.insert(grantee.grantee.clone(), HashMap::new());
        }

        perms
    }
}

impl Context for PostgresContext {
    fn get_role_attributes(&mut self) -> Vec<PostgresRoleAttributes> {
        let rows = self
            .client
            .query(crate::queries::Q_GET_ROLE_ATTRIBUTES, &[])
            .unwrap();

        rows.iter()
            .map(|row| PostgresRoleAttributes {
                name: row.get(0),
                bypassrls: row.get(1),
                canlogin: row.get(2),
                connlimit: row.get(3),
                createdb: row.get(4),
                createrole: row.get(5),
                inherit: row.get(6),
                replication: row.get(7),
                superuser: row.get(8),
                validuntil: row.get(9),
            })
            .collect()
    }

    fn get_all_memberships(&mut self) -> Vec<RoleMembership> {
        let rows = &self
            .client
            .query(crate::queries::Q_ALL_MEMBERSHIPS, &[])
            .unwrap();

        rows.iter()
            .map(|row| RoleMembership {
                role: row.get(0),
                member_of: row.get(1),
            })
            .collect()
    }

    fn get_raw_object_attributes(&mut self) -> Vec<RawObjectAttribute> {
        let rows = &self
            .client
            .query(crate::queries::Q_RAW_OBJECT_ATTRIBUTES, &[])
            .unwrap();

        rows.iter()
            .map(|row| RawObjectAttribute {
                kind: row.get(0),
                schema: row.get(1),
                unqualified_name: row.get(2),
                owner: row.get(3),
                is_dependent: row.get(4),
            })
            .collect()
    }

    fn get_ownerships(&mut self) -> Vec<ObjectOwnership> {
        let raw_attrs = self.get_raw_object_attributes();

        raw_attrs
            .iter()
            .map(|attr| ObjectOwnership {
                owner: attr.owner.clone(),
                objkind: attr.kind.clone(),
                schema: attr.schema.clone(),
                unqualified_name: attr.unqualified_name.clone(),
            })
            .collect()
    }

    fn get_obj_permissions_by_role(&mut self) -> Vec<GranteePrivileges> {
        let rows = &self
            .client
            .query(crate::queries::Q_OBJ_PERMISSIONS_BY_ROLE, &[])
            .unwrap();

        rows.iter()
            .map(|row| GranteePrivileges {
                grantee: row.get(0),
                objkind: ObjectKind::from_str(row.get(1)).unwrap(),
                schema: row.get(2),
                unqualified_name: row.get(3),
                privilege_type: row.get(4),
            })
            .collect()
    }
    fn get_default_permissions(&mut self) -> Vec<DefaultAccessPrivileges> {
        let rows = &self
            .client
            .query(crate::queries::Q_GET_DEFAULT_PERMISSIONS, &[])
            .unwrap();

        rows.iter()
            .map(|row| DefaultAccessPrivileges {
                grantee: row.get(0),
                objkind: row.get(1),
                grantor: row.get(2),
                schema: row.get(3),
                privilege_type: row.get(4),
            })
            .collect()
    }

    fn get_privileges(&mut self, _role: &str) {
        // Get schema privileges
        // Get nonschema privileges
        // Get role privileges
    }
}
