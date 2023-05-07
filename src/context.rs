#![allow(dead_code)]
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

#[derive(Debug)]
pub struct GranteePrivileges {
    grantee: String,
    objkind: String,
    schema: String,
    unqualified_name: Option<String>,
    privilege_type: String,
}

impl fmt::Display for GranteePrivileges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<GranteePrivileges> {} has {} ON {} {}.{}",
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

#[derive(Debug, Clone)]
pub struct PostgresMembership {
    pub role: String,
    pub member_of: String,
}

impl PostgresMembership {
    pub fn new(role: String, member_of: String) -> Self {
        PostgresMembership { role, member_of }
    }
}

impl fmt::Display for PostgresMembership {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<Membership> {}->{}", self.role, self.member_of)
    }
}

pub struct PostgresOwnership {
    pub owner: String,
    pub objkind: String,
    pub schema: String,
    pub unqualified_name: Option<String>,
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
    fn get_all_memberships(&mut self) -> Vec<PostgresMembership>;
    fn get_obj_permissions_by_role(&mut self) -> Vec<GranteePrivileges>;
    fn get_default_permissions(&mut self) -> Vec<DefaultAccessPrivileges>;
    fn get_raw_object_attributes(&mut self) -> Vec<RawObjectAttribute>;
    fn get_ownerships(&mut self) -> Vec<PostgresOwnership>;
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

    fn get_all_memberships(&mut self) -> Vec<PostgresMembership> {
        let rows = &self
            .client
            .query(crate::queries::Q_ALL_MEMBERSHIPS, &[])
            .unwrap();

        rows.iter()
            .map(|row| PostgresMembership {
                role: row.get(0),
                member_of: row.get(1),
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
                objkind: row.get(1),
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

    fn get_ownerships(&mut self) -> Vec<PostgresOwnership> {
        let raw_attrs = self.get_raw_object_attributes();

        raw_attrs
            .iter()
            .map(|attr| PostgresOwnership {
                owner: attr.owner.clone(),
                objkind: attr.kind.clone(),
                schema: attr.schema.clone(),
                unqualified_name: attr.unqualified_name.clone(),
            })
            .collect()
    }
}
