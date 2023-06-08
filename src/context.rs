//! Context trait for retrieving permission information from a database.
use std::{
    collections::HashSet,
    fmt::{self, Debug, Display},
};

/// A trait for retrieving permission information from a database.
///
/// Any database that can have permissions applied to it can implement this
/// trait. The trait is generic over the type of role attributes that the
/// database supports. The `RoleAttribute` type is used to represent the
/// attributes of a role, such as whether it is a superuser, whether it is
/// enabled, etc.
pub trait Context {
    type RoleAttribute;
    fn database_name(&self) -> &str;

    fn get_roles(&mut self) -> Vec<String>;

    fn get_role_attributes(&mut self, role: &str) -> Self::RoleAttribute;

    fn get_role_memberships(&mut self, role: &str) -> RoleMembership;

    fn get_role_ownerships(&mut self, role: &str) -> Vec<DatabaseObject>;

    fn get_role_permissions(&mut self, role: &str) -> Vec<Privilege>;

    // TODO: Confusing to have spec::Role and context::Role, consider renaming
    fn analyze_attributes(&mut self, name: &str, role: &crate::spec::Role) -> Vec<String>;

    fn analyze_memberships(&mut self, name: &str, role: &crate::spec::Role) -> Vec<String>;

    fn get_default_permissions(&mut self, role: &str) -> Vec<DefaultPrivilege>;
}

/// Represents a Role or a User
#[derive(Debug, Clone)]
pub struct Role(pub String);

impl Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A trait for representing the attributes of a role.
pub trait RoleAttribute {
    fn get_attributes(&self) -> Vec<Attributes>;
    fn is_enabled(&self) -> bool {
        self.get_attributes().contains(&Attributes::Enabled)
    }
}

/// A trait for representing attributes of a role. This represents all traits
/// for any database right now, but could be split out by database.
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

/// Represents all the privileges of a particular role, e.g. CREATE, SELECT, etc.
#[derive(Debug)]
pub struct RoleMembership {
    pub memberships: Vec<String>,
}

impl RoleMembership {
    pub fn new(memberships: Vec<String>) -> Self {
        RoleMembership { memberships }
    }
}

/// Database objects are given a struct in order to deal with quoting
/// of object names.
#[derive(PartialEq, Eq, Hash, Ord, PartialOrd)]
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
    pub fn new(kind: ObjectKind, schema: String, unqualified_name: Option<String>) -> Self {
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

/// Represents a particular database object. Currently any object
/// on a database is represented here, but this could be split out by database
#[derive(Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
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

impl ObjectKind {
    pub fn to_privilege(&self, raw_privilege: &str) -> PrivilegeType {
        match self {
            ObjectKind::Schema => match raw_privilege {
                "USAGE" => PrivilegeType::Read,
                "CREATE" => PrivilegeType::Write,
                _ => panic!("Unknown privilege: {}", raw_privilege),
            },
            ObjectKind::Table => match raw_privilege {
                "SELECT" => PrivilegeType::Read,
                "INSERT" => PrivilegeType::Write,
                "UPDATE" => PrivilegeType::Write,
                "DELETE" => PrivilegeType::Write,
                "TRUNCATE" => PrivilegeType::Write,
                "REFERENCES" => PrivilegeType::Read,
                "TRIGGER" => PrivilegeType::Write,
                _ => panic!("Unknown privilege: {}", raw_privilege),
            },
            ObjectKind::View => match raw_privilege {
                "SELECT" => PrivilegeType::Read,
                "INSERT" => PrivilegeType::Write,
                "UPDATE" => PrivilegeType::Write,
                "DELETE" => PrivilegeType::Write,
                "TRUNCATE" => PrivilegeType::Write,
                "REFERENCES" => PrivilegeType::Read,
                "TRIGGER" => PrivilegeType::Write,
                _ => panic!("Unknown privilege: {}", raw_privilege),
            },
            ObjectKind::Sequence => match raw_privilege {
                "SELECT" => PrivilegeType::Read,
                "UPDATE" => PrivilegeType::Write,
                "USAGE" => PrivilegeType::Write,
                _ => panic!("Unknown privilege: {}", raw_privilege),
            },
        }
    }
}
/// These are generic Privileges that will be mapped to from underlying
/// database grants. Different objects may have different mappings, for example
/// USAGE may be a READ on a schema but WRITE on a sequence.
/// If Read/Write are not sufficient we might add more later.
#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PrivilegeType {
    Read,
    Write,
}

/// Represents the privileges that a role has on a particular object.
#[derive(Debug)]
pub struct Privilege {
    pub object: DatabaseObject,
    pub privs: HashSet<PrivilegeType>,
}

impl Privilege {
    pub fn new(object: DatabaseObject, privs: Vec<PrivilegeType>) -> Self {
        Privilege {
            object,
            privs: HashSet::from_iter(privs),
        }
    }
}

/// Represetns a default privlege granted on sub-objects, for example,
/// granting SELECT on all future tables in a schema to ROLE
#[derive(Debug)]
pub struct DefaultPrivilege {
    pub parent: DatabaseObject,
    pub child: ObjectKind,
    pub privs: HashSet<PrivilegeType>,
}
