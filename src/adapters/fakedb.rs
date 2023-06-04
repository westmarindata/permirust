use std::collections::HashSet;

use crate::context::{Attributes, Context, DatabaseObject, ObjectKind, Privilege, RoleMembership};
use crate::context::{PrivilegeType::*, RoleAttribute};

/// A fake database context for testing
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
        match role {
            "alice" => vec![
                Privilege {
                    object: DatabaseObject::new(ObjectKind::Schema, "marketing".to_string(), None),
                    privs: HashSet::from_iter(vec![Read]),
                },
                Privilege {
                    object: DatabaseObject::new(ObjectKind::Schema, "finance".to_string(), None),
                    privs: HashSet::from_iter(vec![Read, Write]),
                },
                Privilege {
                    object: DatabaseObject::new(
                        ObjectKind::Table,
                        "finance".to_string(),
                        Some("q2_results".to_string()),
                    ),
                    privs: HashSet::from_iter(vec![Read]),
                },
            ],

            "bob" => vec![
                Privilege {
                    object: DatabaseObject::new(ObjectKind::Schema, "marketing".to_string(), None),
                    privs: HashSet::from_iter(vec![Read]),
                },
                Privilege {
                    object: DatabaseObject::new(ObjectKind::Schema, "finance".to_string(), None),
                    privs: HashSet::from_iter(vec![Read]),
                },
                Privilege {
                    object: DatabaseObject::new(
                        ObjectKind::Table,
                        "finance".to_string(),
                        Some("q2_results".to_string()),
                    ),
                    privs: HashSet::from_iter(vec![Read, Write]),
                },
            ],
            "carol" => vec![
                Privilege {
                    object: DatabaseObject::new(ObjectKind::Schema, "marketing".to_string(), None),
                    privs: HashSet::from_iter(vec![Read]),
                },
                Privilege {
                    object: DatabaseObject::new(ObjectKind::Schema, "finance".to_string(), None),
                    privs: HashSet::from_iter(vec![Read]),
                },
                Privilege {
                    object: DatabaseObject::new(
                        ObjectKind::Table,
                        "finance".to_string(),
                        Some("q2_results".to_string()),
                    ),
                    privs: HashSet::from_iter(vec![Read]),
                },
            ],
            _ => vec![],
        }
    }

    fn analyze_attributes(&mut self, name: &str, role: &crate::spec::Role) -> Vec<String> {
        let mut sql = vec![];
        if role.can_login {
            sql.push(format!("ALTER ROLE {} LOGIN", name));
        } else {
            sql.push(format!("ALTER ROLE {} NOLOGIN", name));
        }

        if role.is_superuser {
            sql.push(format!("ALTER ROLE {} SUPERUSER", name));
        } else {
            sql.push(format!("ALTER ROLE {} NOSUPERUSER", name));
        }
        sql
    }

    fn analyze_memberships(&mut self, name: &str, role: &crate::spec::Role) -> Vec<String> {
        let mut sql = vec![];
        for member in &role.member_of {
            sql.push(format!("GRANT {} TO {}", member, name));
        }
        sql
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
