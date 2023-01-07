#[allow(dead_code)]
pub fn diff_grant<T: PartialEq + Clone>(
    new_grants: Vec<T>,
    old_grants: Vec<T>,
) -> (Vec<T>, Vec<T>) {
    let mut grants_to_add: Vec<T> = Vec::new();
    let mut grants_to_remove: Vec<T> = Vec::new();

    for new_grant in &new_grants {
        if !old_grants.contains(new_grant) {
            grants_to_add.push(new_grant.clone());
        }
    }

    for old_grant in old_grants {
        if !new_grants.contains(&old_grant) {
            grants_to_remove.push(old_grant);
        }
    }

    (grants_to_add, grants_to_remove)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use crate::grants::{PostgresPrivileges, TableGrant};

    use super::*;

    #[test]
    fn test_diff_grants() {
        let select = TableGrant::new(
            PostgresPrivileges::Select,
            Some("table1".into()),
            "public".into(),
            vec!["user1".into()],
            false,
        )
        .unwrap();

        let insert = TableGrant::new(
            PostgresPrivileges::Insert,
            Some("table1".into()),
            "public".into(),
            vec!["user1".into()],
            false,
        )
        .unwrap();

        let update = TableGrant::new(
            PostgresPrivileges::Update,
            Some("table1".into()),
            "public".into(),
            vec!["user1".into()],
            false,
        )
        .unwrap();

        let delete = TableGrant::new(
            PostgresPrivileges::Delete,
            Some("table1".into()),
            "public".into(),
            vec!["user1".into()],
            false,
        )
        .unwrap();

        let new_grants = vec![select.clone(), insert.clone(), update.clone()];

        let old_grants = vec![insert.clone(), delete.clone()];

        let grants_to_add = vec![select, update];

        let grants_to_remove = vec![delete];

        let (res_add, res_remove) = diff_grant(new_grants, old_grants);
        assert_eq!(res_add, grants_to_add);
        assert_eq!(res_remove, grants_to_remove);
    }

    #[test]
    fn test_diff_grants_all_on_empty_old_grants() {
        let select = TableGrant::new(
            PostgresPrivileges::Select,
            Some("table1".into()),
            "public".into(),
            vec!["user1".into()],
            false,
        )
        .unwrap();

        let new_grant = vec![select.clone()];

        let res_add = diff_grant(new_grant.clone(), vec![]);
        assert_eq!(new_grant, res_add.0);
    }
}
