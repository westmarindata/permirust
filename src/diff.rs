use crate::TableGrant;

fn diff_grants(
    new_grants: Vec<TableGrant>,
    old_grants: Vec<TableGrant>,
) -> (Vec<TableGrant>, Vec<TableGrant>) {
    let mut grants_to_add: Vec<TableGrant> = Vec::new();
    let mut grants_to_remove: Vec<TableGrant> = Vec::new();

    for new_grant in &new_grants {
        if !old_grants.contains(new_grant) {
            grants_to_add.push(new_grant);
        }
    }

    for old_grant in &old_grants {
        if !new_grants.contains(old_grant) {
            grants_to_remove.push(*old_grant);
        }
    }

    (grants_to_add, grants_to_remove)
}

#[cfg(test)]
mod tests {
    use crate::GrantType;

    use super::*;

    #[test]
    fn test_diff_grants() {
        let new_grants = vec![
            TableGrant::new(
                GrantType::Select,
                Some("table1".into()),
                "public".into(),
                vec!["user1".into()],
                false,
            ),
            TableGrant::new(
                GrantType::Insert,
                Some("table1".into()),
                "public".into(),
                vec!["user1".into()],
                false,
            ),
            TableGrant::new(
                GrantType::Update,
                Some("table1".into()),
                "public".into(),
                vec!["user1".into()],
                false,
            ),
        ];

        let old_grants = vec![
            TableGrant::new(
                GrantType::Insert,
                Some("table1".into()),
                "public".into(),
                vec!["user1".into()],
                false,
            ),
            TableGrant::new(
                GrantType::Delete,
                Some("table1".into()),
                "public".into(),
                vec!["user1".into()],
                false,
            ),
        ];

        let grants_to_add = vec![TableGrant::new(
            GrantType::Select,
            Some("table1".into()),
            "public".into(),
            vec!["user1".into()],
            false,
        )];

        let grants_to_remove = vec![
            TableGrant::new(
                GrantType::Update,
                Some("table1".into()),
                "public".into(),
                vec!["user1".into()],
                false,
            ),
            TableGrant::new(
                GrantType::Delete,
                Some("table1".into()),
                "public".into(),
                vec!["user1".into()],
                false,
            ),
        ];

        let (res_add, res_remove) = diff_grants(new_grants, old_grants);
        assert_eq!(res_add, grants_to_add);
        assert_eq!(res_remove, grants_to_remove);
    }
}
