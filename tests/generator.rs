//! Use the Postgres adapter to check if the output spec matches what we expect.

// The spec loaded in Postgres is defined in lib/pg-scripts/init-user-db.sh
//
use permirust::adapters::postgres::PostgresClient;
use permirust::adapters::postgres::PostgresRoleAttributes;
use permirust::context::DatabaseObject;
use permirust::context::ObjectKind::*;
use permirust::context::Privilege;
use permirust::context::PrivilegeType::*;
use permirust::context::RoleMembership;
use permirust::generate::generate_spec;
use permirust::spec::DatabaseSpec;

#[test]
fn test_postgres_generates_correct_spec() {
    let conn_str = "host=localhost port=54321 user=postgres password=password";
    let db_context = PostgresClient::new(conn_str).unwrap();
    let spec_yaml = generate_spec(db_context).unwrap();
    let spec = serde_yaml::from_str::<DatabaseSpec>(&spec_yaml).unwrap();

    let mut expected_spec = DatabaseSpec::new("postgres");

    // Add Roles
    expected_spec.add_role("jdoe", &PostgresRoleAttributes::new(false, false));
    expected_spec.add_role("analyst", &PostgresRoleAttributes::new(true, false));
    expected_spec.add_role("engineer", &PostgresRoleAttributes::new(true, true));
    expected_spec.add_role("postgres", &PostgresRoleAttributes::new(true, true));

    // Add Memberships
    expected_spec.add_memberships(
        "jdoe",
        &RoleMembership {
            memberships: vec!["analyst".to_string(), "engineer".to_string()],
        },
    );

    expected_spec.add_memberships(
        "engineer",
        &RoleMembership {
            memberships: vec!["analyst".to_string()],
        },
    );

    expected_spec.add_memberships(
        "postgres",
        &RoleMembership {
            memberships: vec!["engineer".to_string()],
        },
    );

    // Add Ownerships
    expected_spec.add_ownerships(
        "analyst",
        &[
            DatabaseObject::new(Schema, "finance".into(), None),
            DatabaseObject::new(Schema, "marketing".into(), None),
            DatabaseObject::new(Table, "finance".into(), Some("q2_margin".into())),
            DatabaseObject::new(Table, "finance".into(), Some("q2_revenue".into())),
            DatabaseObject::new(Table, "marketing".into(), Some("ad_spend".into())),
        ],
    );
    expected_spec.add_ownerships(
        "jdoe",
        &[
            DatabaseObject::new(Schema, "reports".into(), None),
            DatabaseObject::new(Table, "reports".into(), Some("some_report".into())),
        ],
    );
    expected_spec.add_ownerships(
        "postgres",
        &[DatabaseObject::new(
            Sequence,
            "reports".into(),
            Some("q2_revenue_seq".into()),
        )],
    );

    // Add privileges expected_spec
    expected_spec.add_privileges(
        "analyst",
        &[
            Privilege::new(
                DatabaseObject::new(Schema, "finance".into(), None),
                vec![Write],
            ),
            Privilege::new(
                DatabaseObject::new(Schema, "marketing".into(), None),
                vec![Read, Write],
            ),
            Privilege::new(
                DatabaseObject::new(Schema, "reports".into(), None),
                vec![Read],
            ),
            Privilege::new(
                DatabaseObject::new(Table, "finance".into(), Some("q2_revenue".into())),
                vec![Read],
            ),
            Privilege::new(
                DatabaseObject::new(Table, "finance".into(), Some("q2_margin".into())),
                vec![Write],
            ),
            Privilege::new(
                DatabaseObject::new(Table, "marketing".into(), Some("ad_spend".into())),
                vec![Read, Write],
            ),
            Privilege::new(
                DatabaseObject::new(Sequence, "reports".into(), Some("q2_revenue_seq".into())),
                vec![Read],
            ),
        ],
    );

    expected_spec.add_privileges(
        "jdoe",
        &[Privilege::new(
            DatabaseObject::new(Sequence, "reports".into(), Some("q2_revenue_seq".into())),
            vec![Read, Write],
        )],
    );

    expected_spec.add_privileges(
        "engineer",
        &[
            Privilege::new(
                DatabaseObject::new(Table, "reports".into(), Some("some_report".into())),
                vec![Read, Write],
            ),
            Privilege::new(
                DatabaseObject::new(Table, "reports".into(), Some("other_report".into())),
                vec![Read, Write],
            ),
        ],
    );
    // Test Spec
    assert_eq!(spec.version, expected_spec.version);
    assert_eq!(spec.adapter, expected_spec.adapter);
    assert_eq!(spec.roles.len(), expected_spec.roles.len());

    // Main Test Loop
    for (role_name, expected_role) in expected_spec.roles.iter() {
        println!("Checking role {}", role_name);
        assert!(spec.roles.contains_key(role_name));

        // Test Memberships
        assert_eq!(
            spec.roles[role_name].member_of,
            expected_role.member_of,
            "\nEnsuring {} is member_of {}. We have {}",
            role_name,
            expected_role.member_of.join(","),
            spec.roles[role_name].member_of.join(","),
        );

        // Test Ownership -- note this is order dependent, we should fix that
        // if it gets buggy
        assert_eq!(
            spec.roles[role_name].owns, expected_role.owns,
            "\nEnsuring {} owns {}.\nWe have {}",
            role_name, expected_role.owns, spec.roles[role_name].owns,
        );

        // Test Privileges
        for (_, spec_role) in spec.roles.iter() {
            assert_eq!(
                spec_role.privileges.schemas, expected_role.privileges.schemas,
                "\nEnsuring {} has schema privileges {:?}.\nWe have {:?}",
                role_name, expected_role.privileges.schemas, spec_role.privileges.schemas,
            );
        }
    }
}
