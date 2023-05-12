pub const Q_ALL_MEMBERSHIPS: &str = "
SELECT
  auth_member.rolname AS member,
  auth_group.rolname AS group
FROM pg_auth_members link_table
JOIN pg_authid auth_member ON link_table.member = auth_member.oid
JOIN pg_authid auth_group ON link_table.roleid = auth_group.oid
";

pub const Q_OBJ_PERMISSIONS_BY_ROLE: &str = "
WITH
  relkind_mapping (objkey, objkind) AS (
      VALUES ('r', 'tables'),
        ('v', 'tables'),
        ('m', 'tables'),
        ('f', 'tables'),
        ('S', 'sequences')
  ), tables_and_sequences AS (
      SELECT
          nsp.nspname AS schema,
          c.relname AS unqualified_name,
          map.objkind,
          (aclexplode(c.relacl)).grantee AS grantee_oid,
          t_owner.rolname AS owner,
          (aclexplode(c.relacl)).privilege_type
      FROM
          pg_class c
          JOIN pg_authid t_owner ON c.relowner = t_owner.OID
          JOIN pg_namespace nsp ON c.relnamespace = nsp.oid
          JOIN relkind_mapping map ON c.relkind = map.objkey
      WHERE
          nsp.nspname NOT LIKE 'pg\\_t%'
          AND c.relacl IS NOT NULL
  ), schemas AS (
      SELECT
           nsp.nspname AS schema,
           NULL::TEXT AS unqualified_name,
           'schemas'::TEXT AS objkind,
           (aclexplode(nsp.nspacl)).grantee AS grantee_oid,
           t_owner.rolname AS owner,
           (aclexplode(nsp.nspacl)).privilege_type
      FROM pg_namespace nsp
      JOIN pg_authid t_owner
          ON nsp.nspowner = t_owner.OID
  ), combined AS (
      SELECT * FROM tables_and_sequences
      UNION ALL
      SELECT * FROM schemas
  )
  SELECT
      t_grantee.rolname AS grantee,
      combined.objkind,
      combined.schema,
      combined.unqualified_name,
      combined.privilege_type
  FROM
      combined
      JOIN pg_authid t_grantee ON combined.grantee_oid = t_grantee.oid
      WHERE combined.owner != t_grantee.rolname
";

pub const Q_GET_ROLE_ATTRIBUTES: &str = "
SELECT
  rolname,
  rolbypassrls,
  rolcanlogin,
  rolconnlimit,
  rolcreatedb,
  rolcreaterole,
  rolinherit,
  rolreplication,
  rolsuper,
  rolvaliduntil
FROM pg_authid
WHERE rolname != 'pg_signal_backend'
";

pub const Q_GET_DEFAULT_PERMISSIONS: &str = " WITH relkind_mapping (objkey, objkind) AS (
        VALUES ('f', 'functions'),
               ('r', 'tables'),
               ('S', 'sequences'),
               ('T', 'types')
    ), subq AS (
        SELECT
            auth.rolname AS grantor,
            auth.oid AS grantor_oid,
            (aclexplode(def.defaclacl)).grantee AS grantee_oid,
            nsp.nspname,
            map.objkind,
            (aclexplode(def.defaclacl)).privilege_type
        FROM
            pg_default_acl def
            JOIN pg_authid auth
                    ON def.defaclrole = auth.oid
            JOIN pg_namespace nsp
                    ON def.defaclnamespace = nsp.oid
            JOIN relkind_mapping map
                    ON def.defaclobjtype = map.objkey
        WHERE
            def.defaclacl IS NOT NULL
    )
    SELECT
        t_grantee.rolname AS grantee,
        subq.objkind,
        subq.grantor,
        subq.nspname AS schema,
        subq.privilege_type
    FROM
        subq
        JOIN pg_authid t_grantee
            ON subq.grantee_oid = t_grantee.oid
    WHERE
        subq.grantor_oid != subq.grantee_oid
    ";
pub const Q_RAW_OBJECT_ATTRIBUTES: &str = "
    WITH relkind_mapping (objkey, kind) AS (
        VALUES ('r', 'tables'),
               ('v', 'tables'),
               ('m', 'tables'),
               ('f', 'tables'),
               ('S', 'sequences')
    ), tables_and_sequences AS (
        SELECT
            map.kind,
            nsp.nspname AS schema,
            c.relname AS unqualified_name,
            c.relowner AS owner_id,
            -- Auto-dependency means that a sequence is linked to a table. Ownership of
            -- that sequence automatically derives from the table's ownership
            COUNT(deps.refobjid) > 0 AS is_dependent
        FROM
            pg_class c
            JOIN relkind_mapping map
                ON c.relkind = map.objkey
            JOIN pg_namespace nsp
                ON c.relnamespace = nsp.OID
            LEFT JOIN pg_depend deps
                ON deps.objid = c.oid
                AND deps.classid = 'pg_class'::REGCLASS
                AND deps.refclassid = 'pg_class'::REGCLASS
                AND deps.deptype = 'a'
        GROUP BY
            map.kind,
            schema,
            unqualified_name,
            owner_id
    ), schemas AS (
        SELECT
            'schemas'::TEXT AS kind,
            nsp.nspname AS schema,
            NULL::TEXT AS unqualified_name,
            nsp.nspowner AS owner_id,
            FALSE AS is_dependent
        FROM pg_namespace nsp
    ), combined AS (
        SELECT *
        FROM tables_and_sequences
        UNION ALL
        SELECT *
        FROM schemas
    )
    SELECT
        co.kind,
        co.schema,
        co.unqualified_name,
        t_owner.rolname AS owner,
        co.is_dependent
    FROM combined AS co
    JOIN pg_authid t_owner
        ON co.owner_id = t_owner.OID
    WHERE
        co.schema NOT LIKE 'pg\\_t%'
    ;
    ";

pub const Q_GET_ALL_CURRENT_NONDEFAULTS: &str = "
    WITH relkind_mapping (objkey, objkind) AS (
        VALUES ('r', 'tables'),
               ('v', 'tables'),
               ('m', 'tables'),
               ('f', 'tables'),
               ('S', 'sequences')
    ), tables_and_sequences AS (
        SELECT
            nsp.nspname AS schema,
            c.relname AS unqualified_name,
            map.objkind,
            (aclexplode(c.relacl)).grantee AS grantee_oid,
            t_owner.rolname AS owner,
            (aclexplode(c.relacl)).privilege_type
        FROM
            pg_class c
            JOIN pg_authid t_owner
                ON c.relowner = t_owner.OID
            JOIN pg_namespace nsp
                ON c.relnamespace = nsp.oid
            JOIN relkind_mapping map
                ON c.relkind = map.objkey
        WHERE
            nsp.nspname NOT LIKE 'pg\\_t%'
            AND c.relacl IS NOT NULL
    ), schemas AS (
        SELECT
             nsp.nspname AS schema,
             NULL::TEXT AS unqualified_name,
             'schemas'::TEXT AS objkind,
             (aclexplode(nsp.nspacl)).grantee AS grantee_oid,
             t_owner.rolname AS owner,
             (aclexplode(nsp.nspacl)).privilege_type
        FROM pg_namespace nsp
        JOIN pg_authid t_owner
            ON nsp.nspowner = t_owner.OID
    ), combined AS (
        SELECT *
        FROM tables_and_sequences
        UNION ALL
        SELECT *
        FROM schemas
    )
    SELECT
        t_grantee.rolname AS grantee,
        combined.objkind,
        combined.schema,
        combined.unqualified_name,
        combined.privilege_type
    FROM
        combined
        JOIN pg_authid t_grantee
            ON combined.grantee_oid = t_grantee.oid
        WHERE combined.owner != t_grantee.rolname
    ;
";
