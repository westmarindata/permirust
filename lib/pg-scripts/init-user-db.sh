set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL

    /* ------------------------- */
    /* Create Database Obejcts   */
    /* ------------------------- */
    CREATE SCHEMA finance;
    CREATE SCHEMA marketing;
    CREATE SCHEMA reports;

    CREATE TABLE finance.Q2_revenue();
    CREATE TABLE finance.Q2_margin();
    CREATE TABLE marketing.ad_spend();
    CREATE TABLE reports.some_report();

    CREATE SEQUENCE reports.Q2_revenue_seq;

    /* ------------------------- */
    /* Create Roles              */
    /* ------------------------- */
    CREATE ROLE jdoe WITH LOGIN;
    CREATE ROLE analyst WITH NOLOGIN;
    CREATE ROLE engineer WITH LOGIN SUPERUSER;

    /* ------------------------- */
    /* Create Memberships        */
    /* ------------------------- */
    GRANT analyst TO jdoe;
    GRANT engineer TO jdoe;
    GRANT analyst to engineer;
    GRANT engineer to postgres;


    /* ------------------------- */
    /* Create Ownerships         */
    /* ------------------------- */
    ALTER SCHEMA finance OWNER TO analyst;
    ALTER SCHEMA marketing OWNER TO analyst;
    ALTER SCHEMA reports OWNER to jdoe;

    ALTER TABLE finance.Q2_revenue OWNER TO analyst;
    ALTER TABLE finance.Q2_margin OWNER TO analyst;
    ALTER TABLE marketing.ad_spend OWNER TO analyst;
    ALTER TABLE reports.some_report OWNER TO jdoe;


    /* ------------------------- */
    /* Create Privileges         */
    /* ------------------------- */

    GRANT CREATE ON SCHEMA finance TO analyst;
    GRANT CREATE, USAGE ON SCHEMA marketing TO analyst;
    GRANT USAGE ON SCHEMA reports TO analyst;

    GRANT SELECT ON TABLE finance.Q2_revenue TO analyst;
    GRANT INSERT, UPDATE, DELETE ON TABLE finance.Q2_margin TO analyst;
    GRANT SELECT, TRUNCATE, INSERT ON TABLE marketing.ad_spend TO analyst;
    GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA reports TO engineer;

    GRANT SELECT ON SEQUENCE reports.Q2_revenue_seq TO analyst;
    GRANT ALL ON SEQUENCE reports.Q2_revenue_seq TO jdoe;

    ALTER DEFAULT PRIVILEGES IN SCHEMA finance
        GRANT ALL PRIVILEGES ON TABLES TO analyst;

    ALTER DEFAULT PRIVILEGES IN SCHEMA marketing
        GRANT SELECT ON TABLES TO jdoe;

    ALTER DEFAULT PRIVILEGES IN SCHEMA marketing
        GRANT USAGE ON SEQUENCES TO engineer;

EOSQL

