set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
	CREATE USER docker;
	CREATE DATABASE docker;
	GRANT ALL PRIVILEGES ON DATABASE docker TO docker;

    CREATE USER jdoe;
    CREATE ROLE analyst;

    CREATE SCHEMA finance;
    CREATE SCHEMA marketing;
    CREATE SCHEMA reports;

    CREATE TABLE finance.Q1_revenue();
    CREATE TABLE finance.Q1_margin();
    CREATE TABLE finance.Q2_revenue();
    CREATE TABLE finance.Q2_margin();

    CREATE TABLE marketing.ad_spend();
    CREATE TABLE marketing.more_ads();
    CREATE TABLE reports.some_report();
    CREATE TABLE reports.other_report();

    CREATE SEQUENCE reports.Q2_revenue_seq;

    ALTER DEFAULT PRIVILEGES IN SCHEMA finance
        GRANT ALL PRIVILEGES ON TABLES TO analyst;

    ALTER DEFAULT PRIVILEGES IN SCHEMA marketing
        GRANT SELECT ON TABLES TO analyst;

    ALTER DEFAULT PRIVILEGES IN SCHEMA marketing
        GRANT USAGE ON SEQUENCES TO analyst;


    GRANT CREATE ON SCHEMA finance to analyst;
    GRANT CREATE, USAGE ON SCHEMA marketing to analyst;
    GRANT USAGE ON SCHEMA reports to analyst;

    GRANT SELECT ON TABLE finance.Q2_revenue TO analyst;
    GRANT INSERT, UPDATE, DELETE ON TABLE finance.Q2_margin TO analyst;
    GRANT SELECT, TRUNCATE, INSERT ON TABLE marketing.ad_spend TO analyst;

    GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA reports TO analyst;

    GRANT SELECT ON SEQUENCE reports.Q2_revenue_seq TO analyst;
    GRANT ALL ON SEQUENCE reports.Q2_revenue_seq TO jdoe;

    GRANT ALL ON ALL TABLES IN SCHEMA reports TO jdoe;

    GRANT analyst TO jdoe;
    GRANT postgres to jdoe;

    ALTER SCHEMA finance OWNER TO analyst;
    ALTER SCHEMA marketing OWNER TO analyst;

EOSQL

