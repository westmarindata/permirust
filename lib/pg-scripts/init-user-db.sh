#!/bin/bash
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

    CREATE TABLE finance.Q2_revenue();
    CREATE TABLE finance.Q2_margin();
    CREATE TABLE marketing.ad_spend();

    CREATE SEQUENCE reports.Q2_revenue_seq;

EOSQL

