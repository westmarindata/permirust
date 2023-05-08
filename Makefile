PHONY: pg

generate:
	cargo run -- generate

pg-start:
	@echo "Building Postgres"
	docker run --rm --name permirust-postgres \
		-p 54321:5432 -e POSTGRES_PASSWORD=password \
		-d -v "${PWD}"/lib/pg-scripts:/docker-entrypoint-initdb.d/ \
		postgres:15
pg-stop:
	docker stop permirust-postgres

pg-conn:
	PGPASSWORD=password psql -h localhost -p 54321 -U postgres postgres
