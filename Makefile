PHONY: pg

generate:
	RUST_LOG=INFO cargo -q run -- generate

pg-start:
	docker stop permirust-postgres
	docker rm permirust-postgres
	@echo "Building Postgres"
	docker run --name permirust-postgres \
		-p 54321:5432 -e POSTGRES_PASSWORD=password \
		-d -v "${PWD}"/lib/pg-scripts:/docker-entrypoint-initdb.d/ \
		postgres:15
pg-stop:
	docker stop permirust-postgres
	docker rm permirust-postgres

pg-conn:
	PGPASSWORD=password psql -h localhost -p 54321 -U postgres postgres
