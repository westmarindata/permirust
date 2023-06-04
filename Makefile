PHONY: pg-start pg-stop pg-conn watch generate

generate:
	RUST_LOG=INFO cargo -q run -- generate

pg-start: pg-stop
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

watch:
	RUST_LOG=permirust=debug cargo-watch -x check -x test -x 'run -- configure'
