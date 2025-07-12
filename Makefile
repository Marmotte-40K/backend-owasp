include .env

create_migration:
	@read -p "Enter migration name: " name; \
	if [ -z "$$name" ]; then \
		echo "Migration name cannot be empty"; \
		exit 1; \
	fi; \
	migrate create -ext=sql -dir database/migrations "$$name" && \
	echo "Migration $$name created successfully"

run_migrations:
	@echo "Running migrations..."
	migrate -path database/migrations -database "postgres://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_DATABASE)?sslmode=disable" up && \
	echo "Migrations ran successfully"

migrate_down:
	@echo "Rolling back last migration..."
	migrate -path database/migrations -database "postgres://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_DATABASE)?sslmode=disable" down && \
	echo "Migration rolled back successfully"
	