.PHONY: up down restart logs ps smoke herd

service ?=

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose down
	docker compose up -d

logs:
	docker compose logs -f $(service)

ps:
	docker compose ps
