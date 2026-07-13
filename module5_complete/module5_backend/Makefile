.PHONY: start stop install test

install:
	pip3 install -r requirements.txt

start:
	python3 main.py

start-prod:
	uvicorn main:app --host 0.0.0.0 --port 8000 --workers 2

test:
	curl -s -H "Authorization: Bearer dev" http://localhost:8000/health | python3 -m json.tool
	curl -s -H "Authorization: Bearer dev" http://localhost:8000/api/v1/me | python3 -m json.tool
	curl -s -H "Authorization: Bearer dev" http://localhost:8000/api/v1/dashboard/summary | python3 -m json.tool
