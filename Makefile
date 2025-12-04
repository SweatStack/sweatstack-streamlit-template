.PHONY: build

build:
	docker build -t sweatstack-streamlit .

serve:
	docker run --rm --env-file .env -p 8080:8080 sweatstack-streamlit