# FLASK STORE API   

## How to run the Dockerfile locally

```
docker run -dp 8000:5000 -w /app -v "$(pwd):/app" flask-store-api sh -c "flask run"
```