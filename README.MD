# FLASK STORE API   

## How to run the Dockerfile locally

```
docker run -dp 5000:5000 -w /app -v "$(pwd):/app" flask-store-api sh -c "flask run"
```