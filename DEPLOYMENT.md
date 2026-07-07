# BAM Rocket deployment notes

## Recommended preview: Railway

This project is a full-stack Node/Express + React/Vite application. Deploy it as one web service, not as a static site.

### Environment variables
Required for a safe preview:
- `JWT_SECRET`: long random secret
- `ENCRYPTION_SECRET`: long random secret

Optional:
- `GEMINI_API_KEY`: enables Gemini-powered AI features; without it the app uses built-in fallback/demo responses
- LinkedIn and Facebook OAuth variables from `.env.example`: required only for real social OAuth

Runtime variables:
- `PORT`: supplied by most cloud platforms automatically; the server now respects it
- `DATA_DIR`: defaults to `.data`; set to your mounted persistent volume path for persistent JSON data

### Railway steps
1. Push this folder to a GitHub repository.
2. In Railway create a new project and choose **Deploy from GitHub repo**.
3. Select the repository. Railway can detect the included `Dockerfile`.
4. Add `JWT_SECRET` and `ENCRYPTION_SECRET` in Variables.
5. Optional: add `GEMINI_API_KEY`.
6. For persistent data, attach a Railway Volume and mount it at `/data`. The Docker image already uses `DATA_DIR=/data`.
7. Generate a public domain in Railway Networking.

### Local Docker preview
```bash
docker build -t bam-rocket .
docker run --rm -p 3000:3000 \
  -e JWT_SECRET="replace-with-a-long-random-secret" \
  -e ENCRYPTION_SECRET="replace-with-another-long-random-secret" \
  -v bamrocket-data:/data \
  bam-rocket
```
Then open `http://localhost:3000`.

### Local Node preview
```bash
cp .env.example .env
npm ci
npm run dev
```
Then open `http://localhost:3000`.

## Important
- The current app uses a JSON file database, not PostgreSQL, despite `DATABASE_URL` appearing in `.env.example`.
- Do not rely on ephemeral cloud filesystem storage for real customer data.
- The login route currently auto-creates an account when an email does not exist. This is convenient for a demo but should be removed before production.
