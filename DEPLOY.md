# Deploy PhishScan (about 15 minutes)

Backend (FastAPI) on Render, frontend (Next.js) on Vercel.

## 0. Push to GitHub
    cd phishscan-project
    git init && git add . && git commit -m "PhishScan"
    git branch -M main
    git remote add origin https://github.com/<you>/phishscan.git && git push -u origin main

## 1. Backend on Render
1. render.com > New > Blueprint > select the repo (uses `render.yaml`).
   (Or New > Web Service > Docker, Root/Context `backend`, Dockerfile `backend/Dockerfile`.)
2. When asked for `CORS_ORIGINS`, enter a placeholder (`https://placeholder.vercel.app`); you'll fix it in step 3.
3. Wait for the build (first build is a few minutes). Open `https://<your-api>.onrender.com/api/health`. It should return JSON.

## 2. Frontend on Vercel
1. vercel.com > Add New > Project > import the same repo.
2. Set **Root Directory** to `frontend`.
3. Add environment variable:  
   `NEXT_PUBLIC_API_URL` = `https://<your-api>.onrender.com/api`   (must end in `/api`)
4. Deploy. Note your URL, e.g. `https://phishscan.vercel.app`.

## 3. Connect them (CORS)
Render > phishscan-api > Environment > set `CORS_ORIGINS` to your exact Vercel URL
(no trailing slash; comma-separate if you have several, e.g. a custom domain). Save; it redeploys.

## Notes
- `NEXT_PUBLIC_API_URL` is baked in at build time: change it, then redeploy the frontend.
- Default storage is SQLite on the container disk, so history resets on each redeploy.
  For persistence, create a Render PostgreSQL database and set `DATABASE_URL` to its
  *internal* URL with the scheme changed to `postgresql+psycopg2://`.
- Smoke test: open the site, scan `https://www.netflix.com/browse` (clean) and
  `http://paypal-secure-login-verify.tk/signin.php` (malicious).
