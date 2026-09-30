# School E-Voting

## Run locally
1. Install Node.js 20+
2. Copy `.env.example` to `.env`, fill in `ADMIN_PASSWORD` and `SESSION_SECRET` (32+ chars). Paste your Neon `DATABASE_URL` (Vercel -> Storage -> your database -> .env.local tab).
3. `npm install`
4. `npm run dev`
5. Students: http://localhost:3000/  |  Admin: http://localhost:3000/?admin=1

## Deploy on Vercel
1. Push this folder to a private GitHub repo (`.env` is git-ignored) and import it at vercel.com/new.
2. In the project, open **Storage -> Create Database -> Neon (Postgres)** and connect it. Vercel adds `DATABASE_URL` automatically.
3. In **Settings -> Environment Variables** add: ADMIN_PASSWORD, SESSION_SECRET (32+ chars), SCHOOL_NAME.
4. **Deployments -> Redeploy**, then open `/api/config` to confirm it works.

## Election flow
Create positions and candidates (election closed) -> add voters (single or bulk) -> open -> close -> publish results.
The ballot locks once voting starts. Votes are stored anonymously.
