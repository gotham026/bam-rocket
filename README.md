# BAM Rocket &bull; Full-Stack B2B Lead Generation & Sales Intelligence SaaS

BAM Rocket is a comprehensive, production-ready, full-stack B2B lead generation, social pipeline outreach (LinkedIn + Facebook OAuth), CRM, outbound sequences, and AI Sales intelligence platform. It features complete secure user session authentication, private isolated workspaces, unified social integrations, and multi-tenant credit wallet deduplication.

## 🚀 Key Architectural Layouts

- **Multi-User Isolation Model**: Authenticated JWT sessions securely separate B2B contacts, pipelines, and wallets. Every database query automatically isolates records based on client `userId` and `workspaceId` tags.
- **Durable File-Based Relational Database**: To ensure 100% cloud boot resilience in Cloud Run nodes without relying on complex external Postgres installations during previews, the application integrates an absolute transaction-safe filesystem database (`.data/db.json`) implementing complete cascading joins, password hashing, and auto-provision seeder.
- **Secure Token Cryptography**: Decouples sensitive OAuth credentials from browser visibility. Access tokens are encrypted using highly secure `ENCRYPTION_SECRET` ciphers before saving them in the databases.
- **Unified Social Tunnels**: True browser iframe compliant OAuth Popups communicate connected status tokens in real-time to the CRM settings panel.
- **Gemini NLP Extraction**: Integrates server-guided natural language query parsing. Extracts high-fidelity metadata (Seniority, technology stacks, industries, buying intent) from search inputs to filter lead pools dynamically.

---

## 🛠️ Installation & Setup

### 1. Configure System Environment
Duplicate `.env.example` as `.env` and configure appropriate secrets:

```env
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/bamrocket
JWT_SECRET=super_secure_auth_secret_sequence_key
ENCRYPTION_SECRET=aes_secret_encryption_channel_xor_key
GEMINI_API_KEY=your_google_ai_studio_api_key
OPENAI_API_KEY=your_optional_additional_openai_key
LINKEDIN_CLIENT_ID=your_linkedin_client_id
LINKEDIN_CLIENT_SECRET=your_linkedin_client_secret
LINKEDIN_REDIRECT_URI=http://localhost:3000/api/integrations/linkedin/callback
FACEBOOK_APP_ID=your_meta_app_id
FACEBOOK_APP_SECRET=your_meta_app_secret
FACEBOOK_REDIRECT_URI=http://localhost:3000/api/integrations/facebook/callback
FRONTEND_URL=http://localhost:3000
BACKEND_URL=http://localhost:3000
```

### 2. Quick-Start Development
Start the full-stack server (Vite + Node/Express proxy) dynamically on port `3000` executing:

```bash
# 1. Install workspace dependencies
npm install

# 2. Run the full-stack server on development mode
npm run dev
```

The system binds the backend routing triggers under `/api/*` and mounts the Vite proxy cleanly to hot-reload local frontend pages.

---

## 🌐 Production Deployment

### 1. Build Compilation
Compile the SPA assets and esbuild server-side bundles into a singular standalone output:

```bash
npm run build
```

This compiles static React files inside `./dist` and creates a self-contained CommonJS Node server at `./dist/server.cjs` which completely bypasses standard module directory import constraints.

### 2. Standalone Start
Bootstrap standard production deployment:

```bash
npm run start
```

---

## 🔒 Security & OAuth Setup

### LinkedIn API Configuration
1. Register a corporate application inside the [LinkedIn Developer Portal](https://developer.linkedin.com/).
2. Enable exact scopes: `r_liteprofile`, `w_member_social`.
3. Add Redirect Portal URL matching `https://<your_domain>.com/api/integrations/linkedin/callback`.
4. Copy credentials to `.env`.

### Meta Graph API Configuration
1. Create a platform business application under the [Meta Developer Page](https://developers.facebook.com/).
2. Configure permissions for `public_profile`, `ads_management`.
3. Set OAuth callback to `https://<your_domain>.com/api/integrations/facebook/callback`.
4. Run standard App Reviews inside credentials setup.
