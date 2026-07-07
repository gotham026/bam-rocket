import "dotenv/config";
import express from "express";
import path from "path";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { GoogleGenAI, Type } from "@google/genai";
import { createServer as createViteServer } from "vite";
import { 
  dbInstance, 
  seedWorkspaceForUser, 
  encryptSecret, 
  decryptSecret,
  User,
  List,
  Lead,
  Company,
  ListItem
} from "./server/db";

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "BAM_ROCKET_JWT_ACC_PASS_TOKEN";

app.use(express.json());

// Enable CORS and cookie sharing support for frames
app.use((req, res, next) => {
  const origin = req.headers.origin || "*";
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

// Helper: parse cookies from headers to support sameSite=none httpOnly session cookie
function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const list: Record<string, string> = {};
  if (!cookieHeader) return list;
  cookieHeader.split(";").forEach((cookie) => {
    const parts = cookie.trim().split("=");
    if (parts.length >= 2) {
      list[parts[0]] = parts.slice(1).join("=");
    }
  });
  return list;
}

// JWT Auth Middleware
function requireAuth(req: any, res: any, next: any) {
  let token = "";
  
  // 1. Try Authorization header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    token = authHeader.substring(7);
  } else {
    // 2. Try cookie
    const cookies = parseCookies(req.headers.cookie);
    if (cookies.token) {
      token = cookies.token;
    }
  }

  if (!token) {
    return res.status(401).json({ error: "Unauthorized. Missing authentication token." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { userId: string; workspaceId: string };
    req.userId = decoded.userId;
    req.workspaceId = decoded.workspaceId;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid, expired, or corrupted token." });
  }
}

// --- 1. AUTH ROUTES ---

app.post("/api/auth/register", async (req: any, res: any) => {
  const { fullName, email, password } = req.body;

  if (!fullName || !email || !password) {
    return res.status(400).json({ error: "Missing required registration parameters." });
  }

  // Simple validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: "Invalid email address format." });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: "Password must consist of at least 6 characters." });
  }

  // Exists?
  const existingUser = dbInstance.getTable("users").find(u => u.email.toLowerCase() === email.toLowerCase());
  if (existingUser) {
    return res.status(400).json({ error: "A user with this email address already exists." });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const userId = `usr_${Math.random().toString(36).substr(2, 9)}`;
    const workspaceId = `wsp_${Math.random().toString(36).substr(2, 9)}`;

    const newUser: User = {
      id: userId,
      fullName,
      email: email.toLowerCase(),
      passwordHash,
      avatarUrl: `https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=120&auto=format&fit=crop&q=80`,
      role: "Owner",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    dbInstance.insert("users", newUser);

    // Create default workspace
    dbInstance.insert("workspaces", {
      id: workspaceId,
      name: `${fullName}'s Workspace`,
      ownerId: userId,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    });

    dbInstance.insert("workspaceMembers", {
      id: `m_${userId}_${workspaceId}`,
      workspaceId,
      userId,
      role: "Owner",
      createdAt: new Date().toISOString()
    });

    // Seed demographic user-specific data (100 people, 50 companies, lists, deals)
    seedWorkspaceForUser(userId, workspaceId);

    // Issue token
    const token = jwt.sign({ userId, workspaceId }, JWT_SECRET, { expiresIn: "7d" });

    // SameSite=None + Secure config for sub-iframe security
    res.setHeader("Set-Cookie", `token=${token}; Path=/; HttpOnly; SameSite=None; Secure; Max-Age=${7 * 24 * 60 * 60}`);
    return res.status(201).json({ token, user: { id: userId, fullName, email: newUser.email, avatarUrl: newUser.avatarUrl, role: newUser.role, workspaceId } });
  } catch (error) {
    return res.status(500).json({ error: "An error occurred during registration." });
  }
});

app.post("/api/auth/login", async (req: any, res: any) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Missing email or password credentials." });
  }

  let user = dbInstance.getTable("users").find(u => u.email.toLowerCase() === email.toLowerCase());
  
  // If user does not exist, dynamically registration-falls-back to provision and connect their workspace!
  if (!user) {
    try {
      const passwordHash = await bcrypt.hash(password, 10);
      const userId = `usr_${Math.random().toString(36).substr(2, 9)}`;
      const workspaceId = `wsp_${Math.random().toString(36).substr(2, 9)}`;
      const fullName = email.split('@')[0].split(/[._-]/).map((s: string) => s.charAt(0).toUpperCase() + s.slice(1)).join(' ') || "Operator Node";

      const newUser: User = {
        id: userId,
        fullName,
        email: email.toLowerCase(),
        passwordHash,
        avatarUrl: `https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=120&auto=format&fit=crop&q=80`,
        role: "Owner",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      dbInstance.insert("users", newUser);

      // Create default workspace
      dbInstance.insert("workspaces", {
        id: workspaceId,
        name: `${fullName}'s Workspace`,
        ownerId: userId,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      });

      dbInstance.insert("workspaceMembers", {
        id: `m_${userId}_${workspaceId}`,
        workspaceId,
        userId,
        role: "Owner",
        createdAt: new Date().toISOString()
      });

      // Seed demographic user-specific data (100 people, 50 companies, lists, deals)
      seedWorkspaceForUser(userId, workspaceId);

      // Issue token
      const token = jwt.sign({ userId, workspaceId }, JWT_SECRET, { expiresIn: "7d" });

      res.setHeader("Set-Cookie", `token=${token}; Path=/; HttpOnly; SameSite=None; Secure; Max-Age=${7 * 24 * 60 * 60}`);
      return res.status(201).json({ token, user: { id: userId, fullName, email: newUser.email, avatarUrl: newUser.avatarUrl, role: newUser.role, workspaceId } });
    } catch (provisionErr) {
      console.error("Auto-provisioning failed:", provisionErr);
      return res.status(500).json({ error: "Failed to automatically provision private workspace." });
    }
  }

  try {
    const isMatched = await bcrypt.compare(password, user.passwordHash);
    if (!isMatched) {
      return res.status(400).json({ error: "Invalid credentials." });
    }

    // Find workspace membership
    const member = dbInstance.getTable("workspaceMembers").find(m => m.userId === user.id);
    const workspaceId = member ? member.workspaceId : "";

    const token = jwt.sign({ userId: user.id, workspaceId }, JWT_SECRET, { expiresIn: "7d" });

    res.setHeader("Set-Cookie", `token=${token}; Path=/; HttpOnly; SameSite=None; Secure; Max-Age=${7 * 24 * 60 * 60}`);
    return res.json({ token, user: { id: user.id, fullName: user.fullName, email: user.email, avatarUrl: user.avatarUrl, role: user.role, workspaceId } });
  } catch (err) {
    return res.status(500).json({ error: "An error occurred during authentication." });
  }
});

app.post("/api/auth/logout", (req, res) => {
  res.setHeader("Set-Cookie", `token=; Path=/; HttpOnly; SameSite=None; Secure; Max-Age=0`);
  return res.json({ message: "Successfully logged out." });
});

app.get("/api/auth/me", requireAuth, (req: any, res: any) => {
  const user = dbInstance.getTable("users").find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: "User not found." });
  return res.json({ user: { id: user.id, fullName: user.fullName, email: user.email, avatarUrl: user.avatarUrl, role: user.role, workspaceId: req.workspaceId } });
});

// --- 2. USER PROFILE & SETTINGS ---

app.get("/api/user/me", requireAuth, (req: any, res: any) => {
  const user = dbInstance.getTable("users").find(u => u.id === req.userId);
  return res.json({ user });
});

app.patch("/api/user/me", requireAuth, (req: any, res: any) => {
  const { fullName, avatarUrl } = req.body;
  const updated = dbInstance.update("users", req.userId, { fullName, avatarUrl });
  return res.json({ user: updated });
});

app.patch("/api/user/password", requireAuth, async (req: any, res: any) => {
  const { currentPassword, newPassword } = req.body;
  const user = dbInstance.getTable("users").find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: "User profile doesn't exist." });

  try {
    const matches = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!matches) {
      return res.status(400).json({ error: "The current password provided is incorrect." });
    }
    const hashed = await bcrypt.hash(newPassword, 10);
    dbInstance.update("users", req.userId, { passwordHash: hashed });
    return res.json({ message: "Password updated successfully." });
  } catch (e) {
    return res.status(500).json({ error: "Database error during password reset." });
  }
});

// --- 3. WORKSPACE ENDPOINTS ---

app.get("/api/workspaces", requireAuth, (req: any, res: any) => {
  const memberships = dbInstance.getTable("workspaceMembers").filter(m => m.userId === req.userId);
  const workspaceIds = memberships.map(m => m.workspaceId);
  const workspaces = dbInstance.getTable("workspaces").filter(w => workspaceIds.includes(w.id));
  
  // Attach role for each workspace
  const workspacesWithRoles = workspaces.map(w => {
    const mem = memberships.find(m => m.workspaceId === w.id);
    return { ...w, role: mem?.role || "Member" };
  });
  
  return res.json({ workspaces: workspacesWithRoles });
});

app.post("/api/workspaces", requireAuth, (req: any, res: any) => {
  const { name } = req.body;
  const workspaceId = `wsp_${Math.random().toString(36).substr(2, 9)}`;
  const workspace = dbInstance.insert("workspaces", {
    id: workspaceId,
    name,
    ownerId: req.userId,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  });

  dbInstance.insert("workspaceMembers", {
    id: `m_${req.userId}_${workspaceId}`,
    workspaceId,
    userId: req.userId,
    role: "Owner",
    createdAt: new Date().toISOString()
  });

  // Provision wallet
  dbInstance.insert("creditWallets", {
    id: `wallet_${req.userId}_${workspaceId}`,
    userId: req.userId,
    workspaceId: workspaceId,
    credits: 10000,
    updatedAt: new Date().toISOString()
  });

  return res.json({ workspace });
});

app.post("/api/workspaces/:id/switch", requireAuth, (req: any, res: any) => {
  // Switch workspace token
  const targetId = req.params.id;
  const mem = dbInstance.getTable("workspaceMembers").find(m => m.userId === req.userId && m.workspaceId === targetId);
  if (!mem) return res.status(403).json({ error: "Access denied." });

  const token = jwt.sign({ userId: req.userId, workspaceId: targetId }, JWT_SECRET, { expiresIn: "7d" });
  res.setHeader("Set-Cookie", `token=${token}; Path=/; HttpOnly; SameSite=None; Secure; Max-Age=${7 * 24 * 60 * 60}`);
  
  const user = dbInstance.getTable("users").find(u => u.id === req.userId);
  return res.json({ token, user: { ...user, workspaceId: targetId } });
});

app.post("/api/workspaces/:id/invite", requireAuth, (req: any, res: any) => {
  const { email, role } = req.body;
  // Simplified invite flow
  let user = dbInstance.getTable("users").find(u => u.email.toLowerCase() === email.toLowerCase());
  let userId;
  if (!user) {
    // Create placeholder dummy user 
    userId = `usr_${Math.random().toString(36).substr(2, 9)}`;
    const pass = Math.random().toString(36).substr(2, 10);
    const hash = bcrypt.hashSync(pass, 10);
    dbInstance.insert("users", {
        id: userId,
        fullName: email.split('@')[0],
        email: email.toLowerCase(),
        passwordHash: hash,
        avatarUrl: `https://images.unsplash.com/photo-1544005313-94ddf0286df2?w=120`,
        role: "Member",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
    });
  } else {
    userId = user.id;
  }
  
  dbInstance.insert("workspaceMembers", {
    id: `m_${userId}_${req.params.id}`,
    workspaceId: req.params.id,
    userId: userId,
    role: role || "Member",
    createdAt: new Date().toISOString()
  });
  
  return res.json({ success: true, message: "Invited successfully" });
});

app.get("/api/workspace/current", requireAuth, (req: any, res: any) => {
  const wsp = dbInstance.getTable("workspaces").find(w => w.id === req.workspaceId);
  return res.json({ workspace: wsp });
});

app.patch("/api/workspace/current", requireAuth, (req: any, res: any) => {
  const { name } = req.body;
  const updated = dbInstance.update("workspaces", req.workspaceId, { name });
  return res.json({ workspace: updated });
});

// --- 4. CREDIT HISTORY & HISTORY ENDPOINTS ---

app.get("/api/credits", requireAuth, (req: any, res: any) => {
  let wallet = dbInstance.getTable("creditWallets").find(w => w.userId === req.userId && w.workspaceId === req.workspaceId);
  if (!wallet) {
    wallet = dbInstance.insert("creditWallets", {
      id: `wallet_${req.userId}`,
      userId: req.userId,
      workspaceId: req.workspaceId,
      credits: 16939,
      updatedAt: new Date().toISOString()
    });
  }
  return res.json({ wallet });
});

app.get("/api/credits/usage", requireAuth, (req: any, res: any) => {
  const usages = dbInstance.getTable("creditUsages")
    .filter(u => u.userId === req.userId && u.workspaceId === req.workspaceId)
    .sort((a,b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  return res.json({ usage: usages });
});

// --- 5. CRM SAVED FILTERS & RECENT SEARCHES ---

app.get("/api/saved-filters", requireAuth, (req: any, res: any) => {
  const filters = dbInstance.getTable("savedFilters").filter(f => f.userId === req.userId);
  return res.json({ filters });
});

app.post("/api/saved-filters", requireAuth, (req: any, res: any) => {
  const { name, type, filtersJson } = req.body;
  const sf = dbInstance.insert("savedFilters", {
    id: `sf_${Math.random().toString(36).substr(2, 9)}`,
    userId: req.userId,
    workspaceId: req.workspaceId,
    name,
    type,
    filtersJson: typeof filtersJson === 'string' ? filtersJson : JSON.stringify(filtersJson),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  });
  return res.json(sf);
});

app.patch("/api/saved-filters/:id", requireAuth, (req: any, res: any) => {
  const updated = dbInstance.update("savedFilters", req.params.id, req.body);
  return res.json(updated);
});

app.delete("/api/saved-filters/:id", requireAuth, (req: any, res: any) => {
  dbInstance.delete("savedFilters", req.params.id);
  return res.json({ success: true });
});

app.get("/api/recent-searches", requireAuth, (req: any, res: any) => {
  const searches = dbInstance.getTable("recentSearches")
    .filter(s => s.userId === req.userId)
    .sort((a,b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  return res.json({ searches });
});

app.delete("/api/recent-searches/:id", requireAuth, (req: any, res: any) => {
  dbInstance.delete("recentSearches", req.params.id);
  return res.json({ success: true });
});

app.delete("/api/recent-searches", requireAuth, (req: any, res: any) => {
  const arr = dbInstance.getTable("recentSearches");
  dbInstance.save(); 
  return res.json({ success: true });
});

// --- 6. LEADS (PEOPLE) CRUD ---

app.get("/api/leads", requireAuth, (req: any, res: any) => {
  const leads = dbInstance.getTable("leads").filter(l => l.userId === req.userId && l.workspaceId === req.workspaceId);
  return res.json({ leads });
});

app.post("/api/leads", requireAuth, (req: any, res: any) => {
  const leadData = req.body;
  const lead: Lead = dbInstance.insert("leads", {
    ...leadData,
    id: `lead_${Math.random().toString(36).substr(2, 9)}`,
    userId: req.userId,
    workspaceId: req.workspaceId,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  });
  return res.json(lead);
});

app.get("/api/leads/:id", requireAuth, (req: any, res: any) => {
  const lead = dbInstance.getTable("leads").find(l => l.id === req.params.id && l.userId === req.userId);
  if (!lead) return res.status(404).json({ error: "Lead not found." });
  return res.json(lead);
});

app.patch("/api/leads/:id", requireAuth, (req: any, res: any) => {
  const updated = dbInstance.update("leads", req.params.id, req.body);
  return res.json(updated);
});

app.delete("/api/leads/:id", requireAuth, (req: any, res: any) => {
  dbInstance.delete("leads", req.params.id);
  return res.json({ success: true });
});

app.post("/api/leads/export", requireAuth, (req: any, res: any) => {
  const { leadIds } = req.body;
  const allLeads = dbInstance.getTable("leads").filter(l => l.userId === req.userId && l.workspaceId === req.workspaceId);
  const selected = leadIds ? allLeads.filter(l => leadIds.includes(l.id)) : allLeads;

  let csv = "Full Name,Title,Seniority,Department,Email,Email Status,Phone,Location,Company,Company Domain,Industry,Buying Intent,Notes\n";
  selected.forEach(l => {
    csv += `"${l.fullName}","${l.title}","${l.seniority}","${l.department}","${l.email}","${l.emailStatus}","${l.phone}","${l.location}","${l.companyName}","${l.companyDomain}","${l.industry}","${l.buyingIntent}","${l.notes.replace(/"/g, '""')}"\n`;
  });
  return res.json({ csv });
});

app.post("/api/leads/enrich", requireAuth, (req: any, res: any) => {
  const { leadIds } = req.body;
  if (!leadIds || !leadIds.length) return res.status(400).json({ error: "No leads specified for enrichment." });

  // Verify wallet
  const wallet = dbInstance.getTable("creditWallets").find(w => w.userId === req.userId);
  if (!wallet || wallet.credits < leadIds.length * 15) {
    return res.status(400).json({ error: "Insufficient CRM credit balances to enrich selected leads." });
  }

  // Charge
  wallet.credits -= leadIds.length * 15;
  dbInstance.insert("creditUsages", {
    id: `cu_${Math.random().toString(36).substr(2, 9)}`,
    userId: req.userId,
    workspaceId: req.workspaceId,
    action: "Enrichment Service Trigger",
    amount: leadIds.length * 15,
    description: `Contact detail extraction for ${leadIds.length} leads`,
    createdAt: new Date().toISOString()
  });

  // Enrich
  const enriched: any[] = [];
  leadIds.forEach((id: string) => {
    const updated = dbInstance.update("leads", id, {
      emailStatus: "Verified",
      phone: `+1 (555) 732-${Math.floor(1000 + Math.random() * 9000)}`,
      leadScore: Math.min(100, Math.floor(70 + Math.random() * 28)),
      buyingIntent: "High"
    });
    if (updated) enriched.push(updated);
  });

  return res.json({ success: true, count: enriched.length, enriched });
});

// --- 7. COMPANIES CRUD ---

app.get("/api/companies", requireAuth, (req: any, res: any) => {
  const comps = dbInstance.getTable("companies").filter(c => c.userId === req.userId && c.workspaceId === req.workspaceId);
  return res.json({ companies: comps });
});

app.post("/api/companies", requireAuth, (req: any, res: any) => {
  const comp = dbInstance.insert("companies", {
    ...req.body,
    id: `company_${Math.random().toString(36).substr(2, 9)}`,
    userId: req.userId,
    workspaceId: req.workspaceId,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  });
  return res.json(comp);
});

app.get("/api/companies/:id", requireAuth, (req: any, res: any) => {
  const comp = dbInstance.getTable("companies").find(c => c.id === req.params.id && c.userId === req.userId);
  if (!comp) return res.status(404).json({ error: "Company profile not found." });
  return res.json(comp);
});

app.patch("/api/companies/:id", requireAuth, (req: any, res: any) => {
  const updated = dbInstance.update("companies", req.params.id, req.body);
  return res.json(updated);
});

app.delete("/api/companies/:id", requireAuth, (req: any, res: any) => {
  dbInstance.delete("companies", req.params.id);
  return res.json({ success: true });
});

app.post("/api/companies/export", requireAuth, (req: any, res: any) => {
  const { companyIds } = req.body;
  const allComps = dbInstance.getTable("companies").filter(c => c.userId === req.userId && c.workspaceId === req.workspaceId);
  const selected = companyIds ? allComps.filter(c => companyIds.includes(c.id)) : allComps;

  let csv = "Company Name,Domain,Industry,Employees,Revenue,City,Country,Founded,Description,Buying Intent\n";
  selected.forEach(c => {
    csv += `"${c.companyName}","${c.domain}","${c.industry}","${c.employees}","${c.revenue}","${c.city}","${c.country}",${c.foundedYear},"${c.description.replace(/"/g, '""')}","${c.buyingIntent}"\n`;
  });
  return res.json({ csv });
});

app.post("/api/companies/enrich", requireAuth, (req: any, res: any) => {
  const { companyIds } = req.body;
  if (!companyIds || !companyIds.length) return res.status(400).json({ error: "No companies specified for enrichment." });

  const wallet = dbInstance.getTable("creditWallets").find(w => w.userId === req.userId);
  if (!wallet || wallet.credits < companyIds.length * 20) {
    return res.status(400).json({ error: "Insufficient available credits to enrich selected companies." });
  }

  wallet.credits -= companyIds.length * 20;
  dbInstance.insert("creditUsages", {
    id: `cu_${Math.random().toString(36).substr(2, 9)}`,
    userId: req.userId,
    workspaceId: req.workspaceId,
    action: "Company Profile Enriched",
    amount: companyIds.length * 20,
    description: `Deep company signals extraction for ${companyIds.length} accounts`,
    createdAt: new Date().toISOString()
  });

  const enriched: any[] = [];
  companyIds.forEach((id: string) => {
    const updated = dbInstance.update("companies", id, {
      companyScore: Math.min(100, Math.floor(75 + Math.random() * 25)),
      buyingIntent: "High",
      foundedYear: 2005 + Math.floor(Math.random() * 15)
    });
    if (updated) enriched.push(updated);
  });

  return res.json({ success: true, count: enriched.length, enriched });
});

// --- 8. LISTS DIRECTORY ENDPOINTS ---

app.get("/api/lists", requireAuth, (req: any, res: any) => {
  const userLists = dbInstance.getTable("lists").filter(l => l.userId === req.userId && l.workspaceId === req.workspaceId);
  return res.json({ lists: userLists });
});

app.post("/api/lists", requireAuth, (req: any, res: any) => {
  const { name, type } = req.body;
  const list: List = dbInstance.insert("lists", {
    id: `list_${Math.random().toString(36).substr(2, 9)}`,
    userId: req.userId,
    workspaceId: req.workspaceId,
    name,
    type,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  });
  return res.json(list);
});

app.get("/api/lists/:id", requireAuth, (req: any, res: any) => {
  const list = dbInstance.getTable("lists").find(l => l.id === req.params.id && l.userId === req.userId);
  if (!list) return res.status(404).json({ error: "List not found." });
  
  // Get items
  const items = dbInstance.getTable("listItems").filter(i => i.listId === list.id);
  return res.json({ list, items });
});

app.patch("/api/lists/:id", requireAuth, (req: any, res: any) => {
  const updated = dbInstance.update("lists", req.params.id, req.body);
  return res.json(updated);
});

app.delete("/api/lists/:id", requireAuth, (req: any, res: any) => {
  dbInstance.delete("lists", req.params.id);
  // Clear items
  const items = dbInstance.getTable("listItems");
  const filtered = items.filter(x => x.listId !== req.params.id);
  // manual clear and assign
  (dbInstance.getTable("listItems") as any[]).length = 0;
  filtered.forEach(item => dbInstance.getTable("listItems").push(item));
  dbInstance.save();

  return res.json({ success: true });
});

app.post("/api/lists/:id/items", requireAuth, (req: any, res: any) => {
  const { leadId, companyId } = req.body;
  const item: ListItem = dbInstance.insert("listItems", {
    id: `li_${Math.random().toString(36).substr(2, 9)}`,
    listId: req.params.id,
    leadId,
    companyId,
    createdAt: new Date().toISOString()
  });
  return res.json(item);
});

app.delete("/api/lists/:id/items/:itemId", requireAuth, (req: any, res: any) => {
  dbInstance.delete("listItems", req.params.itemId);
  return res.json({ success: true });
});

// --- 9. OUTREACH CAMPAIGNS ---

app.get("/api/campaigns", requireAuth, (req: any, res: any) => {
  const camps = dbInstance.getTable("campaigns").filter(c => c.userId === req.userId);
  return res.json({ campaigns: camps });
});

app.post("/api/campaigns", requireAuth, (req: any, res: any) => {
  const { name, type, targetListId } = req.body;
  const camp = dbInstance.insert("campaigns", {
    id: `camp_${Math.random().toString(36).substr(2, 9)}`,
    userId: req.userId,
    workspaceId: req.workspaceId,
    name,
    status: "Paused",
    type,
    targetListId,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  });
  return res.json(camp);
});

app.get("/api/campaigns/:id", requireAuth, (req: any, res: any) => {
  const camp = dbInstance.getTable("campaigns").find(c => c.id === req.params.id && c.userId === req.userId);
  if (!camp) return res.status(404).json({ error: "Campaign not found" });
  return res.json(camp);
});

app.patch("/api/campaigns/:id", requireAuth, (req: any, res: any) => {
  const updated = dbInstance.update("campaigns", req.params.id, req.body);
  return res.json(updated);
});

app.delete("/api/campaigns/:id", requireAuth, (req: any, res: any) => {
  dbInstance.delete("campaigns", req.params.id);
  return res.json({ success: true });
});

// --- 10. DEALS PIPELINE ---

app.get("/api/deals", requireAuth, (req: any, res: any) => {
  const Dl = dbInstance.getTable("deals").filter(d => d.userId === req.userId);
  return res.json({ deals: Dl });
});

app.post("/api/deals", requireAuth, (req: any, res: any) => {
  const d = dbInstance.insert("deals", {
    ...req.body,
    id: `deal_${Math.random().toString(36).substr(2, 9)}`,
    userId: req.userId,
    workspaceId: req.workspaceId,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  });
  return res.json(d);
});

app.patch("/api/deals/:id", requireAuth, (req: any, res: any) => {
  const updated = dbInstance.update("deals", req.params.id, req.body);
  return res.json(updated);
});

app.delete("/api/deals/:id", requireAuth, (req: any, res: any) => {
  dbInstance.delete("deals", req.params.id);
  return res.json({ success: true });
});

// --- 11. UNIBOX INBOX MESSAGES ---

app.get("/api/inbox", requireAuth, (req: any, res: any) => {
  const msgs = dbInstance.getTable("inboxMessages").filter(m => m.userId === req.userId);
  const leads = dbInstance.getTable("leads").filter(l => l.userId === req.userId);

  const mappedMsgs = msgs.map((m: any) => {
    // Standardize isRead
    const isRead = m.read !== undefined ? m.read : (m.isRead !== undefined ? m.isRead : true);
    
    // Find matching lead to populate senderName and companyName
    const matchingLead = leads.find(l => l.email && m.sender && l.email.toLowerCase() === m.sender.toLowerCase());
    
    let senderName = m.senderName;
    let companyName = m.companyName;
    
    if (!senderName) {
      if (matchingLead) {
        senderName = matchingLead.fullName || `${matchingLead.firstName} ${matchingLead.lastName}`;
      } else if (m.sender) {
        // Fallback: derive from email (e.g., satya.nadella@microsoft.com -> Satya Nadella)
        const emailParts = m.sender.split("@");
        if (emailParts.length === 2) {
          const namePart = emailParts[0];
          senderName = namePart
            .split(".")
            .map((part: string) => part.charAt(0).toUpperCase() + part.slice(1))
            .join(" ");
        } else {
          senderName = m.sender;
        }
      } else {
        senderName = "Unknown Sender";
      }
    }

    if (!companyName) {
      if (matchingLead) {
        companyName = matchingLead.companyName;
      } else if (m.sender) {
        const emailParts = m.sender.split("@");
        if (emailParts.length === 2) {
          const domain = emailParts[1];
          const name = domain.split(".")[0];
          companyName = name.charAt(0).toUpperCase() + name.slice(1);
        } else {
          companyName = "Unknown Company";
        }
      } else {
        companyName = "Unknown Company";
      }
    }

    const unmappedStatus = m.status || (isRead ? "Read" : "Unread");

    return {
      ...m,
      senderName,
      senderEmail: m.sender || m.senderEmail,
      companyName,
      isRead,
      unread: !isRead,
      timestamp: m.timestamp || m.createdAt || new Date().toISOString(),
      status: unmappedStatus
    };
  });

  return res.json({ messages: mappedMsgs });
});

app.patch("/api/inbox/:id", requireAuth, (req: any, res: any) => {
  const updated = dbInstance.update("inboxMessages", req.params.id, req.body);
  return res.json(updated);
});

app.post("/api/inbox/:id/reply", requireAuth, (req: any, res: any) => {
  const { body } = req.body;
  const parent = dbInstance.getTable("inboxMessages").find(m => m.id === req.params.id);
  if (!parent) return res.status(404).json({ error: "Thread not found." });

  // Add outgoing message mimicking reply
  const reply = dbInstance.insert("inboxMessages", {
    id: `msg_${Math.random().toString(36).substr(2, 9)}`,
    userId: req.userId,
    workspaceId: req.workspaceId,
    provider: parent.provider,
    sender: "user@bamrocket.com",
    recipient: parent.sender,
    subject: parent.subject.startsWith("Re:") ? parent.subject : `Re: ${parent.subject}`,
    body,
    read: true,
    archived: false,
    createdAt: new Date().toISOString()
  });

  return res.json(reply);
});

// --- 12. AI KNOWLEDGE BASE ---

app.get("/api/knowledge", requireAuth, (req: any, res: any) => {
  const items = dbInstance.getTable("knowledgeItems").filter(k => k.userId === req.userId);
  return res.json({ knowledge: items });
});

app.post("/api/knowledge", requireAuth, (req: any, res: any) => {
  const item = dbInstance.insert("knowledgeItems", {
    ...req.body,
    id: `knowledge_${Math.random().toString(36).substr(2, 9)}`,
    userId: req.userId,
    workspaceId: req.workspaceId,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  });
  return res.json(item);
});

app.patch("/api/knowledge/:id", requireAuth, (req: any, res: any) => {
  const updated = dbInstance.update("knowledgeItems", req.params.id, req.body);
  return res.json(updated);
});

app.delete("/api/knowledge/:id", requireAuth, (req: any, res: any) => {
  dbInstance.delete("knowledgeItems", req.params.id);
  return res.json({ success: true });
});

// --- 13. GENERATIVE BOT OPERATOR AGENTS ---

app.get("/api/agents", requireAuth, (req: any, res: any) => {
  const ags = dbInstance.getTable("agents").filter(a => a.userId === req.userId);
  return res.json({ agents: ags });
});

app.post("/api/agents", requireAuth, (req: any, res: any) => {
  const ag = dbInstance.insert("agents", {
    ...req.body,
    id: `agent_${Math.random().toString(36).substr(2, 9)}`,
    userId: req.userId,
    workspaceId: req.workspaceId,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  });
  return res.json(ag);
});

app.patch("/api/agents/:id", requireAuth, (req: any, res: any) => {
  const updated = dbInstance.update("agents", req.params.id, req.body);
  return res.json(updated);
});

app.delete("/api/agents/:id", requireAuth, (req: any, res: any) => {
  dbInstance.delete("agents", req.params.id);
  return res.json({ success: true });
});

// --- 14. AUTHENTIC SOCIAL OAUTH INTEGRATIONS ---

// Secure endpoint checking status
app.get("/api/integrations", requireAuth, (req: any, res: any) => {
  const accounts = dbInstance.getTable("connectedAccounts").filter(a => a.userId === req.userId);
  const response = {
    linkedin: accounts.find(a => a.provider === "linkedin") ? { connected: true, scopes: ["r_liteprofile", "w_member_social"] } : { connected: false },
    facebook: accounts.find(a => a.provider === "facebook") ? { connected: true, scopes: ["public_profile", "ads_management"] } : { connected: false }
  };
  return res.json(response);
});

// A. LinkedIn OAuth Endpoints
app.get("/api/integrations/linkedin/connect", (req: any, res: any) => {
  const redirectUri = `${req.protocol}://${req.get("host")}/api/integrations/linkedin/callback`;
  const clientId = process.env.LINKEDIN_CLIENT_ID || "MOCK_LINKEDIN_ID";
  // Generates genuine popup ready authorization trigger url
  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    state: req.query.state || "BAM_ROCKET_SEC_STATE",
    scope: "r_liteprofile w_member_social"
  });
  res.redirect(`https://www.linkedin.com/oauth/v2/authorization?${params.toString()}`);
});

app.get("/api/integrations/linkedin/callback", (req: any, res: any) => {
  const { code, state } = req.query;
  // This executes postMessage in popup notifying parent success and triggers auto close
  return res.send(`
    <html>
      <body style="background: #070913; color: white; font-family: sans-serif; text-align: center; padding-top: 50px;">
        <h2 style="color: #4f46e5;">BAM Rocket Social Core Connect</h2>
        <p>Syncing LinkedIn permissions cleanly with your user pipeline...</p>
        <script>
          if (window.opener) {
            window.opener.postMessage({ type: "OAUTH_AUTH_SUCCESS", provider: "linkedin", code: "${code}" }, "*");
            window.close();
          } else {
            window.location.href = "/";
          }
        </script>
      </body>
    </html>
  `);
});

// Mock connect directly inside authenticated session, encrypting credentials securely
app.post("/api/integrations/linkedin/connect-success", requireAuth, (req: any, res: any) => {
  const encAccessToken = encryptSecret(`linkedin_access_token_${Math.random().toString(36).substr(2)}`);
  const encRefreshToken = encryptSecret(`linkedin_refresh_token_${Math.random().toString(36).substr(2)}`);
  
  const connected = dbInstance.insert("connectedAccounts", {
    id: `acc_li_${req.userId}`,
    userId: req.userId,
    workspaceId: req.workspaceId,
    provider: "linkedin",
    providerUserId: "linkedin_user_id_seed",
    accessTokenEncrypted: encAccessToken,
    refreshTokenEncrypted: encRefreshToken,
    tokenExpiresAt: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString(),
    scopes: ["r_liteprofile", "w_member_social"],
    connectedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  });

  return res.json({ success: true, connected });
});

app.post("/api/integrations/linkedin/disconnect", requireAuth, (req: any, res: any) => {
  const accounts = dbInstance.getTable("connectedAccounts");
  const filtered = accounts.filter(a => !(a.userId === req.userId && a.provider === "linkedin"));
  (dbInstance.getTable("connectedAccounts") as any[]).length = 0;
  filtered.forEach(item => dbInstance.getTable("connectedAccounts").push(item));
  dbInstance.save();
  return res.json({ success: true });
});

// B. Facebook OAuth Endpoints
app.get("/api/integrations/facebook/connect", (req: any, res: any) => {
  const redirectUri = `${req.protocol}://${req.get("host")}/api/integrations/facebook/callback`;
  const appId = process.env.FACEBOOK_APP_ID || "MOCK_FB_APP_ID";
  const params = new URLSearchParams({
    client_id: appId,
    redirect_uri: redirectUri,
    state: req.query.state || "BAM_ROCKET_FB_STATE",
    scope: "public_profile,ads_management"
  });
  res.redirect(`https://www.facebook.com/v12.0/dialog/oauth?${params.toString()}`);
});

app.get("/api/integrations/facebook/callback", (req: any, res: any) => {
  const { code, state } = req.query;
  return res.send(`
    <html>
      <body style="background: #070913; color: white; font-family: sans-serif; text-align: center; padding-top: 50px;">
        <h2 style="color: #4f46e5;">BAM Rocket Social Core Connect</h2>
        <p>Syncing Facebook permissions cleanly with your user pipeline...</p>
        <script>
          if (window.opener) {
            window.opener.postMessage({ type: "OAUTH_AUTH_SUCCESS", provider: "facebook", code: "${code}" }, "*");
            window.close();
          } else {
            window.location.href = "/";
          }
        </script>
      </body>
    </html>
  `);
});

app.post("/api/integrations/facebook/connect-success", requireAuth, (req: any, res: any) => {
  const encAccessToken = encryptSecret(`facebook_access_token_${Math.random().toString(36).substr(2)}`);
  const encRefreshToken = encryptSecret(`facebook_refresh_token_${Math.random().toString(36).substr(2)}`);
  
  const connected = dbInstance.insert("connectedAccounts", {
    id: `acc_fb_${req.userId}`,
    userId: req.userId,
    workspaceId: req.workspaceId,
    provider: "facebook",
    providerUserId: "facebook_user_id_seed",
    accessTokenEncrypted: encAccessToken,
    refreshTokenEncrypted: encRefreshToken,
    tokenExpiresAt: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString(),
    scopes: ["public_profile", "ads_management"],
    connectedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  });

  return res.json({ success: true, connected });
});

app.post("/api/integrations/facebook/disconnect", requireAuth, (req: any, res: any) => {
  const accounts = dbInstance.getTable("connectedAccounts");
  const filtered = accounts.filter(a => !(a.userId === req.userId && a.provider === "facebook"));
  (dbInstance.getTable("connectedAccounts") as any[]).length = 0;
  filtered.forEach(item => dbInstance.getTable("connectedAccounts").push(item));
  dbInstance.save();
  return res.json({ success: true });
});


// --- 15. SERVER-SIDE GEMINI POWERED INTELLIGENCE API ---

// Lazy initialization of GoogleGenAI
let aiClient: GoogleGenAI | null = null;
function getAIClient(): GoogleGenAI {
  if (!aiClient) {
    const key = process.env.GEMINI_API_KEY;
    if (!key) {
      console.warn("⚠️ GEMINI_API_KEY is not configured! Defaulting to intelligent sandbox simulator.");
    }
    aiClient = new GoogleGenAI({
      apiKey: key || "MOCK_STUB_KEY",
      httpOptions: {
        headers: { 'User-Agent': 'aistudio-build' }
      }
    });
  }
  return aiClient;
}

app.post("/api/ai/icp-builder", requireAuth, async (req: any, res: any) => {
  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error: "Missing prompt parameter." });

  const ai = getAIClient();
  const apiKeyExists = !!process.env.GEMINI_API_KEY;

  let icp = {
    name: "Generated ICP",
    filters: {
      title: "", seniority: "All", department: "All", country: "All",
      industry: "All", companySize: "All"
    },
    recommendations: ["Target companies with high growth", "Look for Series A funding", "Roles with 'Innovation'"]
  };

  if (apiKeyExists) {
    try {
      const response = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents: `Analyze this ideal customer profile description and extract definitive filters and 3 strategic recommendations.
        Schema:
        {
          "name": "string (A punchy title for this ICP)",
          "filters": {
            "title": "string",
            "seniority": "string (All, C-Suite, Director, Manager, Senior)",
            "department": "string (All, Engineering, Marketing, Sales, Product)",
            "country": "string",
            "industry": "string",
            "companySize": "string (All, 1-10, 11-50, 51-200, 201-500, 500+)"
          },
          "recommendations": ["string", "string", "string"]
        }
        
        Profile Description: "${prompt}"`,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              name: { type: Type.STRING },
              filters: {
                type: Type.OBJECT,
                properties: {
                  title: { type: Type.STRING },
                  seniority: { type: Type.STRING },
                  department: { type: Type.STRING },
                  country: { type: Type.STRING },
                  industry: { type: Type.STRING },
                  companySize: { type: Type.STRING }
                }
              },
              recommendations: { type: Type.ARRAY, items: { type: Type.STRING } }
            }
          }
        }
      });
      icp = JSON.parse(response.text.trim());
    } catch (e) {
      console.error("ICP Generator failed", e);
    }
  } else {
    // Basic fallback logic
    icp.name = prompt.slice(0, 30) + "... ICP";
    if (prompt.toLowerCase().includes("software")) icp.filters.industry = "SaaS";
    if (prompt.toLowerCase().includes("ceo")) icp.filters.seniority = "C-Suite";
    icp.recommendations = ["Consider looking at closely related adjacent industries.", "Target individuals with buying power.", "Search for related keywords in technologies."];
  }

  // Generate an ID and save to local mock if we wanted (or just return it to client to save)
  return res.json({ icp });
});
app.post("/api/ai/lead-search", requireAuth, async (req: any, res: any) => {
  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error: "Missing prompt parameter." });

  const ai = getAIClient();
  const apiKeyExists = !!process.env.GEMINI_API_KEY;

  let extractedFilters = {
    title: "", seniority: "All", department: "All", country: "All",
    city: "", industry: "All", companySize: "All", revenue: "All",
    technologies: [] as string[], buyingIntent: "All"
  };

  if (apiKeyExists) {
    try {
      const response = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents: `Analyze the user's natural language B2B prospect search query and extract structured filter key-value pairs matching this exact JSON schema:
        {
          "title": "string (the exact job title or empty)",
          "seniority": "string (one of: All, C-Suite, Director, Manager, Senior, Entry-level)",
          "department": "string (one of: All, Engineering, Marketing, Sales, Product, Founder, Operations)",
          "country": "string (one of: All, USA, Germany, United Kingdom, Albania, Kosovo, Canada)",
          "city": "string (exact city or empty)",
          "industry": "string (one of: All, SaaS, Construction, Financial Services, Healthcare, E-Commerce, Cybersecurity, AI Research, Real Estate)",
          "companySize": "string (one of: All, 1-10, 11-50, 51-200, 201-500, 500+)",
          "revenue": "string (one of: All, Under 1M, 1M-10M, 10M-50M, 50M-100M, 100M+)",
          "technologies": ["string array"],
          "buyingIntent": "string (one of: All, High, Medium, Low, None)"
        }
        
        User Query: "${prompt}"`,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              title: { type: Type.STRING },
              seniority: { type: Type.STRING },
              department: { type: Type.STRING },
              country: { type: Type.STRING },
              city: { type: Type.STRING },
              industry: { type: Type.STRING },
              companySize: { type: Type.STRING },
              revenue: { type: Type.STRING },
              technologies: { type: Type.ARRAY, items: { type: Type.STRING } },
              buyingIntent: { type: Type.STRING }
            }
          }
        }
      });
      extractedFilters = JSON.parse(response.text.trim());
    } catch (e) {
      console.error("Gemini failed, falling back to regex heuristic parser", e);
    }
  }

  // Double check fallback if Gemini key is missing or errored
  if (!extractedFilters.title) {
    const textLower = prompt.toLowerCase();
    if (textLower.includes("founder") || textLower.includes("ceo")) {
      extractedFilters.title = "Founder";
      extractedFilters.seniority = "C-Suite";
    }
    if (textLower.includes("marketing")) {
      extractedFilters.department = "Marketing";
    }
    if (textLower.includes("engineer") || textLower.includes("developer")) {
      extractedFilters.department = "Engineering";
    }
    if (textLower.includes("germany") || textLower.includes("munich")) {
      extractedFilters.country = "Germany";
    }
    if (textLower.includes("albania") || textLower.includes("tirana")) {
      extractedFilters.country = "Albania";
    }
    if (textLower.includes("saas")) {
      extractedFilters.industry = "SaaS";
    }
    if (textLower.includes("shopify")) {
      extractedFilters.technologies = ["Shopify"];
    }
    if (textLower.includes("high") || textLower.includes("warm")) {
      extractedFilters.buyingIntent = "High";
    }
  }

  // Filter current user's leads based on extracted filters
  const allLeads = dbInstance.getTable("leads").filter(l => l.userId === req.userId && l.workspaceId === req.workspaceId);
  const matching = allLeads.filter(l => {
    if (extractedFilters.title && !l.title.toLowerCase().includes(extractedFilters.title.toLowerCase())) return false;
    if (extractedFilters.seniority !== "All" && l.seniority !== extractedFilters.seniority) return false;
    if (extractedFilters.department !== "All" && l.department !== extractedFilters.department) return false;
    if (extractedFilters.country !== "All" && l.country !== extractedFilters.country) return false;
    if (extractedFilters.city && !l.city.toLowerCase().includes(extractedFilters.city.toLowerCase())) return false;
    if (extractedFilters.industry !== "All" && l.industry !== extractedFilters.industry) return false;
    if (extractedFilters.companySize !== "All" && l.employees !== extractedFilters.companySize) return false;
    if (extractedFilters.revenue !== "All" && l.revenue !== extractedFilters.revenue) return false;
    if (extractedFilters.buyingIntent !== "All" && l.buyingIntent !== extractedFilters.buyingIntent) return false;
    if (extractedFilters.technologies && extractedFilters.technologies.length > 0) {
      const leadTechs = JSON.parse(l.technologiesJson || "[]") as string[];
      const hasTech = extractedFilters.technologies.some(t => leadTechs.some(lt => lt.toLowerCase() === t.toLowerCase()));
      if (!hasTech) return false;
    }
    return true;
  });

  // Save RecentSearch
  dbInstance.insert("recentSearches", {
    id: `rs_${Math.random().toString(36).substr(2, 9)}`,
    userId: req.userId,
    workspaceId: req.workspaceId,
    type: "People",
    prompt,
    detectedFiltersJson: JSON.stringify(extractedFilters),
    resultCount: matching.length,
    createdAt: new Date().toISOString()
  });

  return res.json({ detectedFilters: extractedFilters, results: matching });
});

app.post("/api/ai/company-search", requireAuth, async (req: any, res: any) => {
  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error: "Missing prompt parameter." });

  const ai = getAIClient();
  const apiKeyExists = !!process.env.GEMINI_API_KEY;

  let extractedFilters = {
    industry: "All", country: "All", city: "", companySize: "All", revenue: "All",
    technologies: [] as string[], buyingIntent: "All"
  };

  if (apiKeyExists) {
    try {
      const response = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents: `Analyze the user's natural language B2B company search query and extract structured key-value filters matching this JSON schema:
        {
          "industry": "string (one of: All, SaaS, Construction, Financial Services, Healthcare, E-Commerce, Cybersecurity, AI Research, Real Estate)",
          "country": "string (one of: All, USA, Germany, United Kingdom, Albania, Kosovo, Canada)",
          "city": "string (exact city or empty)",
          "companySize": "string (one of: All, 1-10, 11-50, 51-200, 201-500, 500+)",
          "revenue": "string (one of: All, Under 1M, 1M-10M, 10M-50M, 50M-100M, 100M+)",
          "technologies": ["string array"],
          "buyingIntent": "string (one of: All, High, Medium, Low, None)"
        }
        
        User Query: "${prompt}"`,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              industry: { type: Type.STRING },
              country: { type: Type.STRING },
              city: { type: Type.STRING },
              companySize: { type: Type.STRING },
              revenue: { type: Type.STRING },
              technologies: { type: Type.ARRAY, items: { type: Type.STRING } },
              buyingIntent: { type: Type.STRING }
            }
          }
        }
      });
      extractedFilters = JSON.parse(response.text.trim());
    } catch (e) {
      console.error("Gemini failed, falling back to regex heuristic parser", e);
    }
  }

  // Regex Heuristics fallback
  if (extractedFilters.industry === "All") {
    const textLower = prompt.toLowerCase();
    if (textLower.includes("saas")) extractedFilters.industry = "SaaS";
    if (textLower.includes("construction") || textLower.includes("builder")) extractedFilters.industry = "Construction";
    if (textLower.includes("germany") || textLower.includes("munich")) extractedFilters.country = "Germany";
    if (textLower.includes("albania") || textLower.includes("tirana")) extractedFilters.country = "Albania";
    if (textLower.includes("shopify")) extractedFilters.technologies = ["Shopify"];
    if (textLower.includes("high") || textLower.includes("warm")) extractedFilters.buyingIntent = "High";
  }

  const allComps = dbInstance.getTable("companies").filter(c => c.userId === req.userId && c.workspaceId === req.workspaceId);
  const matching = allComps.filter(c => {
    if (extractedFilters.industry !== "All" && c.industry !== extractedFilters.industry) return false;
    if (extractedFilters.country !== "All" && c.country !== extractedFilters.country) return false;
    if (extractedFilters.city && !c.city.toLowerCase().includes(extractedFilters.city.toLowerCase())) return false;
    if (extractedFilters.companySize !== "All" && c.employees !== extractedFilters.companySize) return false;
    if (extractedFilters.revenue !== "All" && c.revenue !== extractedFilters.revenue) return false;
    if (extractedFilters.buyingIntent !== "All" && c.buyingIntent !== extractedFilters.buyingIntent) return false;
    if (extractedFilters.technologies && extractedFilters.technologies.length > 0) {
      const compTechs = JSON.parse(c.technologiesJson || "[]") as string[];
      const hasTech = extractedFilters.technologies.some(t => compTechs.some(ct => ct.toLowerCase() === t.toLowerCase()));
      if (!hasTech) return false;
    }
    return true;
  });

  // Save RecentSearch
  dbInstance.insert("recentSearches", {
    id: `rs_${Math.random().toString(36).substr(2, 9)}`,
    userId: req.userId,
    workspaceId: req.workspaceId,
    type: "Company",
    prompt,
    detectedFiltersJson: JSON.stringify(extractedFilters),
    resultCount: matching.length,
    createdAt: new Date().toISOString()
  });

  return res.json({ detectedFilters: extractedFilters, results: matching });
});

app.post("/api/ai/write-email", requireAuth, async (req: any, res: any) => {
  const { leadId, companyId, goal, tone } = req.body;
  if (!goal) return res.status(400).json({ error: "Please clarify campaign or email goals" });

  const ai = getAIClient();
  const apiKeyExists = !!process.env.GEMINI_API_KEY;

  let leadName = "Prospect";
  let title = "Decision Maker";
  let companyName = "Value Partner";

  if (leadId) {
    const lead = dbInstance.getTable("leads").find(l => l.id === leadId);
    if (lead) {
      leadName = lead.fullName;
      title = lead.title;
      companyName = lead.companyName;
    }
  }

  const emailTone = tone || "Warm Executive";
  const emailGoal = goal || "Schedule a 10 min strategy call";

  let subject = `Core idea for ${companyName}`;
  let body = `Hi ${leadName},\n\nI hope this finds you well. I was reviewing decision makers under ${companyName} and wanted to reach out. I'd love to discuss how our systems could improve outreach sequences.\n\nBest,\nUser`;

  if (apiKeyExists) {
    try {
      const response = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents: `Draft a highly polished, short outreach B2B cold email based on these parameters:
        - Lead Name: ${leadName} (Title: ${title})
        - Company: ${companyName}
        - Email Campaign Goal: "${emailGoal}"
        - Desired Brand Tone: "${emailTone}"
        
        The result must return a JSON object with strictly these keys:
        {
          "subject": "The email subject line",
          "body": "The complete email body parsed with natural newline characters \\n"
        }`
      });
      const parsed = JSON.parse(response.text.trim());
      subject = parsed.subject;
      body = parsed.body;
    } catch (e) {
      console.error("Gemini failed cold email draft, falling back to static template", e);
    }
  }

  return res.json({ subject, body });
});

app.post("/api/ai/summarize-profile", requireAuth, async (req: any, res: any) => {
  const { leadId, companyId } = req.body;
  let context = "A generic B2B partner workspace";

  if (leadId) {
    const lead = dbInstance.getTable("leads").find(l => l.id === leadId);
    if (lead) {
      context = `Lead: ${lead.fullName}, Position: ${lead.title}, Company: ${lead.companyName}, Territory: ${lead.location}, Industry: ${lead.industry}, Intent Level: ${lead.buyingIntent}, Tech Stack: ${lead.technologiesJson}`;
    }
  } else if (companyId) {
    const comp = dbInstance.getTable("companies").find(c => c.id === companyId);
    if (comp) {
      context = `Company: ${comp.companyName}, Domain: ${comp.domain}, Staff: ${comp.employees}, Revenue: ${comp.revenue}, Territory: ${comp.city}, ${comp.country}, Tech Spend: ${comp.technologiesJson}, Target Segment: ${comp.description}`;
    }
  }

  const ai = getAIClient();
  const apiKeyExists = !!process.env.GEMINI_API_KEY;
  let summary = `This profile represents a primary target decision maker in the region. Their tech stack includes notable libraries and services indicating robust budget capabilities. We recommend executing direct custom email outreach.`;

  if (apiKeyExists) {
    try {
      const response = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents: `Summarize this B2B profile into a descriptive, concise 2-sentence executive cheat-sheet highlighting their primary business value, buying intent signals, and recommended pitch hook:
        
        ${context}`
      });
      summary = response.text.trim();
    } catch (e) {
      console.error("Gemini failed summarization, falling back", e);
    }
  }

  return res.json({ summary });
});

app.post("/api/ai/agent-run", requireAuth, async (req: any, res: any) => {
  const { agentId } = req.body;
  if (!agentId) return res.status(400).json({ error: "Missing agentId." });

  const agent = dbInstance.getTable("agents").find(a => a.id === agentId);
  if (!agent) return res.status(404).json({ error: "Agent not found." });

  const ai = getAIClient();
  const apiKeyExists = !!process.env.GEMINI_API_KEY;
  let result = `Successfully triggered ${agent.name}. Scanned the latest outbound lists, processed intent markers, charged 0 credits under the daily allocation layout.`;

  if (apiKeyExists) {
    try {
      const response = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents: `Perform a simulation log run for this generative CRM agent:
        Name: ${agent.name}
        Goal: "${agent.goal}"
        Tone/Strategy: "${agent.tone}"
        
        Generate a professional, realistic 3-sentence executive log report summarizing details of matching outbound campaigns, actions taken, and recommended CRM items updated.`
      });
      result = response.text.trim();
    } catch (e) {
      console.error("Gemini failed agent run log, falling back", e);
    }
  }

  return res.json({ log: result });
});


// Lightweight health endpoint for cloud platform checks
app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", service: "bam-rocket" });
});

// --- 16. STATIC FRONTEND ROUTING & VITE MIDDLEWARE ---

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`BAM Rocket full-stack core running on http://localhost:${PORT}`);
  });
}

startServer();
