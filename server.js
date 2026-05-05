const express = require("express");
const { Pool } = require("pg");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── MODE FALLBACK (sans PostgreSQL) ─────────────────────────────────────────
let dbMode = "postgres"; // "postgres" ou "memory"

// Données en mémoire pour le mode fallback
const memDB = {
  employees: [],
  presences: [],
  evenements: [],
  annonces: [],
  commandes: [],
  _nextId: { employees: 1, presences: 1, evenements: 1, annonces: 1, commandes: 1 }
};

function memNextId(table) {
  return memDB._nextId[table]++;
}

function initMemDB() {
  const adminPass = process.env.ADMIN_PASSWORD || "elitecorp2026";
  const hash = crypto.createHash("sha256").update(adminPass).digest("hex");
  memDB.employees.push({
    id: memNextId("employees"),
    nom: "Admin", prenom: "Elite Corp", poste: "Directeur Général",
    email: "admin@elitecorp.fr", telephone: null,
    role: "admin", password_hash: hash, statut: "actif",
    date_embauche: new Date().toISOString().split("T")[0],
    created_at: new Date().toISOString()
  });
  console.log("[MEM] Mode mémoire activé — admin@elitecorp.fr /", adminPass);
}

// Wrapper DB : redirige vers mémoire si postgres KO
const db = {
  async query(sql, params = []) {
    if (dbMode === "memory") throw new Error("USE_MEM");
    return pool.query(sql, params);
  }
};

// Simple in-memory session store + PostgreSQL pour persistance
const sessions = new Map();

function generateSessionId() {
  return crypto.randomBytes(32).toString("hex");
}

// Sauvegarde session en DB (fire-and-forget)
async function dbSaveSession(sid, data) {
  try {
    const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await pool.query(
      `INSERT INTO sessions (sid, data, expires_at) VALUES ($1,$2,$3)
       ON CONFLICT (sid) DO UPDATE SET data=$2, expires_at=$3`,
      [sid, JSON.stringify(data), expires]
    );
  } catch(e) { /* silencieux */ }
}

// Charge les sessions depuis DB au démarrage
async function loadSessionsFromDB() {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS sessions (
      sid TEXT PRIMARY KEY,
      data TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL
    )`);
    await pool.query(`DELETE FROM sessions WHERE expires_at < NOW()`);
    const res = await pool.query(`SELECT sid, data FROM sessions WHERE expires_at > NOW()`);
    for (const row of res.rows) {
      try { sessions.set(row.sid, JSON.parse(row.data)); } catch(e) {}
    }
    console.log(`[SESSION] ${sessions.size} sessions restaurées depuis DB`);
  } catch(e) {
    console.log("[SESSION] Erreur chargement sessions:", e.message);
  }
}

// Session middleware — accepte cookie sid OU header x-session-id OU query ?sid=
app.use((req, res, next) => {
  const sid = req.headers["x-session-id"]
    || req.query.sid
    || (req.headers.cookie || "").split(";").map(c => c.trim()).find(c => c.startsWith("sid="))?.split("=")[1];
  if (sid && sessions.has(sid)) {
    req.session = sessions.get(sid);
    req.sessionId = sid;
  } else {
    req.session = null;
    req.sessionId = null;
  }
  next();
});

function requireAuth(req, res, next) {
  if (!req.session) return res.status(401).json({ error: "Non authentifié" });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session) return res.status(401).json({ error: "Non authentifié" });
  if (req.session.role !== "admin") return res.status(403).json({ error: "Accès refusé" });
  next();
}

// Rôles valides : admin, user, interimaire
const VALID_ROLES = ["admin", "user", "interimaire"];

// Bloque les intérimaires sur les actions sensibles (commandes, annonces, gestion)
function requireNotInterimaire(req, res, next) {
  if (!req.session) return res.status(401).json({ error: "Non authentifié" });
  if (req.session.role === "interimaire") return res.status(403).json({ error: "Accès refusé — rôle intérimaire" });
  next();
}

const pool = new Pool({
  host: process.env.PG_HOST || "localhost",
  port: parseInt(process.env.PG_PORT || "5432"),
  database: process.env.PG_DB || "mydb",
  user: process.env.PG_USER || "postgres",
  password: process.env.PG_PASSWORD || "",
  ssl: false,
  connectionTimeoutMillis: 5000
});

async function initDB() {
  try {
    // Test de connexion rapide
    await pool.query("SELECT 1");

    await pool.query(`
      CREATE TABLE IF NOT EXISTS employees (
        id SERIAL PRIMARY KEY,
        nom TEXT NOT NULL,
        prenom TEXT NOT NULL,
        poste TEXT NOT NULL,
        email TEXT,
        telephone TEXT,
        role TEXT DEFAULT 'user',
        password_hash TEXT,
        statut TEXT DEFAULT 'actif',
        date_embauche DATE DEFAULT CURRENT_DATE,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS presences (
        id SERIAL PRIMARY KEY,
        employee_id INTEGER REFERENCES employees(id),
        date DATE DEFAULT CURRENT_DATE,
        heure_arrivee TIME,
        heure_depart TIME,
        statut TEXT DEFAULT 'absent',
        note TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(employee_id, date)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS evenements (
        id SERIAL PRIMARY KEY,
        titre TEXT NOT NULL,
        description TEXT,
        date DATE NOT NULL,
        heure_debut TIME,
        heure_fin TIME,
        lieu TEXT,
        type TEXT DEFAULT 'general',
        created_by INTEGER REFERENCES employees(id),
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS annonces (
        id SERIAL PRIMARY KEY,
        titre TEXT NOT NULL,
        contenu TEXT NOT NULL,
        priorite TEXT DEFAULT 'normale',
        created_by INTEGER REFERENCES employees(id),
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS commandes (
        id SERIAL PRIMARY KEY,
        client_nom TEXT NOT NULL,
        description TEXT NOT NULL,
        montant NUMERIC(10,2),
        priorite TEXT DEFAULT 'normale',
        statut TEXT DEFAULT 'devis',
        date_prestation DATE,
        heure_debut TIME,
        heure_fin TIME,
        lieu TEXT,
        evenement_id INTEGER REFERENCES evenements(id) ON DELETE SET NULL,
        created_by INTEGER REFERENCES employees(id),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Check if admin exists
    const adminCheck = await pool.query("SELECT id FROM employees WHERE role='admin' LIMIT 1");
    if (adminCheck.rows.length === 0) {
      const adminPass = process.env.ADMIN_PASSWORD || "elitecorp2026";
      const hash = crypto.createHash("sha256").update(adminPass).digest("hex");
      await pool.query(
        "INSERT INTO employees (nom, prenom, poste, email, role, password_hash, statut) VALUES ($1,$2,$3,$4,$5,$6,$7)",
        ["Admin", "Elite Corp", "Directeur Général", "admin@elitecorp.fr", "admin", hash, "actif"]
      );
      console.log("[DB] Admin créé — mot de passe:", adminPass);
    }

    console.log("[DB] PostgreSQL initialisé");
  } catch (e) {
    console.log("[DB] PostgreSQL inaccessible:", e.message);
    console.log("[DB] ⚡ Basculement en mode mémoire");
    dbMode = "memory";
    initMemDB();
  }
}

// ─── AUTH ────────────────────────────────────────────────────────────────────

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email et mot de passe requis" });

  try {
    const hash = crypto.createHash("sha256").update(password).digest("hex");
    let emp;

    if (dbMode === "memory") {
      emp = memDB.employees.find(e => e.email === email && e.password_hash === hash) || null;
    } else {
      const result = await pool.query(
        "SELECT id, nom, prenom, poste, role, statut FROM employees WHERE email=$1 AND password_hash=$2",
        [email, hash]
      );
      emp = result.rows[0] || null;
    }

    if (!emp) return res.status(401).json({ error: "Identifiants incorrects" });
    if (emp.statut !== "actif") return res.status(403).json({ error: "Compte désactivé" });

    const sid = generateSessionId();
    const sessionData = { id: emp.id, nom: emp.nom, prenom: emp.prenom, poste: emp.poste, role: emp.role };
    sessions.set(sid, sessionData);
    dbSaveSession(sid, sessionData); // persistance DB (fire-and-forget)
    res.setHeader("Set-Cookie", `sid=${sid}; Path=/; HttpOnly; SameSite=Lax`);
    res.json({ success: true, sessionId: sid, user: { id: emp.id, nom: emp.nom, prenom: emp.prenom, poste: emp.poste, role: emp.role } });
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.post("/api/logout", (req, res) => {
  if (req.sessionId) sessions.delete(req.sessionId);
  res.setHeader("Set-Cookie", "sid=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
  res.json({ success: true });
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json(req.session);
});

// ─── EMPLOYEES ───────────────────────────────────────────────────────────────

// ─── EMPLOYEES PAR RÔLE ──────────────────────────────────────────────────────
app.get("/api/employees/role/:role", requireAuth, async (req, res) => {
  const role = req.params.role;
  if (!VALID_ROLES.includes(role)) return res.status(400).json({ error: `Rôle invalide. Valeurs acceptées : ${VALID_ROLES.join(", ")}` });
  try {
    if (dbMode === "memory") {
      return res.json(memDB.employees.filter(e => e.role === role && e.statut === "actif").map(safeEmp));
    }
    const result = await pool.query(
      "SELECT id, nom, prenom, poste, email, telephone, role, statut, date_embauche FROM employees WHERE role=$1 AND statut='actif' ORDER BY nom, prenom",
      [role]
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/employees", requireAuth, async (req, res) => {
  try {
    if (dbMode === "memory") {
      return res.json(memDB.employees.map(safeEmp));
    }
    const result = await pool.query(
      "SELECT id, nom, prenom, poste, email, telephone, role, statut, date_embauche FROM employees ORDER BY nom, prenom"
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

function safeEmp(e) {
  return { id: e.id, nom: e.nom, prenom: e.prenom, poste: e.poste, email: e.email, telephone: e.telephone, role: e.role, statut: e.statut, date_embauche: e.date_embauche };
}

app.post("/api/employees", requireAdmin, async (req, res) => {
  const { nom, prenom, poste, email, telephone, role, password } = req.body;
  if (!nom || !prenom || !poste) return res.status(400).json({ error: "Champs obligatoires manquants" });
  const roleValide = VALID_ROLES.includes(role) ? role : "user";
  try {
    const hash = password ? crypto.createHash("sha256").update(password).digest("hex") : null;
    if (dbMode === "memory") {
      const emp = { id: memNextId("employees"), nom, prenom, poste, email: email||null, telephone: telephone||null, role: roleValide, password_hash: hash, statut: "actif", date_embauche: new Date().toISOString().split("T")[0], created_at: new Date().toISOString() };
      memDB.employees.push(emp);
      return res.json(safeEmp(emp));
    }
    const result = await pool.query(
      "INSERT INTO employees (nom, prenom, poste, email, telephone, role, password_hash) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, nom, prenom, poste, email, telephone, role, statut",
      [nom, prenom, poste, email || null, telephone || null, roleValide, hash]
    );
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── CHANGER LE RÔLE D'UN EMPLOYÉ ────────────────────────────────────────────
app.put("/api/employees/:id/role", requireAdmin, async (req, res) => {
  const { role } = req.body;
  if (!VALID_ROLES.includes(role)) return res.status(400).json({ error: `Rôle invalide. Valeurs acceptées : ${VALID_ROLES.join(", ")}` });
  try {
    if (dbMode === "memory") {
      const emp = memDB.employees.find(e => e.id == req.params.id);
      if (!emp) return res.status(404).json({ error: "Employé introuvable" });
      emp.role = role;
      return res.json(safeEmp(emp));
    }
    const result = await pool.query(
      "UPDATE employees SET role=$1 WHERE id=$2 RETURNING id, nom, prenom, poste, role, statut",
      [role, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Employé introuvable" });
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put("/api/employees/:id", requireAdmin, async (req, res) => {
  const { nom, prenom, poste, email, telephone, role, statut, password } = req.body;
  const roleValide = VALID_ROLES.includes(role) ? role : "user";
  try {
    if (dbMode === "memory") {
      const emp = memDB.employees.find(e => e.id == req.params.id);
      if (!emp) return res.status(404).json({ error: "Employé introuvable" });
      Object.assign(emp, { nom, prenom, poste, email, telephone, role: roleValide, statut });
      if (password) emp.password_hash = crypto.createHash("sha256").update(password).digest("hex");
      return res.json(safeEmp(emp));
    }
    let query, params;
    if (password) {
      const hash = crypto.createHash("sha256").update(password).digest("hex");
      query = "UPDATE employees SET nom=$1, prenom=$2, poste=$3, email=$4, telephone=$5, role=$6, statut=$7, password_hash=$8 WHERE id=$9 RETURNING id, nom, prenom, poste, email, telephone, role, statut";
      params = [nom, prenom, poste, email, telephone, roleValide, statut, hash, req.params.id];
    } else {
      query = "UPDATE employees SET nom=$1, prenom=$2, poste=$3, email=$4, telephone=$5, role=$6, statut=$7 WHERE id=$8 RETURNING id, nom, prenom, poste, email, telephone, role, statut";
      params = [nom, prenom, poste, email, telephone, roleValide, statut, req.params.id];
    }
    const result = await pool.query(query, params);
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete("/api/employees/:id", requireAdmin, async (req, res) => {
  try {
    if (dbMode === "memory") {
      const emp = memDB.employees.find(e => e.id == req.params.id);
      if (emp) emp.statut = "inactif";
      return res.json({ success: true });
    }
    await pool.query("UPDATE employees SET statut='inactif' WHERE id=$1", [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── PRESENCES ───────────────────────────────────────────────────────────────

app.get("/api/presences", requireAuth, async (req, res) => {
  const date = req.query.date || new Date().toISOString().split("T")[0];
  try {
    if (dbMode === "memory") {
      const rows = memDB.employees.filter(e => e.statut === "actif").map(e => {
        const p = memDB.presences.find(p => p.employee_id === e.id && p.date === date);
        return { id: p?.id||null, employee_id: e.id, nom: e.nom, prenom: e.prenom, poste: e.poste, date, heure_arrivee: p?.heure_arrivee||null, heure_depart: p?.heure_depart||null, statut: p?.statut||"absent", note: p?.note||null };
      });
      return res.json(rows);
    }
    const result = await pool.query(`
      SELECT p.id, p.employee_id, e.nom, e.prenom, e.poste,
             p.date, p.heure_arrivee, p.heure_depart, p.statut, p.note
      FROM employees e
      LEFT JOIN presences p ON p.employee_id = e.id AND p.date = $1
      WHERE e.statut = 'actif'
      ORDER BY e.nom, e.prenom
    `, [date]);
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/presences/pointer", requireAuth, async (req, res) => {
  const empId = req.session.id;
  const today = new Date().toISOString().split("T")[0];
  const now = new Date().toTimeString().split(" ")[0];

  try {
    if (dbMode === "memory") {
      const existing = memDB.presences.find(p => p.employee_id === empId && p.date === today);
      if (!existing) {
        memDB.presences.push({ id: memNextId("presences"), employee_id: empId, date: today, heure_arrivee: now, heure_depart: null, statut: "present", note: null });
        return res.json({ action: "arrivee", heure: now });
      } else if (!existing.heure_depart) {
        existing.heure_depart = now;
        return res.json({ action: "depart", heure: now });
      } else {
        return res.json({ action: "deja_pointe", heure_arrivee: existing.heure_arrivee, heure_depart: existing.heure_depart });
      }
    }
    const existing = await pool.query(
      "SELECT * FROM presences WHERE employee_id=$1 AND date=$2",
      [empId, today]
    );

    if (existing.rows.length === 0) {
      await pool.query(
        "INSERT INTO presences (employee_id, date, heure_arrivee, statut) VALUES ($1,$2,$3,'present') ON CONFLICT (employee_id, date) DO UPDATE SET heure_arrivee=$3, statut='present'",
        [empId, today, now]
      );
      res.json({ action: "arrivee", heure: now });
    } else if (!existing.rows[0].heure_depart) {
      await pool.query(
        "UPDATE presences SET heure_depart=$1 WHERE employee_id=$2 AND date=$3",
        [now, empId, today]
      );
      res.json({ action: "depart", heure: now });
    } else {
      res.json({ action: "deja_pointe", heure_arrivee: existing.rows[0].heure_arrivee, heure_depart: existing.rows[0].heure_depart });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/presences/me", requireAuth, async (req, res) => {
  const today = new Date().toISOString().split("T")[0];
  try {
    if (dbMode === "memory") {
      return res.json(memDB.presences.find(p => p.employee_id === req.session.id && p.date === today) || null);
    }
    const result = await pool.query(
      "SELECT * FROM presences WHERE employee_id=$1 AND date=$2",
      [req.session.id, today]
    );
    res.json(result.rows[0] || null);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put("/api/presences/:id", requireAdmin, async (req, res) => {
  const { statut, heure_arrivee, heure_depart, note } = req.body;
  try {
    if (dbMode === "memory") {
      const p = memDB.presences.find(p => p.id == req.params.id);
      if (!p) return res.status(404).json({ error: "Présence introuvable" });
      Object.assign(p, { statut, heure_arrivee: heure_arrivee||null, heure_depart: heure_depart||null, note: note||null });
      return res.json(p);
    }
    const result = await pool.query(
      "UPDATE presences SET statut=$1, heure_arrivee=$2, heure_depart=$3, note=$4 WHERE id=$5 RETURNING *",
      [statut, heure_arrivee || null, heure_depart || null, note || null, req.params.id]
    );
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── EVENEMENTS ──────────────────────────────────────────────────────────────

app.get("/api/evenements", requireAuth, async (req, res) => {
  const { mois, annee } = req.query;
  try {
    if (dbMode === "memory") {
      let rows = memDB.evenements;
      if (mois && annee) rows = rows.filter(e => { const d = new Date(e.date); return d.getMonth()+1 == mois && d.getFullYear() == annee; });
      return res.json(rows.map(e => ({ ...e, createur: "Admin Elite Corp" })));
    }
    let query = `
      SELECT ev.*, e.nom || ' ' || e.prenom as createur
      FROM evenements ev
      LEFT JOIN employees e ON e.id = ev.created_by
    `;
    const params = [];
    if (mois && annee) {
      query += " WHERE EXTRACT(MONTH FROM ev.date)=$1 AND EXTRACT(YEAR FROM ev.date)=$2";
      params.push(mois, annee);
    }
    query += " ORDER BY ev.date, ev.heure_debut";
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/evenements", requireAdmin, async (req, res) => {
  const { titre, description, date, heure_debut, heure_fin, lieu, type } = req.body;
  if (!titre || !date) return res.status(400).json({ error: "Titre et date requis" });
  try {
    if (dbMode === "memory") {
      const ev = { id: memNextId("evenements"), titre, description: description||null, date, heure_debut: heure_debut||null, heure_fin: heure_fin||null, lieu: lieu||null, type: type||"general", created_by: req.session.id, created_at: new Date().toISOString() };
      memDB.evenements.push(ev);
      return res.json(ev);
    }
    const result = await pool.query(
      "INSERT INTO evenements (titre, description, date, heure_debut, heure_fin, lieu, type, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *",
      [titre, description || null, date, heure_debut || null, heure_fin || null, lieu || null, type || "general", req.session.id]
    );
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete("/api/evenements/:id", requireAdmin, async (req, res) => {
  try {
    if (dbMode === "memory") {
      memDB.evenements = memDB.evenements.filter(e => e.id != req.params.id);
      return res.json({ success: true });
    }
    await pool.query("DELETE FROM evenements WHERE id=$1", [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── ANNONCES ────────────────────────────────────────────────────────────────

app.get("/api/annonces", requireAuth, async (req, res) => {
  try {
    if (dbMode === "memory") {
      return res.json(memDB.annonces.map(a => ({ ...a, auteur: "Admin Elite Corp" })).reverse());
    }
    const result = await pool.query(`
      SELECT a.*, e.nom || ' ' || e.prenom as auteur
      FROM annonces a
      LEFT JOIN employees e ON e.id = a.created_by
      ORDER BY a.created_at DESC
    `);
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/annonces", requireAdmin, async (req, res) => {
  const { titre, contenu, priorite } = req.body;
  if (!titre || !contenu) return res.status(400).json({ error: "Titre et contenu requis" });
  try {
    if (dbMode === "memory") {
      const a = { id: memNextId("annonces"), titre, contenu, priorite: priorite||"normale", created_by: req.session.id, created_at: new Date().toISOString() };
      memDB.annonces.push(a);
      return res.json(a);
    }
    const result = await pool.query(
      "INSERT INTO annonces (titre, contenu, priorite, created_by) VALUES ($1,$2,$3,$4) RETURNING *",
      [titre, contenu, priorite || "normale", req.session.id]
    );
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete("/api/annonces/:id", requireAdmin, async (req, res) => {
  try {
    if (dbMode === "memory") {
      memDB.annonces = memDB.annonces.filter(a => a.id != req.params.id);
      return res.json({ success: true });
    }
    await pool.query("DELETE FROM annonces WHERE id=$1", [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── STATS ───────────────────────────────────────────────────────────────────

app.get("/api/stats", requireAuth, async (req, res) => {
  const today = new Date().toISOString().split("T")[0];
  try {
    if (dbMode === "memory") {
      return res.json({
        employes: memDB.employees.filter(e => e.statut === "actif").length,
        presents: memDB.presences.filter(p => p.date === today && p.statut === "present").length,
        evenements: memDB.evenements.filter(e => e.date >= today).length,
        annonces: memDB.annonces.length
      });
    }
    const [empCount, presentCount, evCount, annCount] = await Promise.all([
      pool.query("SELECT COUNT(*) FROM employees WHERE statut='actif'"),
      pool.query("SELECT COUNT(*) FROM presences WHERE date=$1 AND statut='present'", [today]),
      pool.query("SELECT COUNT(*) FROM evenements WHERE date >= $1", [today]),
      pool.query("SELECT COUNT(*) FROM annonces")
    ]);
    res.json({
      employes: parseInt(empCount.rows[0].count),
      presents: parseInt(presentCount.rows[0].count),
      evenements: parseInt(evCount.rows[0].count),
      annonces: parseInt(annCount.rows[0].count)
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── COMMANDES ───────────────────────────────────────────────────────────────

app.get("/api/commandes", requireAuth, async (req, res) => {
  try {
    if (dbMode === "memory") {
      return res.json(memDB.commandes.map(c => ({ ...c, createur: "Admin Elite Corp" })).reverse());
    }
    const result = await pool.query(`
      SELECT c.*, e.nom || ' ' || e.prenom as createur
      FROM commandes c
      LEFT JOIN employees e ON e.id = c.created_by
      ORDER BY c.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/commandes", requireAdmin, async (req, res) => {
  const { client_nom, description, montant, priorite, date_prestation, heure_debut, heure_fin, lieu } = req.body;
  if (!client_nom || !description) return res.status(400).json({ error: "Client et description requis" });
  try {
    if (dbMode === "memory") {
      const c = { id: memNextId("commandes"), client_nom, description, montant: montant||null, priorite: priorite||"normale", statut: "devis", date_prestation: date_prestation||null, heure_debut: heure_debut||null, heure_fin: heure_fin||null, lieu: lieu||null, evenement_id: null, created_by: req.session.id, created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
      memDB.commandes.push(c);
      return res.json(c);
    }
    const result = await pool.query(
      `INSERT INTO commandes (client_nom, description, montant, priorite, date_prestation, heure_debut, heure_fin, lieu, statut, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'devis',$9) RETURNING *`,
      [client_nom, description, montant || null, priorite || "normale",
       date_prestation || null, heure_debut || null, heure_fin || null, lieu || null, req.session.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/commandes/:id/statut", requireAdmin, async (req, res) => {
  const { statut } = req.body;
  const validStatuts = ["devis", "confirme", "en_cours", "termine"];
  if (!validStatuts.includes(statut)) return res.status(400).json({ error: "Statut invalide" });

  try {
    if (dbMode === "memory") {
      const cmd = memDB.commandes.find(c => c.id == req.params.id);
      if (!cmd) return res.status(404).json({ error: "Commande introuvable" });
      let evenement_cree = false;
      if (statut === "confirme" && !cmd.evenement_id) {
        const ev = { id: memNextId("evenements"), titre: `📋 ${cmd.client_nom} — ${cmd.description.substring(0,50)}`, description: `Prestation confirmée\nClient : ${cmd.client_nom}`, date: cmd.date_prestation || new Date().toISOString().split("T")[0], heure_debut: cmd.heure_debut||null, heure_fin: cmd.heure_fin||null, lieu: cmd.lieu||null, type: "prestation", created_by: req.session.id, created_at: new Date().toISOString() };
        memDB.evenements.push(ev);
        cmd.evenement_id = ev.id;
        evenement_cree = true;
      }
      cmd.statut = statut;
      cmd.updated_at = new Date().toISOString();
      return res.json({ commande: cmd, evenement_cree });
    }

    const cmdRes = await pool.query("SELECT * FROM commandes WHERE id=$1", [req.params.id]);
    if (cmdRes.rows.length === 0) return res.status(404).json({ error: "Commande introuvable" });
    const cmd = cmdRes.rows[0];

    let evenement_id = cmd.evenement_id;

    if (statut === "confirme" && !cmd.evenement_id) {
      const dateEv = cmd.date_prestation || new Date().toISOString().split("T")[0];
      const evRes = await pool.query(
        `INSERT INTO evenements (titre, description, date, heure_debut, heure_fin, lieu, type, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,'prestation',$7) RETURNING *`,
        [
          `📋 ${cmd.client_nom} — ${cmd.description.substring(0, 50)}`,
          `Prestation confirmée\nClient : ${cmd.client_nom}\n${cmd.description}${cmd.montant ? `\nMontant : ${cmd.montant}€` : ""}`,
          dateEv,
          cmd.heure_debut || null,
          cmd.heure_fin || null,
          cmd.lieu || null,
          req.session.id
        ]
      );
      evenement_id = evRes.rows[0].id;
    }

    const result = await pool.query(
      `UPDATE commandes SET statut=$1, evenement_id=$2, updated_at=NOW() WHERE id=$3 RETURNING *`,
      [statut, evenement_id, req.params.id]
    );
    res.json({ commande: result.rows[0], evenement_cree: statut === "confirme" && !cmd.evenement_id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/commandes/:id", requireAdmin, async (req, res) => {
  const { client_nom, description, montant, priorite, date_prestation, heure_debut, heure_fin, lieu } = req.body;
  try {
    if (dbMode === "memory") {
      const cmd = memDB.commandes.find(c => c.id == req.params.id);
      if (!cmd) return res.status(404).json({ error: "Commande introuvable" });
      Object.assign(cmd, { client_nom, description, montant: montant||null, priorite: priorite||"normale", date_prestation: date_prestation||null, heure_debut: heure_debut||null, heure_fin: heure_fin||null, lieu: lieu||null, updated_at: new Date().toISOString() });
      return res.json(cmd);
    }
    const result = await pool.query(
      `UPDATE commandes SET client_nom=$1, description=$2, montant=$3, priorite=$4,
       date_prestation=$5, heure_debut=$6, heure_fin=$7, lieu=$8, updated_at=NOW()
       WHERE id=$9 RETURNING *`,
      [client_nom, description, montant || null, priorite || "normale",
       date_prestation || null, heure_debut || null, heure_fin || null, lieu || null, req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/commandes/:id", requireAdmin, async (req, res) => {
  try {
    if (dbMode === "memory") {
      memDB.commandes = memDB.commandes.filter(c => c.id != req.params.id);
      return res.json({ success: true });
    }
    await pool.query("DELETE FROM commandes WHERE id=$1", [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── STATIC ───────────────────────────────────────────────────────────────────

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "app.html")));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "public", "app.html")));
app.get("/dashboard", (req, res) => res.sendFile(path.join(__dirname, "public", "app.html")));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "app.html")));

const PORT = process.env.PORT || 80;
initDB().then(async () => {
  await loadSessionsFromDB();
  app.listen(PORT, "0.0.0.0", () => console.log(`[Elite Corp] Serveur démarré sur le port ${PORT}`));
});
