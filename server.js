const express = require("express");
const { Pool } = require("pg");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Simple in-memory session store
const sessions = new Map();

function generateSessionId() {
  return crypto.randomBytes(32).toString("hex");
}

// Session middleware
app.use((req, res, next) => {
  const sid = req.headers["x-session-id"] || (req.headers.cookie || "").split(";").map(c => c.trim()).find(c => c.startsWith("sid="))?.split("=")[1];
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

const pool = new Pool({
  host: process.env.PG_HOST || "localhost",
  port: parseInt(process.env.PG_PORT || "5432"),
  database: process.env.PG_DB || "mydb",
  user: process.env.PG_USER || "postgres",
  password: process.env.PG_PASSWORD || "",
  ssl: false
});

async function initDB() {
  try {
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

    console.log("[DB] Base de données initialisée");
  } catch (e) {
    console.log("[DB] Erreur init:", e.message);
    console.log("[DB] Mode démo sans base de données activé");
  }
}

// ─── AUTH ────────────────────────────────────────────────────────────────────

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email et mot de passe requis" });

  try {
    const hash = crypto.createHash("sha256").update(password).digest("hex");
    const result = await pool.query(
      "SELECT id, nom, prenom, poste, role, statut FROM employees WHERE email=$1 AND password_hash=$2",
      [email, hash]
    );
    if (result.rows.length === 0) return res.status(401).json({ error: "Identifiants incorrects" });
    const emp = result.rows[0];
    if (emp.statut !== "actif") return res.status(403).json({ error: "Compte désactivé" });

    const sid = generateSessionId();
    sessions.set(sid, { id: emp.id, nom: emp.nom, prenom: emp.prenom, poste: emp.poste, role: emp.role });
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

app.get("/api/employees", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, nom, prenom, poste, email, telephone, role, statut, date_embauche FROM employees ORDER BY nom, prenom"
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/employees", requireAdmin, async (req, res) => {
  const { nom, prenom, poste, email, telephone, role, password } = req.body;
  if (!nom || !prenom || !poste) return res.status(400).json({ error: "Champs obligatoires manquants" });
  try {
    const hash = password ? crypto.createHash("sha256").update(password).digest("hex") : null;
    const result = await pool.query(
      "INSERT INTO employees (nom, prenom, poste, email, telephone, role, password_hash) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, nom, prenom, poste, email, telephone, role, statut",
      [nom, prenom, poste, email || null, telephone || null, role || "user", hash]
    );
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put("/api/employees/:id", requireAdmin, async (req, res) => {
  const { nom, prenom, poste, email, telephone, role, statut, password } = req.body;
  try {
    let query, params;
    if (password) {
      const hash = crypto.createHash("sha256").update(password).digest("hex");
      query = "UPDATE employees SET nom=$1, prenom=$2, poste=$3, email=$4, telephone=$5, role=$6, statut=$7, password_hash=$8 WHERE id=$9 RETURNING id, nom, prenom, poste, email, telephone, role, statut";
      params = [nom, prenom, poste, email, telephone, role, statut, hash, req.params.id];
    } else {
      query = "UPDATE employees SET nom=$1, prenom=$2, poste=$3, email=$4, telephone=$5, role=$6, statut=$7 WHERE id=$8 RETURNING id, nom, prenom, poste, email, telephone, role, statut";
      params = [nom, prenom, poste, email, telephone, role, statut, req.params.id];
    }
    const result = await pool.query(query, params);
    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete("/api/employees/:id", requireAdmin, async (req, res) => {
  try {
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
    const existing = await pool.query(
      "SELECT * FROM presences WHERE employee_id=$1 AND date=$2",
      [empId, today]
    );

    if (existing.rows.length === 0) {
      // Pointer arrivée
      await pool.query(
        "INSERT INTO presences (employee_id, date, heure_arrivee, statut) VALUES ($1,$2,$3,'present') ON CONFLICT (employee_id, date) DO UPDATE SET heure_arrivee=$3, statut='present'",
        [empId, today, now]
      );
      res.json({ action: "arrivee", heure: now });
    } else if (!existing.rows[0].heure_depart) {
      // Pointer départ
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
    await pool.query("DELETE FROM evenements WHERE id=$1", [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── ANNONCES ────────────────────────────────────────────────────────────────

app.get("/api/annonces", requireAuth, async (req, res) => {
  try {
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
    // Récupérer la commande actuelle
    const cmdRes = await pool.query("SELECT * FROM commandes WHERE id=$1", [req.params.id]);
    if (cmdRes.rows.length === 0) return res.status(404).json({ error: "Commande introuvable" });
    const cmd = cmdRes.rows[0];

    let evenement_id = cmd.evenement_id;

    // Si passage à "confirmé" → créer automatiquement un événement dans le calendrier
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
    await pool.query("DELETE FROM commandes WHERE id=$1", [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── STATIC ───────────────────────────────────────────────────────────────────

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/dashboard", (req, res) => res.sendFile(path.join(__dirname, "public", "dashboard.html")));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));

const PORT = process.env.PORT || 80;
initDB().then(() => {
  app.listen(PORT, "0.0.0.0", () => console.log(`[Elite Corp] Serveur démarré sur le port ${PORT}`));
});
