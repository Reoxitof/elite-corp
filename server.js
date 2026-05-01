const express = require("express");
const { Pool } = require("pg");
const path = require("path");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

const pool = new Pool({
  host: process.env.PG_HOST || "postgres-ghzw.internal",
  port: parseInt(process.env.PG_PORT || "5432"),
  database: process.env.PG_DB || "mydb",
  user: process.env.PG_USER || "postgres",
  password: process.env.PG_PASSWORD || "LQPZsmNPPgwiRNL8",
  ssl: false
});

async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS candidatures (
        id SERIAL PRIMARY KEY,
        nom TEXT NOT NULL,
        prenom TEXT NOT NULL,
        contact TEXT NOT NULL,
        poste TEXT NOT NULL,
        age TEXT,
        experience TEXT,
        motivation TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log("[DB] Table candidatures prete");
  } catch(e) {
    console.log("[DB] Erreur init:", e.message);
  }
}

app.post("/postuler", async (req, res) => {
  const { nom, prenom, contact, poste, age, experience, motivation } = req.body;
  if (!nom || !prenom || !contact || !poste) {
    return res.status(400).json({ error: "Champs obligatoires manquants" });
  }
  try {
    await pool.query(
      "INSERT INTO candidatures (nom, prenom, contact, poste, age, experience, motivation) VALUES ($1,$2,$3,$4,$5,$6,$7)",
      [nom, prenom, contact, poste, age||"", experience||"", motivation||""]
    );
    res.json({ success: true, message: "Candidature envoyee avec succes !" });
  } catch(e) {
    console.error("[DB] Erreur:", e.message);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.get("/admin/candidatures", async (req, res) => {
  if (req.query.key !== (process.env.ADMIN_KEY || "elitecorp2026")) {
    return res.status(403).json({ error: "Acces refuse" });
  }
  const result = await pool.query("SELECT * FROM candidatures ORDER BY created_at DESC");
  res.json(result.rows);
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

const PORT = process.env.PORT || 80;
initDB().then(() => {
  app.listen(PORT, "0.0.0.0", () => console.log("Elite Corp sur port " + PORT));
});
