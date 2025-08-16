import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import sqlite3 from 'sqlite3';

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

// ===== Servir arquivos estáticos da pasta 'public' =====
app.use(express.static('public'));

// ===== DB =====
sqlite3.verbose();
const db = new sqlite3.Database('./rpg.db');

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT CHECK(role IN ('mestre','jogador')) NOT NULL DEFAULT 'jogador',
      char_id INTEGER
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS characters (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_user_id INTEGER NOT NULL,
      name TEXT,
      data TEXT NOT NULL,
      FOREIGN KEY(owner_user_id) REFERENCES users(id)
    )
  `);
});

// ===== Helpers =====
function signToken(user) {
  return jwt.sign({ uid: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
}
function auth(req, res, next) {
  const authH = req.headers.authorization || '';
  const token = authH.startsWith('Bearer ') ? authH.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'no_token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid_token' });
  }
}
function canReadCharacter(user, character) {
  return user.role === 'mestre' || character.owner_user_id === user.uid;
}
function canWriteCharacter(user, character) {
  return canReadCharacter(user, character);
}

// ===== Auth =====
app.post('/auth/register', (req, res) => {
  const { username, password, role } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'missing_fields' });
  const hash = bcrypt.hashSync(String(password), 10);
  const r = (role === 'mestre') ? 'mestre' : 'jogador';

  db.run(
    'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
    [username, hash, r],
    function (err) {
      if (err) return res.status(409).json({ error: 'user_exists' });
      const user = { id: this.lastID, username, role: r };
      const token = signToken(user);
      res.json({ token, role: r, userId: user.id, charId: null });
    }
  );
});

app.post('/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'missing_fields' });

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
    if (err || !row) return res.status(401).json({ error: 'invalid_credentials' });
    const ok = bcrypt.compareSync(String(password), row.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid_credentials' });
    const token = signToken(row);
    res.json({ token, role: row.role, userId: row.id, charId: row.char_id ?? null });
  });
});

// ===== Characters =====
app.post('/characters', auth, (req, res) => {
  const ownerId = req.user.uid;
  const data = req.body?.data;
  if (!data) return res.status(400).json({ error: 'missing_data' });

  const name = data?.header?.name || null;
  db.run(
    'INSERT INTO characters (owner_user_id, name, data) VALUES (?, ?, ?)',
    [ownerId, name, JSON.stringify(data)],
    function (err) {
      if (err) return res.status(500).json({ error: 'db_error' });
      const charId = this.lastID;

      db.get('SELECT role, char_id FROM users WHERE id=?', [ownerId], (e, u) => {
        if (!e && u && u.role === 'jogador' && !u.char_id) {
          db.run('UPDATE users SET char_id=? WHERE id=?', [charId, ownerId]);
        }
        res.status(201).json({ id: charId });
      });
    }
  );
});

app.get('/characters', auth, (req, res) => {
  if (req.user.role === 'mestre') {
    db.all('SELECT id, name, data FROM characters', [], (err, rows) => {
      if (err) return res.status(500).json({ error: 'db_error' });
      const list = rows.map(r => {
        const data = JSON.parse(r.data);
        return {
          id: r.id,
          name: data?.header?.name || r.name || 'Sem nome',
          hpCurrent: data?.hp?.current ?? null,
          hpMax: data?.hp?.max ?? null,
          ac: data?.misc?.ac ?? null
        };
      });
      res.json(list);
    });
  } else {
    db.get('SELECT char_id FROM users WHERE id=?', [req.user.uid], (err, u) => {
      if (err || !u || !u.char_id) return res.json([]);
      db.get('SELECT id, name, data FROM characters WHERE id=?', [u.char_id], (e, row) => {
        if (e || !row) return res.json([]);
        const data = JSON.parse(row.data);
        res.json([{
          id: row.id,
          name: data?.header?.name || row.name || 'Sem nome',
          hpCurrent: data?.hp?.current ?? null,
          hpMax: data?.hp?.max ?? null,
          ac: data?.misc?.ac ?? null
        }]);
      });
    });
  }
});

app.get('/characters/:id', auth, (req, res) => {
  const id = Number(req.params.id);
  db.get('SELECT * FROM characters WHERE id=?', [id], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'not_found' });
    if (!canReadCharacter(req.user, row)) return res.status(403).json({ error: 'forbidden' });
    res.json({ id: row.id, owner_user_id: row.owner_user_id, data: JSON.parse(row.data) });
  });
});

app.put('/characters/:id', auth, (req, res) => {
  const id = Number(req.params.id);
  const data = req.body?.data;
  if (!data) return res.status(400).json({ error: 'missing_data' });

  db.get('SELECT * FROM characters WHERE id=?', [id], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'not_found' });
    if (!canWriteCharacter(req.user, row)) return res.status(403).json({ error: 'forbidden' });
    const name = data?.header?.name || row.name;
    db.run('UPDATE characters SET name=?, data=? WHERE id=?', [name, JSON.stringify(data), id], (e) => {
      if (e) return res.status(500).json({ error: 'db_error' });
      res.json({ ok: true });
    });
  });
});

app.listen(PORT, () => console.log(`API on http://localhost:${PORT}`));