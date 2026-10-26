// HTTP layer: routes, validation, auth. Exported without listen() so tests can start it.
const express = require('express'), path = require('path'), crypto = require('crypto'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const db = require('./db');

if (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET) throw new Error('Set JWT_SECRET in production.');
const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'); // dev: new secret each start

const app = express();
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const bad = (m, status = 400) => Object.assign(new Error(m), { status });
const wrap = f => (req, res, next) => { try { f(req, res); } catch (e) { next(e); } };
const today = () => new Date().toLocaleDateString('en-CA'); // YYYY-MM-DD, local
const validDate = d => /^\d{4}-\d{2}-\d{2}$/.test(d) && new Date(d + 'T00:00:00Z').toISOString().slice(0, 10) === d;
const num = v => { const n = Number(v); if (!Number.isInteger(n)) throw bad('Record not found.', 404); return n; };

// ---- auth ----
const attempts = new Map(); // ip -> {n, reset}; simple login rate limit (10 per 15 min)
app.post('/api/auth/login', wrap((req, res) => {
  const ip = req.ip, now = Date.now(), a = attempts.get(ip);
  if (a && a.reset > now && a.n >= 10) throw bad('Too many attempts. Try again in a few minutes.', 429);
  const { username = '', password = '' } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(String(username).trim());
  if (!u || !bcrypt.compareSync(String(password), u.password_hash)) {
    attempts.set(ip, { n: (a && a.reset > now ? a.n : 0) + 1, reset: a && a.reset > now ? a.reset : now + 15 * 60e3 });
    throw bad('Incorrect username or password.', 401);
  }
  attempts.delete(ip);
  const user = { id: u.id, username: u.username, role: u.role };
  res.json({ token: jwt.sign(user, SECRET, { expiresIn: '8h' }), user });
}));
function auth(req, res, next) {
  const t = (req.headers.authorization || '').replace(/^Bearer /, '');
  try { req.user = jwt.verify(t, SECRET); next(); } catch { next(bad('Please sign in.', 401)); }
}
const adminOnly = (req, res, next) => req.user.role === 'admin' ? next() : next(bad('Only an administrator can do this.', 403));
app.get('/api/health', (req, res) => res.json({ status: 'ok' }));
app.get('/api/auth/me', auth, (req, res) => res.json({ user: req.user }));

// ---- reference data ----
const DOCTORS = `SELECT d.id, d.name, d.specialty, d.start_time AS start, d.end_time AS end, dep.name AS department
                 FROM doctors d JOIN departments dep ON dep.id = d.department_id ORDER BY d.name`;
app.get('/api/doctors', auth, (req, res) => res.json(db.prepare(DOCTORS).all()));

// ---- patients ----
const PATIENT = `SELECT id, 'PT-' || (1000 + id) AS code, name, age, gender, phone, created_at FROM patients`;
function cleanPatient(b = {}, partial = false) {
  const o = {};
  if (!partial || b.name !== undefined) { const v = String(b.name || '').trim(); if (v.length < 2 || v.length > 80) throw bad('Name must be 2–80 characters.'); o.name = v; }
  if (!partial || b.age !== undefined) { const v = Number(b.age); if (b.age === '' || !Number.isInteger(v) || v < 0 || v > 120) throw bad('Age must be a whole number from 0 to 120.'); o.age = v; }
  if (!partial || b.phone !== undefined) { const v = String(b.phone || '').trim(); if (!/^[0-9+\-\s]{7,15}$/.test(v)) throw bad('Phone must be 7–15 digits.'); o.phone = v; }
  if (!partial || b.gender !== undefined) { const v = String(b.gender || 'Not specified'); if (!['Female', 'Male', 'Other', 'Not specified'].includes(v)) throw bad('Choose a gender from the list.'); o.gender = v; }
  return o;
}
app.get('/api/patients', auth, (req, res) => {
  const q = `%${String(req.query.q || '').trim()}%`;
  res.json(db.prepare(`${PATIENT} WHERE name LIKE ? OR phone LIKE ? OR 'PT-' || (1000 + id) LIKE ? ORDER BY id DESC`).all(q, q, q));
});
app.post('/api/patients', auth, wrap((req, res) => {
  const o = cleanPatient(req.body);
  const r = db.prepare('INSERT INTO patients(name,age,gender,phone) VALUES(@name,@age,@gender,@phone)').run(o);
  res.status(201).json(db.prepare(`${PATIENT} WHERE id = ?`).get(r.lastInsertRowid));
}));
app.get('/api/patients/:id', auth, wrap((req, res) => {
  const p = db.prepare(`${PATIENT} WHERE id = ?`).get(num(req.params.id));
  if (!p) throw bad('Patient not found.', 404);
  res.json(p);
}));
app.put('/api/patients/:id', auth, wrap((req, res) => {
  const id = num(req.params.id), o = cleanPatient(req.body, true), k = Object.keys(o);
  if (!k.length) throw bad('Nothing to update.');
  const r = db.prepare(`UPDATE patients SET ${k.map(x => `${x} = @${x}`).join(', ')} WHERE id = @id`).run({ ...o, id });
  if (!r.changes) throw bad('Patient not found.', 404);
  res.json(db.prepare(`${PATIENT} WHERE id = ?`).get(id));
}));
app.delete('/api/patients/:id', auth, adminOnly, wrap((req, res) => {
  const id = num(req.params.id);
  if (db.prepare("SELECT 1 FROM appointments WHERE patient_id = ? AND status = 'Confirmed'").get(id))
    throw bad('This patient has confirmed appointments. Cancel them first.', 409);
  if (!db.prepare('DELETE FROM patients WHERE id = ?').run(id).changes) throw bad('Patient not found.', 404);
  res.json({ message: 'Patient deleted.' });
}));

// ---- appointments ----
const APT = `SELECT a.id, 'AP-' || (5000 + a.id) AS code, a.date, a.time, a.status, p.id AS patientId, p.name AS patient,
             d.name AS doctor, dep.name AS department FROM appointments a
             JOIN patients p ON p.id = a.patient_id JOIN doctors d ON d.id = a.doctor_id JOIN departments dep ON dep.id = d.department_id`;
app.get('/api/appointments', auth, (req, res) => res.json(db.prepare(`${APT} ORDER BY a.date DESC, a.time DESC`).all()));
app.post('/api/appointments', auth, wrap((req, res) => {
  const { patientId, doctorId, date, time } = req.body || {};
  const p = db.prepare('SELECT id FROM patients WHERE id = ?').get(Number(patientId));
  if (!p) throw bad('Choose a registered patient.', 404);
  const d = db.prepare('SELECT * FROM doctors WHERE id = ?').get(Number(doctorId));
  if (!d) throw bad('Choose a doctor from the list.', 404);
  if (!validDate(String(date))) throw bad('Enter a valid date.');
  if (date < today()) throw bad('Appointments cannot be booked in the past.');
  if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(String(time))) throw bad('Enter a valid time.');
  if (time < d.start_time || time >= d.end_time) throw bad(`${d.name} sees patients from ${d.start_time} to ${d.end_time}.`);
  try {
    const r = db.prepare('INSERT INTO appointments(patient_id,doctor_id,date,time) VALUES(?,?,?,?)').run(p.id, d.id, date, time);
    res.status(201).json(db.prepare(`${APT} WHERE a.id = ?`).get(r.lastInsertRowid));
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') throw bad(`${d.name} is already booked at ${time} on ${date}.`, 409);
    throw e;
  }
}));
app.patch('/api/appointments/:id', auth, wrap((req, res) => {
  const id = num(req.params.id), status = req.body && req.body.status;
  if (!['Completed', 'Cancelled'].includes(status)) throw bad('Status must be Completed or Cancelled.');
  const cur = db.prepare('SELECT status FROM appointments WHERE id = ?').get(id);
  if (!cur) throw bad('Appointment not found.', 404);
  if (cur.status !== 'Confirmed') throw bad(`This appointment is already ${cur.status.toLowerCase()}.`, 409);
  db.prepare('UPDATE appointments SET status = ? WHERE id = ?').run(status, id);
  res.json(db.prepare(`${APT} WHERE a.id = ?`).get(id));
}));

// ---- dashboard ----
app.get('/api/dashboard', auth, (req, res) => {
  const one = (sql, ...a) => db.prepare(sql).get(...a).n, t = today();
  res.json({
    patients: one('SELECT COUNT(*) n FROM patients'), doctors: one('SELECT COUNT(*) n FROM doctors'),
    upcoming: one("SELECT COUNT(*) n FROM appointments WHERE status = 'Confirmed' AND date >= ?", t),
    today: db.prepare(`${APT} WHERE a.date = ? AND a.status <> 'Cancelled' ORDER BY a.time`).all(t)
  });
});

// ---- errors ----
app.use('/api', (req, res, next) => next(bad('Unknown API route.', 404)));
app.use((err, req, res, next) => {
  const status = err.type === 'entity.parse.failed' ? 400 : err.status || 500;
  if (status === 500) console.error(err);
  res.status(status).json({ error: status === 500 ? 'Something went wrong on the server.' : err.type ? 'Invalid JSON.' : err.message });
});
module.exports = app;
