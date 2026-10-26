// Data layer: SQLite schema, constraints and seed data.
const Database = require('better-sqlite3'), fs = require('fs'), path = require('path'), bcrypt = require('bcryptjs');
const file = process.env.DB_PATH || path.join(__dirname, 'data', 'carepoint.db');
if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
const db = new Database(file);
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL COLLATE NOCASE,
  password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('admin','reception')));
CREATE TABLE IF NOT EXISTS departments (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS doctors (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, specialty TEXT NOT NULL,
  department_id INTEGER NOT NULL REFERENCES departments(id),
  start_time TEXT NOT NULL, end_time TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS patients (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, age INTEGER NOT NULL CHECK (age BETWEEN 0 AND 120),
  gender TEXT NOT NULL, phone TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS appointments (
  id INTEGER PRIMARY KEY,
  patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  doctor_id INTEGER NOT NULL REFERENCES doctors(id),
  date TEXT NOT NULL, time TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Confirmed' CHECK (status IN ('Confirmed','Completed','Cancelled')));
-- The database itself prevents double-booking, even under concurrent requests.
CREATE UNIQUE INDEX IF NOT EXISTS one_doctor_one_slot ON appointments(doctor_id, date, time) WHERE status <> 'Cancelled';
`);

if (!db.prepare('SELECT 1 FROM users').get()) {
  const u = db.prepare('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)');
  u.run('admin', bcrypt.hashSync('Admin@123', 10), 'admin');
  u.run('reception', bcrypt.hashSync('Reception@123', 10), 'reception');
  const dep = db.prepare('INSERT INTO departments(name) VALUES(?)');
  const ids = {};
  for (const n of ['General Medicine', 'Cardiology', 'Neurology', 'Pediatrics', 'Orthopedics', 'Dermatology']) ids[n] = dep.run(n).lastInsertRowid;
  const doc = db.prepare('INSERT INTO doctors(name,specialty,department_id,start_time,end_time) VALUES(?,?,?,?,?)');
  [['Dr. Priya Sharma', 'Cardiologist', 'Cardiology', '09:00', '14:00'], ['Dr. Arjun Rao', 'General Physician', 'General Medicine', '10:00', '16:00'],
   ['Dr. Meera Iyer', 'Dermatologist', 'Dermatology', '09:30', '13:30'], ['Dr. Karthik Nair', 'Orthopedic Surgeon', 'Orthopedics', '11:00', '17:00'],
   ['Dr. Sneha Patel', 'Pediatrician', 'Pediatrics', '09:00', '15:00'], ['Dr. Vikram Das', 'Neurologist', 'Neurology', '12:00', '18:00']]
    .forEach(([n, s, d, a, b]) => doc.run(n, s, ids[d], a, b));
}
module.exports = db;
