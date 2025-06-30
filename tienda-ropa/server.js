const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');
const app = express();
const db = new sqlite3.Database('./database.db');

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: 'ropa123',
  resave: false,
  saveUninitialized: true,
}));

// Crear tablas si no existen
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL,
  password TEXT NOT NULL,
  dni TEXT UNIQUE NOT NULL
)`);

db.run(`CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY,
  name TEXT,
  price REAL,
  image TEXT
)`);

// Rutas
app.get('/', (req, res) => res.redirect('/login'));

// --- LOGIN ---
app.get('/login', (req, res) => {
  const msg = req.session.msg || null;
  req.session.msg = null;
  res.render('login', { msg });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (!user) {
      req.session.msg = "Usuario no existe.";
      return res.redirect('/login');
    }
    bcrypt.compare(password, user.password, (err, result) => {
      if (result) {
        req.session.user = user;
        res.redirect('/dashboard');
      } else {
        req.session.msg = "Contraseña incorrecta.";
        res.redirect('/login');
      }
    });
  });
});

// --- REGISTRO ---
app.get('/register', (req, res) => {
  const msg = req.session.msg || null;
  req.session.msg = null;
  res.render('register', { msg });
});

app.post('/register', (req, res) => {
  const { username, password, dni } = req.body;

  if (password.length < 8) {
    req.session.msg = "La contraseña debe tener al menos 8 caracteres.";
    return res.redirect('/register');
  }

  db.get("SELECT * FROM users WHERE dni = ?", [dni], (err, existingUser) => {
    if (existingUser) {
      req.session.msg = "Este DNI ya está registrado.";
      return res.redirect('/register');
    }

    bcrypt.hash(password, 10, (err, hash) => {
      db.run("INSERT INTO users (username, password, dni) VALUES (?, ?, ?)", [username, hash, dni], (err) => {
        if (err) {
          req.session.msg = "Error al registrar. Intenta con otro usuario o DNI.";
          return res.redirect('/register');
        }
        res.redirect('/login');
      });
    });
  });
});

// --- DASHBOARD ---
app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  db.all("SELECT * FROM products", (err, products) => {
    res.render('dashboard', { user: req.session.user, products });
  });
});

// --- AGREGAR PRODUCTO ---
app.post('/add-product', (req, res) => {
  const { name, price, image } = req.body;
  db.run("INSERT INTO products (name, price, image) VALUES (?, ?, ?)", [name, price, image], () => {
    res.redirect('/dashboard');
  });
});

// --- ELIMINAR PRODUCTO ---
app.post('/delete-product/:id', (req, res) => {
  db.run("DELETE FROM products WHERE id = ?", [req.params.id], () => {
    res.redirect('/dashboard');
  });
});

// --- INICIAR SERVIDOR ---
app.listen(3000, () => console.log("Servidor corriendo en http://localhost:3000"));
