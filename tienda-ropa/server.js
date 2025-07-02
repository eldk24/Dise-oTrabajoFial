// server.js
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

// BORRA y CREA tabla de usuarios con validaciones
// db.run(`DROP TABLE IF EXISTS users`);
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  dni TEXT UNIQUE NOT NULL
)`);

// CREA tabla de productos con categoría y stock
// db.run(`DROP TABLE IF EXISTS products`);
db.run(`CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY,
  name TEXT,
  category TEXT,
  price REAL,
  image TEXT,
  stock TEXT
)`);


// Rutas
app.get('/', (req, res) => res.redirect('/login'));

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

  db.get("SELECT * FROM users WHERE dni = ? OR username = ?", [dni, username], (err, existingUser) => {
    if (existingUser) {
      if (existingUser.dni === dni) {
        req.session.msg = "Este DNI ya está registrado.";
      } else if (existingUser.username === username) {
        req.session.msg = "Este nombre de usuario ya está en uso.";
      } else {
        req.session.msg = "Usuario o DNI ya están registrados.";
      }
      return res.redirect('/register');
    }

    bcrypt.hash(password, 10, (err, hash) => {
      db.run("INSERT INTO users (username, password, dni) VALUES (?, ?, ?)", [username, hash, dni], (err) => {
        if (err) {
          console.error("Error en INSERT:", err.message);
          req.session.msg = "Error inesperado al registrar.";
          return res.redirect('/register');
        }
        res.redirect('/login');
      });
    });
  });
});

app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  db.all("SELECT * FROM products", (err, products) => {
    const categories = ['Polos', 'Pantalones', 'Camisas', 'Casacas', 'Blusas', 'Chompas', 'Poleras'];
    const productsByCategory = {};
    categories.forEach(cat => {
      productsByCategory[cat] = products.filter(p => p.category === cat);
    });
    res.render('dashboard', { user: req.session.user, productsByCategory });
  });
});

app.post('/add-product', (req, res) => {
  const { name, category, price, image, stock } = req.body;
  db.run(
    "INSERT INTO products (name, category, price, image, stock) VALUES (?, ?, ?, ?, ?)",
    [name, category, price, image, stock],
    (err) => {
      if (err) {
        console.error("Error al insertar producto:", err.message); // 👈 VER ESTO EN TERMINAL
      }
      res.redirect('/dashboard');
    }
  );
});


app.post('/delete-product/:id', (req, res) => {
  db.run("DELETE FROM products WHERE id = ?", [req.params.id], () => {
    res.redirect('/dashboard');
  });
});

app.listen(3000, () => console.log("Servidor corriendo en http://localhost:3000"));
