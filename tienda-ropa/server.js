const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
const db = new sqlite3.Database('./database.db');

// Configurar EJS y middlewares
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: 'ropa123',
  resave: false,
  saveUninitialized: true,
}));

// Crear tablas si no existen
// BORRA y CREA tabla de usuarios con validaciones
db.run(`DROP TABLE IF EXISTS users`);
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  dni TEXT UNIQUE NOT NULL,
  role TEXT NOT NULL
)`);


db.run(`CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY,
  name TEXT,
  category TEXT,
  price REAL,
  image TEXT,
  stock INTEGER
)`);

// Configurar nodemailer con tu correo
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'eldiego241@gmail.com',
    pass: 'vckn hral hddj xamt' // contraseña de aplicación de Gmail
  }
});

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

        if (user.role === 'admin') {
          res.redirect('/dashboard');
        } else {
          res.redirect('/comprar');
        }
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
  const { username, password, dni, role } = req.body;

  if (password.length < 8) {
    req.session.msg = "La contraseña debe tener al menos 8 caracteres.";
    return res.redirect('/register');
  }

  db.get("SELECT * FROM users WHERE dni = ? OR username = ?", [dni, username], (err, existingUser) => {
    if (existingUser) {
      req.session.msg = "Usuario o DNI ya registrado.";
      return res.redirect('/register');
    }

    bcrypt.hash(password, 10, (err, hash) => {
      db.run("INSERT INTO users (username, password, dni, role) VALUES (?, ?, ?, ?)",
        [username, hash, dni, role],
        (err) => {
          if (err) {
            console.error("Error al registrar:", err.message);
            req.session.msg = "Error al registrar.";
            return res.redirect('/register');
          }

          req.session.user = { username, role };

          if (role === 'admin') {
            const otp = Math.floor(100000 + Math.random() * 900000).toString();

            transporter.sendMail({
              from: 'eldiego241@gmail.com',
              to: username,
              subject: 'Código OTP de acceso',
              text: `Tu código OTP es: ${otp}`
            }, (error, info) => {
              if (error) {
                console.error("Error al enviar OTP:", error.message);
                req.session.msg = "Error al enviar OTP.";
                return res.redirect('/register');
              }

              console.log("OTP enviado:", otp);
              req.session.otp = otp;
              return res.redirect('/dashboard');
            });
          } else {
            return res.redirect('/comprar');
          }
        });
    });
  });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});


app.get('/dashboard', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') return res.redirect('/login');

  db.all("SELECT * FROM products", (err, products) => {
    const categories = ['Polos', 'Pantalones', 'Camisas', 'Casacas', 'Blusas', 'Chompas', 'Poleras'];
    const productsByCategory = {};
    categories.forEach(cat => {
      productsByCategory[cat] = products.filter(p => p.category === cat);
    });
    res.render('dashboard', { user: req.session.user, productsByCategory });
  });
});

app.get('/comprar', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'cliente') return res.redirect('/login');

  db.all("SELECT * FROM products", (err, products) => {
    const categories = ['Polos', 'Pantalones', 'Camisas', 'Casacas', 'Blusas', 'Chompas', 'Poleras'];
    const productsByCategory = {};
    categories.forEach(cat => {
      productsByCategory[cat] = products.filter(p => p.category === cat);
    });
    res.render('comprar', { user: req.session.user, productsByCategory });
  });
});

app.post('/add-product', (req, res) => {
  const { name, category, price, image, stock } = req.body;
  db.run("INSERT INTO products (name, category, price, image, stock) VALUES (?, ?, ?, ?, ?)",
    [name, category, price, image, stock],
    (err) => {
      if (err) console.error("Error al agregar producto:", err.message);
      res.redirect('/dashboard');
    });
});

app.post('/delete-product/:id', (req, res) => {
  db.run("DELETE FROM products WHERE id = ?", [req.params.id], () => {
    res.redirect('/dashboard');
  });
});

app.listen(3000, () => {
  console.log("Servidor corriendo en http://localhost:3000");
});
