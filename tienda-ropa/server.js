const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();
const db = new sqlite3.Database('./database.db');

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: 'ropa123',
  resave: false,
  saveUninitialized: true
}));

// Crear tabla users
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  dni TEXT UNIQUE NOT NULL,
  role TEXT NOT NULL,
  otp TEXT
)`);

// Crear tabla productos
db.run(`CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY,
  name TEXT,
  category TEXT,
  price REAL,
  image TEXT,
  stock INTEGER
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
      req.session.msg = "Usuario no encontrado.";
      return res.redirect('/login');
    }

    bcrypt.compare(password, user.password, (err, result) => {
      if (!result) {
        req.session.msg = "Contraseña incorrecta.";
        return res.redirect('/login');
      }

      if (user.role === 'admin' && user.otp) {
        req.session.tempUser = user;
        return res.redirect('/verificar-otp');
      }

      req.session.user = user;
      res.redirect(user.role === 'admin' ? '/dashboard' : '/comprar');
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

  db.get("SELECT * FROM users WHERE dni = ? OR username = ?", [dni, username], (err, existing) => {
    if (existing) {
      req.session.msg = "Usuario o DNI ya registrado.";
      return res.redirect('/register');
    }

    bcrypt.hash(password, 10, (err, hash) => {
      if (role === 'admin') {
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const transporter = nodemailer.createTransport({
          service: 'gmail',
          auth: {
            user: 'tucorreo@gmail.com',
            pass: 'clave_de_aplicacion'
          }
        });

        const mailOptions = {
          from: 'tucorreo@gmail.com',
          to: username,
          subject: 'Código de autenticación',
          text: `Tu código es: ${otp}`
        };

        transporter.sendMail(mailOptions, (error) => {
          if (error) {
            req.session.msg = "Error al enviar OTP.";
            return res.redirect('/register');
          }

          db.run("INSERT INTO users (username, password, dni, role, otp) VALUES (?, ?, ?, ?, ?)",
            [username, hash, dni, role, otp], (err) => {
              if (err) {
                req.session.msg = "Error al registrar.";
                return res.redirect('/register');
              }

              req.session.tempUser = { username };
              res.redirect('/verificar-otp');
            });
        });
      } else {
        db.run("INSERT INTO users (username, password, dni, role) VALUES (?, ?, ?, ?)",
          [username, hash, dni, role], (err) => {
            if (err) {
              req.session.msg = "Error al registrar.";
              return res.redirect('/register');
            }

            req.session.user = { username, role };
            res.redirect('/comprar');
          });
      }
    });
  });
});

app.get('/verificar-otp', (req, res) => {
  if (!req.session.tempUser) return res.redirect('/login');
  res.render('otp');
});

app.post('/verificar-otp', (req, res) => {
  const { codigo } = req.body;
  const username = req.session.tempUser.username;

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (user.otp === codigo) {
      db.run("UPDATE users SET otp = NULL WHERE username = ?", [username]);
      req.session.user = user;
      req.session.tempUser = null;
      res.redirect('/dashboard');
    } else {
      req.session.msg = "Código incorrecto.";
      res.redirect('/verificar-otp');
    }
  });
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
    res.render('dashboard', { user: req.session.user, productsByCategory });
  });
});

app.post('/add-product', (req, res) => {
  const { name, category, price, image, stock } = req.body;
  db.run("INSERT INTO products (name, category, price, image, stock) VALUES (?, ?, ?, ?, ?)",
    [name, category, price, image, stock], () => res.redirect('/dashboard'));
});

app.post('/delete-product/:id', (req, res) => {
  db.run("DELETE FROM products WHERE id = ?", [req.params.id], () => res.redirect('/dashboard'));
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.listen(3000, () => console.log("Servidor en http://localhost:3000"));
