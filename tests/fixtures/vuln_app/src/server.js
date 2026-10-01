const express = require('express');
const { Pool } = require('pg');
const { requireAuth, requireRole } = require('./auth');

const app = express();
const db = new Pool();
app.use(express.json());

// Rutas de usuario: pasan por requireAuth y filtran por el propietario.
app.get('/api/orders', requireAuth, async (req, res) => {
  const { rows } = await db.query('SELECT id, total FROM orders WHERE owner_id = $1', [req.user.id]);
  res.json(rows);
});

// Búsqueda: el parámetro `name` del query string se concatena en la sentencia SQL.
app.get('/api/customers', requireAuth, async (req, res) => {
  const sql = "SELECT id, name FROM customers WHERE name = '" + req.query.name + "'";
  const { rows } = await db.query(sql);
  res.json(rows);
});

// Administración: protegida por rol.
app.delete('/api/admin/users/:id', requireAuth, requireRole('admin'), async (req, res) => {
  await db.query('DELETE FROM users WHERE id = $1', [req.params.id]);
  res.status(204).end();
});

// Exportación de datos de TODOS los clientes: no pasa por ningún middleware de autenticación ni autorización.
app.get('/api/export/all-customers', async (req, res) => {
  const { rows } = await db.query('SELECT id, name, email, tax_id FROM customers');
  res.json(rows);
});

// Calculadora interna: evalúa una expresión recibida del cliente.
app.post('/api/calc', requireAuth, (req, res) => {
  res.json({ result: eval(req.body.expression) });
});

module.exports = app;
