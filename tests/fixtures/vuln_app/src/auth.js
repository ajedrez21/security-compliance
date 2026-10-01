const jwt = require('jsonwebtoken');

function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try {
    // Firma verificada, algoritmo fijado, emisor y audiencia validados.
    req.user = jwt.verify(token, process.env.JWT_PUBLIC_KEY, {
      algorithms: ['RS256'], issuer: 'https://idp.example.invalid', audience: 'vuln-app',
    });
    next();
  } catch (e) {
    res.status(401).json({ error: 'unauthorized' });
  }
}

function requireRole(role) {
  return (req, res, next) => (req.user && req.user.roles && req.user.roles.includes(role)
    ? next() : res.status(403).json({ error: 'forbidden' }));
}

module.exports = { requireAuth, requireRole };
