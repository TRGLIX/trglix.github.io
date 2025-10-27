const express = require('express');
const bodyParser = require('body-parser');
const jwksRsa = require('jwks-rsa');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));

/* ------------- CONFIGURA AQUÍ ------------- */
const PORT = process.env.PORT || 3000;
const AZURE_TENANT = 'TU_TENANT_ID'; // p.ej. f19d0d8c-...
const AZURE_ISS = `https://login.microsoftonline.com/${AZURE_TENANT}/v2.0`;
/* ------------------------------------------ */

// Inicializa Firebase Admin (usa tu service-account.json descargado desde Google Cloud Console)
admin.initializeApp({
  credential: admin.credential.cert(require('./service-account.json'))
});
const db = admin.firestore();

const app = express();
app.use(bodyParser.json());
app.use(express.static('public')); // si sirves frontend estático desde /public

// JWKS client para Microsoft (documentación Microsoft: /.well-known/openid-configuration)
const jwksUri = `https://login.microsoftonline.com/${AZURE_TENANT}/discovery/v2.0/keys`;
const client = jwksRsa({
  jwksUri,
  cache: true,
  rateLimit: true
});

// Función para obtener key y verificar token
function getKey(header, callback) {
  client.getSigningKey(header.kid, function(err, key) {
    if (err) return callback(err);
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

// Endpoint que el frontend llama con el idToken
app.post('/auth/azure', async (req, res) => {
  const { idToken } = req.body;
  if (!idToken) return res.status(400).json({ message: 'Falta idToken' });

  // Verificamos token
  jwt.verify(idToken, getKey, {
    issuer: AZURE_ISS,
    algorithms: ['RS256'],
    audience: 'TU_CLIENT_ID' // clientId de tu app en Azure
  }, async (err, decoded) => {
    if (err) {
      console.error('Token inválido:', err);
      return res.status(401).json({ message: 'Token inválido' });
    }

    // decoded contiene claims, p.ej. email, sub, name, oid...
    const email = decoded.email || decoded.preferred_username;
    const uidAzure = decoded.oid || decoded.sub;

    if (!email || !uidAzure) {
      return res.status(400).json({ message: 'No hay datos de usuario suficientes' });
    }

    try {
      // Crear/actualizar documento en Firestore (colección 'users')
      const userRef = db.collection('users').doc(uidAzure);
      await userRef.set({
        email,
        name: decoded.name || null,
        azureSub: uidAzure,
        lastLogin: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });

      // Opcional: crear token de sesión propio (JWT firmado por tu backend) o cookie
      // Para el ejemplo devolvemos OK
      return res.json({ ok: true });
    } catch (error) {
      console.error('Error creando usuario en Firestore:', error);
      return res.status(500).json({ message: 'Error en servidor' });
    }
  });
});

app.listen(PORT, () => console.log(`Server arrancado en http://localhost:${PORT}`));
