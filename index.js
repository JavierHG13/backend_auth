import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import dotenv from 'dotenv';
import session from 'express-session';
import authRoutes from './src/routes/authRoutes.js';
import './src/config/db.js' // Importa la conexión para inicializarla

dotenv.config();

const app = express();

const FRONTEND_URL = process.env.FRONTEND_URL

app.use(morgan('dev'));
app.use(cors({
  origin: FRONTEND_URL, 
  credentials: true
}));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // poner true si usas HTTPS
}));
app.use('/api/auth', authRoutes);

// Ruta de prueba
app.get('/', (req, res) => {
  res.json({ message: 'Servidor funcionando correctamente' });
});

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
