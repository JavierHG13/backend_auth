import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

export const db = await mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME
});

try {
  await db.connect();
  console.log('Conectado a la base de datos MySQL');
} catch (error) {
  console.error('Error al conectar con la base de datos:', error);
}
