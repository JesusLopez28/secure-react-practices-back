import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import authRoutes from './routes/authRoutes';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware de seguridad
app.use(helmet()); // Añade encabezados de seguridad
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173', // Permitir solo desde el frontend
  credentials: true
}));

// Middleware para JSON
app.use(express.json());

// Rutas
app.use('/api/auth', authRoutes);

// Manejador de errores
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Error interno del servidor' });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor funcionando en el puerto ${PORT}`);
});

export default app;
