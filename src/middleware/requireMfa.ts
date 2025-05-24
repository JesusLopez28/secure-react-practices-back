import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { UserModel } from '../models/User';

export const requireMfa = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    // Obtener token del encabezado
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ message: 'No autorizado - Token no proporcionado' });
      return;
    }
    
    const token = authHeader.split(' ')[1];
    
    // Verificar el token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key') as any;
    
    // Si el token requiere MFA pero la solicitud no está en la ruta de verificación MFA
    if (decoded.requiresMfa && req.path !== '/verify-mfa') {
      res.status(403).json({ message: 'Verificación MFA requerida' });
      return;
    }
    
    // Agregar datos del usuario a la solicitud para su uso posterior
    (req as any).user = { id: decoded.id };
    
    next();
  } catch (error) {
    console.error('Error en middleware MFA:', error);
    res.status(401).json({ message: 'Token inválido o expirado' });
    return;
  }
};
