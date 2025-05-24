import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import { UserModel, User } from '../models/User';

// Validación de contraseña según estándar ISO/IEC 27002 - A.9.2.4
const validatePassword = (password: string): { valid: boolean; message: string } => {
  // Requisitos mínimos de contraseña
  const minLength = 10;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  
  if (password.length < minLength) {
    return { valid: false, message: `La contraseña debe tener al menos ${minLength} caracteres` };
  }
  
  if (!hasUpperCase) {
    return { valid: false, message: 'La contraseña debe contener al menos una letra mayúscula' };
  }
  
  if (!hasLowerCase) {
    return { valid: false, message: 'La contraseña debe contener al menos una letra minúscula' };
  }
  
  if (!hasNumbers) {
    return { valid: false, message: 'La contraseña debe contener al menos un número' };
  }
  
  if (!hasSpecialChar) {
    return { valid: false, message: 'La contraseña debe contener al menos un carácter especial' };
  }
  
  return { valid: true, message: 'Contraseña válida' };
};

export const register = async (req: Request, res: Response) => {
  try {
    const { username, email, password, confirmPassword } = req.body;
    
    // Verificar que los campos requeridos estén presentes
    if (!username || !email || !password) {
      res.status(400).json({ message: 'Todos los campos son requeridos' });
      return;
    }
    
    // Verificar que las contraseñas coincidan
    if (password !== confirmPassword) {
      res.status(400).json({ message: 'Las contraseñas no coinciden' });
      return;
    }
    
    // Validar la contraseña según política de seguridad
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      res.status(400).json({ message: passwordValidation.message });
      return;
    }
    
    // Crear el usuario en la base de datos
    const userId = await UserModel.create({ username, email, password });
    
    res.status(201).json({ message: 'Usuario registrado exitosamente', userId });
    return;
  } catch (error) {
    console.error('Error al registrar usuario:', error);
    res.status(500).json({ message: 'Error en el servidor' });
    return;
  }
};

export const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    
    // Verificar que los campos requeridos estén presentes
    if (!email || !password) {
      res.status(400).json({ message: 'Email y contraseña son requeridos' });
      return;
    }
    
    // Verificar credenciales
    const user = await UserModel.verifyPassword(email, password);
    
    if (!user) {
      res.status(401).json({ message: 'Credenciales inválidas' });
      return;
    }
    
    // Verificar si tiene MFA habilitado
    const hasMfa = await UserModel.hasMfaEnabled(user.id as number);
    
    if (hasMfa) {
      // Si tiene MFA, generar un token temporal para la verificación MFA
      const tempToken = jwt.sign(
        { id: user.id, requiresMfa: true },
        process.env.JWT_SECRET || 'your-secret-key',
        { expiresIn: '5m' }
      );
      
      res.status(200).json({
        message: 'MFA requerido',
        requiresMfa: true,
        tempToken
      });
      return;
    }
    
    // Si no tiene MFA, generar token JWT normal
    const token = jwt.sign(
      { id: user.id },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );
    
    res.status(200).json({
      message: 'Login exitoso',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });
    return;
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ message: 'Error en el servidor' });
    return;
  }
};

export const setupMfa = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.id;
    
    // Generar un secreto TOTP (conforme a RFC 6238)
    const secret = speakeasy.generateSecret({
      length: 20,
      name: `SecureReactApp:${userId}`
    });
    
    // Guardar el secreto en la base de datos
    await UserModel.saveMfaSecret(userId, secret.base32);
    
    // Generar código QR para configuración en app de autenticación
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url || '');
    
    res.status(200).json({
      message: 'MFA configurado correctamente',
      secret: secret.base32,
      qrCode: qrCodeUrl
    });
    return;
  } catch (error) {
    console.error('Error al configurar MFA:', error);
    res.status(500).json({ message: 'Error en el servidor' });
    return;
  }
};

export const verifyMfa = async (req: Request, res: Response) => {
  try {
    const { token, userId } = req.body;
    
    if (!token || !userId) {
      res.status(400).json({ message: 'Token y userId son requeridos' });
      return;
    }
    
    // Obtener el secreto MFA del usuario
    const secret = await UserModel.getMfaSecret(userId);
    
    if (!secret) {
      res.status(400).json({ message: 'MFA no configurado para este usuario' });
      return;
    }
    
    // Verificar el token TOTP
    const verified = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 1 // Permite una ventana de 1 intervalo (30 segundos por defecto)
    });
    
    if (!verified) {
      res.status(401).json({ message: 'Código MFA inválido' });
      return;
    }
    
    // Generar token JWT completo
    const jwtToken = jwt.sign(
      { id: userId },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );
    
    res.status(200).json({
      message: 'Verificación MFA exitosa',
      token: jwtToken
    });
    return;
  } catch (error) {
    console.error('Error en verificación MFA:', error);
    res.status(500).json({ message: 'Error en el servidor' });
    return;
  }
};
