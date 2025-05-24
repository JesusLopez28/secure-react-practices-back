import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import { UserModel } from '../models/User';
import { MfaCodeModel } from '../models/MfaCode';

// Configuración de nodemailer
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: Number(process.env.EMAIL_PORT),
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
});

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
    
    // Buscar usuario por email en texto plano
    const user = await UserModel.verifyPassword(email, password);
    if (!user) {
      return res.status(401).json({ message: 'Credenciales inválidas. Verifica tu correo y contraseña.' });
    }

    // Generar código MFA y guardarlo en la base de datos
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutos
    await MfaCodeModel.create(user.id!, code, expiresAt);

    // Enviar el código por correo
    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: user.email,
      subject: 'Código de verificación 2FA',
      text: `Tu código de verificación es: ${code}`,
      html: `<p>Tu código de verificación es: <b>${code}</b></p>`
    });

    res.status(200).json({
      message: 'MFA requerido',
      requiresMfa: true,
      tempEmail: user.email
    });
    return;
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ message: 'Error en el servidor. Intenta de nuevo más tarde.' });
    return;
  }
};

// Endpoint para verificar el código MFA enviado por email
export const verifyMfa = async (req: Request, res: Response) => {
  try {
    const { code, email } = req.body;
    if (!code || !email) {
      res.status(400).json({ message: 'Código y email son requeridos' });
      return;
    }

    // Buscar usuario
    const user = await UserModel.getByEmail(email);
    if (!user) {
      res.status(400).json({ message: 'Usuario no encontrado' });
      return;
    }

    // Buscar código válido en la base de datos
    const mfaCode = await MfaCodeModel.findValidCode(user.id!, code);
    if (!mfaCode) {
      res.status(401).json({ message: 'Código MFA inválido o expirado' });
      return;
    }

    // Marcar el código como usado
    await MfaCodeModel.markAsUsed(mfaCode.id);

    // Generar token JWT completo
    const jwtToken = jwt.sign(
      { id: user.id },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.status(200).json({
      message: 'Verificación MFA exitosa',
      token: jwtToken,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });
    return;
  } catch (error) {
    console.error('Error en verificación MFA:', error);
    res.status(500).json({ message: 'Error en el servidor' });
    return;
  }
};
