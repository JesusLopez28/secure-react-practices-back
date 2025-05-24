import pool from '../config/database';
import bcrypt from 'bcryptjs';
import CryptoJS from 'crypto-js';

export interface User {
  id?: number;
  username: string;
  email: string;
  password: string;
  mfa_enabled?: boolean;
  mfa_secret?: string;
  created_at?: Date;
}

export class UserModel {
  // Crear un nuevo usuario con contraseña segura (hash con salt)
  static async create(userData: User): Promise<number> {
    const { username, email, password } = userData;
    
    // Hash de la contraseña según ISO/IEC 27002 - A.9.2.4
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    // Cifrar el email según prácticas de seguridad
    const encryptedEmail = CryptoJS.AES.encrypt(
      email, 
      process.env.EMAIL_ENCRYPTION_KEY || 'default-secret-key'
    ).toString();

    const [result] = await pool.execute(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username, encryptedEmail, hashedPassword]
    );
    
    return (result as any).insertId;
  }

  // Verificar contraseña del usuario
  static async verifyPassword(email: string, password: string): Promise<User | null> {
    const [rows] = await pool.execute(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );
    
    const users = rows as User[];
    if (users.length === 0) return null;
    
    const user = users[0];
    const isValid = await bcrypt.compare(password, user.password);
    
    return isValid ? user : null;
  }

  // Obtener usuario por ID
  static async getById(id: number): Promise<User | null> {
    const [rows] = await pool.execute(
      'SELECT * FROM users WHERE id = ?',
      [id]
    );
    
    const users = rows as User[];
    return users.length > 0 ? users[0] : null;
  }

  // Guardar secreto MFA para un usuario
  static async saveMfaSecret(userId: number, secret: string): Promise<boolean> {
    await pool.execute(
      'UPDATE users SET mfa_secret = ?, mfa_enabled = ? WHERE id = ?',
      [secret, true, userId]
    );
    
    return true;
  }

  // Verificar si el usuario tiene MFA habilitado
  static async hasMfaEnabled(userId: number): Promise<boolean> {
    const [rows] = await pool.execute(
      'SELECT mfa_enabled FROM users WHERE id = ?',
      [userId]
    );
    
    const users = rows as User[];
    return users.length > 0 ? !!users[0].mfa_enabled : false;
  }

  // Obtener secreto MFA de un usuario
  static async getMfaSecret(userId: number): Promise<string | null> {
    const [rows] = await pool.execute(
      'SELECT mfa_secret FROM users WHERE id = ? AND mfa_enabled = true',
      [userId]
    );
    
    const users = rows as User[];
    return users.length > 0 ? users[0].mfa_secret || null : null;
  }
}
