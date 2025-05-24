import pool from '../config/database';

export class MfaCodeModel {
  static async create(userId: number, code: string, expiresAt: Date): Promise<void> {
    await pool.execute(
      'INSERT INTO mfa_codes (user_id, code, expires_at) VALUES (?, ?, ?)',
      [userId, code, expiresAt]
    );
  }

  static async findValidCode(userId: number, code: string): Promise<any | null> {
    const [rows] = await pool.execute(
      `SELECT * FROM mfa_codes
       WHERE user_id = ? AND code = ? AND used = FALSE AND expires_at > NOW()
       ORDER BY created_at DESC LIMIT 1`,
      [userId, code]
    );
    const codes = rows as any[];
    return codes.length > 0 ? codes[0] : null;
  }

  static async markAsUsed(id: number): Promise<void> {
    await pool.execute(
      'UPDATE mfa_codes SET used = TRUE WHERE id = ?',
      [id]
    );
  }
}
