import express, { Request, Response, NextFunction, RequestHandler } from 'express';
import { register, login, setupMfa, verifyMfa } from '../controllers/authController';
import { auth } from '../middleware/auth';
import { requireMfa } from '../middleware/requireMfa';

// Wrapper para controladores async
const asyncHandler = (
  fn: (req: Request, res: Response, next: NextFunction) => Promise<any> | any
): RequestHandler => {
  return ((req: Request, res: Response, next: NextFunction): void => {
    Promise.resolve(fn(req, res, next)).catch(next);
  }) as RequestHandler;
};

const router = express.Router();

// Rutas públicas
router.post('/register', asyncHandler(register));
router.post('/login', asyncHandler(login));
router.post('/verify-mfa', requireMfa, asyncHandler(verifyMfa));

// Rutas protegidas
router.post('/setup-mfa', auth, asyncHandler(setupMfa));

export default router;
