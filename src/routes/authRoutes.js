import { Router } from 'express';
import { 
    register, 
    verifyEmail, 
    resendCode, 
    login, 
    googleAuth,
    forgotPassword,           
    verifyRecoveryCode,    
    resetPassword,      
    resendRecoveryCode
} from '../controllers/authController.js';


const router = Router();

// Rutas de registro
router.post('/register', register);
router.post('/verify-email', verifyEmail);
router.post('/resend-code', resendCode);

// Rutas de login
router.post('/login', login);
router.post('/google-auth', googleAuth);

// Rutas de recuperación de contraseña
router.post('/forgot-password', forgotPassword);
router.post('/verify-recovery-code', verifyRecoveryCode);
router.post('/reset-password', resetPassword);
router.post('/resend-recovery-code', resendRecoveryCode);

export default router;
