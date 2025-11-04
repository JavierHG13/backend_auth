import bcrypt from 'bcryptjs';
import transporter from '../config/mailer.js';
import { db } from '../config/db.js';
import { OAuth2Client } from "google-auth-library";
import { createToken } from '../config/jwt.js';
import { tempStorage } from '../config/tempStorage.js';

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

export const register = async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password)
        return res.status(400).json({ message: 'Todos los campos son requeridos' });

    try {
        const [existing] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

        if (existing.length > 0)
            return res.status(400).json({ message: 'El correo ya está registrado' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const verificationCode = Math.floor(100000 + Math.random() * 900000);

        // Guardar en Map en vez de sesión
        tempStorage.saveRegistration(email, {
            name,
            email,
            password: hashedPassword,
            verificationCode
        });

        console.log(' Registro guardado:', email, '- Código:', verificationCode);

        await transporter.sendMail({
            from: `"Soporte" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Verificación de correo electrónico',
            html: `
                <h2>Hola ${name}</h2>
                <p>Tu código de verificación es:</p>
                <h3>${verificationCode}</h3>
                <p>Ingresa este código en la aplicación para activar tu cuenta.</p>
            `
        });

        res.json({ message: 'Código de verificación enviado. Revisa tu correo.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error al registrar usuario' });
    }
};

export const verifyEmail = async (req, res) => {
    const { code, email } = req.body;

    console.log("Verificando:", email, "- Código:", code);

    const tempUserData = tempStorage.getRegistration(email);

    if (!tempUserData)
        return res.status(400).json({ message: 'No hay registro pendiente de verificación' });

    const EXPIRATION_TIME = 4 * 60 * 1000;
    if (Date.now() - tempUserData.createdAt > EXPIRATION_TIME) {
        tempStorage.deleteRegistration(email);
        return res.status(400).json({ message: 'El código de verificación ha expirado' });
    }

    try {
        if (parseInt(code) === tempUserData.verificationCode) {
            // Verificar nuevamente que el correo no se haya registrado
            const [existing] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
            if (existing.length > 0) {
                tempStorage.deleteRegistration(email);
                return res.status(400).json({ message: 'El correo ya está registrado' });
            }

            await db.query(
                'INSERT INTO users (name, email, password, verified) VALUES (?, ?, ?, ?)',
                [tempUserData.name, tempUserData.email, tempUserData.password, 1]
            );

            tempStorage.deleteRegistration(email);

            res.json({ message: 'Correo verificado exitosamente. Tu cuenta ha sido creada.' });
        } else {
            res.status(400).json({ message: 'Código incorrecto' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error al verificar el correo' });
    }
};

export const resendCode = async (req, res) => {
    const { email } = req.body;

    const tempUserData = tempStorage.getRegistration(email);

    if (!tempUserData)
        return res.status(400).json({ message: 'No hay registro pendiente de verificación' });

    try {
        const verificationCode = Math.floor(100000 + Math.random() * 900000);

        // Actualizar código
        tempStorage.saveRegistration(email, {
            ...tempUserData,
            verificationCode
        });

        await transporter.sendMail({
            from: `"Soporte" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Nuevo código de verificación',
            html: `
                <h2>Hola ${tempUserData.name}</h2>
                <p>Has solicitado un nuevo código de verificación.</p>
                <p>Tu nuevo código es:</p>
                <h3>${verificationCode}</h3>
                <p>Ingresa este código en la aplicación para activar tu cuenta.</p>
            `
        });

        res.json({ message: 'Nuevo código enviado. Revisa tu correo.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error al reenviar código' });
    }
};

// Recuperación de contraseña
export const forgotPassword = async (req, res) => {
    const { email } = req.body;

    if (!email)
        return res.status(400).json({ message: 'El correo es requerido' });

    try {
        const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

        if (rows.length === 0)
            return res.status(404).json({ message: 'No existe una cuenta con ese correo' });

        const user = rows[0];
        const recoveryCode = Math.floor(100000 + Math.random() * 900000);

        // Guardar en Map
        tempStorage.saveRecovery(email, {
            userId: user.id,
            recoveryCode,
            verified: false
        });

        await transporter.sendMail({
            from: `"Soporte" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Recuperación de contraseña',
            html: `
                <h2>Hola ${user.name}</h2>
                <p>Has solicitado recuperar tu contraseña.</p>
                <p>Tu código de recuperación es:</p>
                <h3>${recoveryCode}</h3>
                <p>Ingresa este código en la aplicación para restablecer tu contraseña.</p>
                <p><small>Este código expira en 10 minutos.</small></p>
            `
        });

        res.json({ message: 'Código de recuperación enviado. Revisa tu correo.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error al procesar la solicitud' });
    }
};

export const verifyRecoveryCode = async (req, res) => {
    const { code, email } = req.body; // Necesitas enviar el email

    const passwordRecovery = tempStorage.getRecovery(email);

    if (!passwordRecovery)
        return res.status(400).json({ message: 'No hay solicitud de recuperación activa' });

    const EXPIRATION_TIME = 10 * 60 * 1000;
    if (Date.now() - passwordRecovery.createdAt > EXPIRATION_TIME) {
        tempStorage.deleteRecovery(email);
        return res.status(400).json({ message: 'El código de recuperación ha expirado' });
    }

    try {
        if (parseInt(code) === passwordRecovery.recoveryCode) {
            // Marcar como verificado
            tempStorage.saveRecovery(email, {
                ...passwordRecovery,
                verified: true
            });
            res.json({ message: 'Código verificado correctamente' });
        } else {
            res.status(400).json({ message: 'Código incorrecto' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error al verificar el código' });
    }
};

export const resetPassword = async (req, res) => {
    const { newPassword, email } = req.body; // Necesitas enviar el email

    const passwordRecovery = tempStorage.getRecovery(email);

    if (!passwordRecovery)
        return res.status(400).json({ message: 'No hay solicitud de recuperación activa' });

    if (!passwordRecovery.verified)
        return res.status(400).json({ message: 'Debes verificar el código primero' });

    if (!newPassword || newPassword.length < 6)
        return res.status(400).json({ message: 'La contraseña debe tener al menos 6 caracteres' });

    const EXPIRATION_TIME = 10 * 60 * 1000;
    if (Date.now() - passwordRecovery.createdAt > EXPIRATION_TIME) {
        tempStorage.deleteRecovery(email);
        return res.status(400).json({ message: 'La sesión ha expirado' });
    }

    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await db.query(
            'UPDATE users SET password = ? WHERE id = ?',
            [hashedPassword, passwordRecovery.userId]
        );

        const [rows] = await db.query('SELECT name FROM users WHERE id = ?', [passwordRecovery.userId]);
        const userName = rows[0]?.name || 'Usuario';

        await transporter.sendMail({
            from: `"Soporte" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Contraseña actualizada',
            html: `
                <h2>Hola ${userName}</h2>
                <p>Tu contraseña ha sido actualizada exitosamente.</p>
            `
        });

        tempStorage.deleteRecovery(email);

        res.json({ message: 'Contraseña actualizada exitosamente' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error al actualizar la contraseña' });
    }

};



export const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password)
        return res.status(400).json({ message: "Correo y contraseña requeridos" });

    try {
        const [rows] = await db.query("SELECT * FROM users WHERE email = ?", [email]);

        if (rows.length === 0)
            return res.status(400).json({ message: "Credenciales incorrectas" });

        const user = rows[0];

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch)
            return res.status(400).json({ message: "Credenciales incorrectas" });

        const token = createToken(user);

        // Guardar sesión (opcional)
        req.session.user = {
            id: user.id,
            name: user.name,
            email: user.email
        };

        res.status(200).json({
            message: "Inicio de sesión exitoso",
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email
            }
        });

    } catch (error) {
        console.error("Error en login:", error);
        res.status(500).json({ message: "Error en el servidor" });
    }
};

// 🔹 LOGIN CON GOOGLE
export const googleAuth = async (req, res) => {
    const { googleToken } = req.body;

    if (!googleToken)
        return res.status(400).json({ message: "Token de Google no recibido" });

    try {
        // Verificar token de Google
        const ticket = await client.verifyIdToken({
            idToken: googleToken,
            audience: process.env.GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();
        const { email, name, sub } = payload;

        // Buscar usuario por email
        const [existingUser] = await db.query("SELECT * FROM users WHERE email = ?", [email]);

        let user;
        if (existingUser.length === 0) {
            // Crear usuario nuevo
            const hashedPassword = await bcrypt.hash(sub, 10);
            const [result] = await db.query(
                "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                [name, email, hashedPassword]
            );

            user = { id: result.insertId, name, email };
        } else {
            user = existingUser[0];
        }

        const token = createToken(user);

        req.session.user = {
            id: user.id,
            name: user.name,
            email: user.email
        };

        res.status(200).json({
            message: "Inicio de sesión con Google exitoso",
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email
            }
        });

    } catch (error) {
        console.error("Error en autenticación con Google:", error);
        res.status(400).json({ message: "Error en autenticación con Google" });
    }
};


// Reenviar código de recuperación
export const resendRecoveryCode = async (req, res) => {
    const passwordRecovery = req.session.passwordRecovery;

    if (!passwordRecovery)
        return res.status(400).json({ message: 'No hay solicitud de recuperación activa' });

    try {
        // Generar nuevo código
        const recoveryCode = Math.floor(100000 + Math.random() * 900000);

        // Actualizar sesión
        req.session.passwordRecovery.recoveryCode = recoveryCode;
        req.session.passwordRecovery.createdAt = Date.now();
        req.session.passwordRecovery.verified = false; // Resetear verificación

        // Obtener nombre del usuario
        const [rows] = await db.query('SELECT name FROM users WHERE id = ?', [passwordRecovery.userId]);
        const userName = rows[0]?.name || 'Usuario';

        // Reenviar correo
        await transporter.sendMail({
            from: `"Soporte" <${process.env.EMAIL_USER}>`,
            to: passwordRecovery.email,
            subject: 'Nuevo código de recuperación',
            html: `
                <h2>Hola ${userName}</h2>
                <p>Has solicitado un nuevo código de recuperación.</p>
                <p>Tu nuevo código es:</p>
                <h3>${recoveryCode}</h3>
                <p><small>Este código expira en 10 minutos.</small></p>
            `
        });

        res.json({ message: 'Nuevo código enviado. Revisa tu correo.' });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error al reenviar código' });
    }
};