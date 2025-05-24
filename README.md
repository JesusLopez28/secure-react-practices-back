# Secure React Practices - Backend

Este es el backend para la aplicación de prácticas seguras en React, implementando estándares de seguridad para autenticación y manejo de información sensible.

## Características de Seguridad

### Contraseñas Seguras y Cifrado (ISO/IEC 27001 y 27002)

- Implementación de políticas de contraseñas robustas según ISO/IEC 27002 - A.9.2.4
- Almacenamiento seguro de contraseñas con hash+salt usando bcrypt
- Cifrado de información sensible con AES

### Autenticación Multifactor (NIST SP 800-63B)

- Implementación de MFA basado en TOTP según RFC 6238
- Generación de códigos QR para aplicaciones de autenticación
- Verificación segura de tokens MFA

## Tecnologías

- Node.js con Express
- TypeScript
- MySQL para almacenamiento persistente
- JWT para gestión de tokens de autenticación
- Bcrypt para hash de contraseñas
- Speakeasy para implementación TOTP
- Helmet para seguridad HTTP

## Instalación

1. Clonar el repositorio
2. Ejecutar `npm install` para instalar dependencias
3. Configurar variables de entorno en un archivo `.env`
4. Inicializar la base de datos con el script SQL en `src/db/init.sql`
5. Ejecutar `npm run dev` para iniciar el servidor en modo desarrollo

## Variables de Entorno

Crea un archivo `.env` en la raíz del proyecto con las siguientes variables:

```
PORT=3001
NODE_ENV=development
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=
DB_NAME=secure_react_db
JWT_SECRET=your_secret_key
EMAIL_ENCRYPTION_KEY=email_encryption_key
FRONTEND_URL=http://localhost:5173
```

## Estándares de Seguridad

Esta aplicación sigue los siguientes estándares de seguridad:

1. **ISO/IEC 27001**: Sistema de Gestión de la Seguridad de la Información
2. **ISO/IEC 27002 (A.9.2.4)**: Gestión de contraseñas
3. **NIST SP 800-63B**: Guía para autenticación digital
4. **RFC 6238**: Algoritmo TOTP (Time-based One-Time Password)