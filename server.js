/**
 * =======================================================================
 * LABORATORIO ACADÉMICO DE SEGURIDAD INFORMÁTICA (AppSec)
 * VULNERABILIDAD: Subida Insegura de Archivos (Unrestricted File Upload)
 * IDENTIFICADORES: CWE-434 / OWASP Top 10 (A04:2021 / A03:2021)
 * =======================================================================
 */

const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Directorios del sistema
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const VULNERABLE_DIR = path.join(UPLOADS_DIR, 'vulnerable');
const SECURE_DIR = path.join(UPLOADS_DIR, 'secure');
const PUBLIC_DIR = path.join(__dirname, 'public');
const TEST_FILES_DIR = path.join(__dirname, 'test_files');

// Asegurar existencia de directorios
[VULNERABLE_DIR, SECURE_DIR, TEST_FILES_DIR].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

// Middleware de parsing y estáticos
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

// Exponer archivos de prueba para descarga rápida desde la UI
app.use('/test_files', express.static(TEST_FILES_DIR));

// Estado global de la sesión del usuario (para la demo)
let userProfile = {
    fullName: 'SEBASTIAN JAVIER LLANOS SIERRA',
    initials: 'SL',
    avatarUrl: null,
    avatarName: 'Ninguno',
    description: '',
    lastUploadMode: null
};

// =======================================================================
// 1. CONFIGURACIÓN DEL ESCENARIO VULNERABLE (CWE-434)
// =======================================================================
// MALA PRÁCTICA:
// - Conserva el nombre original enviado por el cliente (riesgo de sobrescritura y directory traversal).
// - Guarda el archivo en un directorio público accesible directamente vía URL.
// - No valida extensión.
// - No valida tipo MIME ni magic bytes.
const vulnerableStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, VULNERABLE_DIR);
    },
    filename: (req, file, cb) => {
        // VULNERABILIDAD: Conservar exactamente el nombre original del cliente
        cb(null, file.originalname);
    }
});

const uploadVulnerable = multer({
    storage: vulnerableStorage,
    limits: { fileSize: 1024 * 1024 * 1024 } // 1 GB (sin restricción práctica)
});

// =======================================================================
// 2. CONFIGURACIÓN DEL ESCENARIO SEGURO (AppSec Best Practices)
// =======================================================================
// BUENA PRÁCTICA:
// - Almacenamiento en memoria temporal primero para inspección profunda.
// - Verificación estricta de extensión en lista blanca.
// - Verificación de número mágico (Magic Bytes) reales en el buffer.
// - Renombrado aleatorio con UUID v4 (anti-traversal y anti-sobrescritura).
// - Almacenamiento fuera del alcance de ejecución directa del servidor web.
const memoryStorage = multer.memoryStorage();
const uploadSecureMemory = multer({
    storage: memoryStorage,
    limits: { fileSize: 2 * 1024 * 1024 } // Límite estricto: 2 MB
});

// Firmas de Magic Bytes válidas para imágenes
const MAGIC_BYTES = {
    jpg: [0xFF, 0xD8, 0xFF],
    png: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
    gif: [0x47, 0x49, 0x46, 0x38]
};

function verifyMagicBytes(buffer, extension) {
    if (!buffer || buffer.length < 8) return false;

    if (extension === 'jpg' || extension === 'jpeg') {
        return buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF;
    }
    if (extension === 'png') {
        const expected = MAGIC_BYTES.png;
        for (let i = 0; i < expected.length; i++) {
            if (buffer[i] !== expected[i]) return false;
        }
        return true;
    }
    if (extension === 'gif') {
        const expected = MAGIC_BYTES.gif;
        for (let i = 0; i < expected.length; i++) {
            if (buffer[i] !== expected[i]) return false;
        }
        return true;
    }
    return false;
}

// =======================================================================
// RUTAS DE LA API
// =======================================================================

// Obtener perfil actual
app.get('/api/profile', (req, res) => {
    res.json(userProfile);
});

// Resetear estado del laboratorio
app.post('/api/reset', (req, res) => {
    userProfile.avatarUrl = null;
    userProfile.avatarName = 'Ninguno';
    userProfile.description = '';
    userProfile.lastUploadMode = null;
    res.json({ success: true, message: 'Perfil restablecido' });
});

// -----------------------------------------------------------------------
// ENDPOINT 1: SUBIDA VULNERABLE (INSEGURA)
// -----------------------------------------------------------------------
app.post('/api/upload-vulnerable', uploadVulnerable.single('avatar'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No se envió ningún archivo.' });
    }

    const filename = req.file.originalname;
    const publicUrl = `/uploads/vulnerable/${encodeURIComponent(filename)}`;
    const fullDiskPath = path.join(VULNERABLE_DIR, filename);

    // Leer primeros bytes para telemetría educativa
    let magicBytesHex = '';
    try {
        const sampleBuffer = Buffer.alloc(8);
        const fd = fs.openSync(fullDiskPath, 'r');
        fs.readSync(fd, sampleBuffer, 0, 8, 0);
        fs.closeSync(fd);
        magicBytesHex = sampleBuffer.toString('hex').toUpperCase().match(/.{1,2}/g).join(' ');
    } catch (e) {
        magicBytesHex = 'N/A';
    }

    // Actualizar perfil
    userProfile.avatarUrl = publicUrl;
    userProfile.avatarName = filename;
    userProfile.description = req.body.description || '';
    userProfile.lastUploadMode = 'vulnerable';

    const ext = path.extname(filename).toLowerCase();
    const isDangerous = ['.php', '.html', '.htm', '.js', '.sh', '.py', '.jsp', '.exe', '.svg'].includes(ext);

    res.json({
        success: true,
        mode: 'vulnerable',
        status: 'warning',
        title: isDangerous ? '⚠️ ALERTA: Archivo Potencialmente Malicioso Aceptado' : '✅ Archivo Subido (Sin Validación)',
        filename: filename,
        savedAs: filename,
        storagePath: fullDiskPath,
        publicUrl: publicUrl,
        size: req.file.size,
        clientMimeType: req.file.mimetype,
        magicBytesHex: magicBytesHex,
        extension: ext,
        vulnerabilities: [
            'CWE-434: Falta de validación de lista blanca de extensiones.',
            'CWE-20: Sin verificación de tipo de contenido real (Magic Bytes).',
            'CWE-22: Nombre de archivo original conservado sin sanitizar.',
            'CWE-732: Almacenado en directorio público directamente ejecutable.'
        ],
        exploitSimulation: isDangerous ? {
            detectedType: ext === '.php' ? 'RCE (Remote Code Execution / WebShell)' : (ext === '.html' ? 'Stored XSS (Cross-Site Scripting)' : 'Archivo de Script No Permitido'),
            recommendation: 'Acceda a la URL pública generada para observar cómo el servidor web interpreta el archivo.'
        } : null
    });
});

// -----------------------------------------------------------------------
// ENDPOINT 2: SUBIDA SEGURA (REMEDIADA CON APPSEC)
// -----------------------------------------------------------------------
app.post('/api/upload-secure', uploadSecureMemory.single('avatar'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No se envió ningún archivo.' });
    }

    const originalName = req.file.originalname;
    const rawExt = path.extname(originalName).toLowerCase().replace('.', '');
    const clientMime = req.file.mimetype.toLowerCase();
    const buffer = req.file.buffer;

    // 1. Telemetría de magic bytes
    const sampleHex = buffer.slice(0, 8).toString('hex').toUpperCase().match(/.{1,2}/g)?.join(' ') || 'N/A';

    // 2. Control de Lista Blanca Estricta de Extensiones
    const ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif'];
    if (!ALLOWED_EXTENSIONS.includes(rawExt)) {
        return res.status(400).json({
            success: false,
            mode: 'secure',
            status: 'blocked',
            title: '🛑 BLOQUEADO: Extensión No Autorizada',
            reason: `La extensión .${rawExt} no pertenece a la lista blanca estricta (${ALLOWED_EXTENSIONS.join(', ')}).`,
            cweMitigated: 'CWE-434 / CWE-241',
            clientMimeType: clientMime,
            magicBytesHex: sampleHex,
            filename: originalName
        });
    }

    // 3. Verificación de Content-Type coherente
    const ALLOWED_MIME = ['image/jpeg', 'image/png', 'image/gif'];
    if (!ALLOWED_MIME.includes(clientMime)) {
        return res.status(400).json({
            success: false,
            mode: 'secure',
            status: 'blocked',
            title: '🛑 BLOQUEADO: Cabecera MIME Sospechosa',
            reason: `El Content-Type "${clientMime}" no corresponde a una imagen legítima.`,
            cweMitigated: 'CWE-434',
            clientMimeType: clientMime,
            magicBytesHex: sampleHex,
            filename: originalName
        });
    }

    // 4. Verificación de Firmas de Magic Bytes (Contenido Real)
    const isMagicValid = verifyMagicBytes(buffer, rawExt);
    if (!isMagicValid) {
        return res.status(400).json({
            success: false,
            mode: 'secure',
            status: 'blocked',
            title: '🛑 BLOQUEADO: Firma Binaria Falsa (Magic Bytes Mismatch)',
            reason: `El archivo dice ser .${rawExt}, pero sus bytes de cabecera no coinciden con la firma oficial de este formato. ¡Intento de bypass detectado!`,
            cweMitigated: 'CWE-434 / Spoofing de extensiones',
            clientMimeType: clientMime,
            magicBytesHex: sampleHex,
            filename: originalName
        });
    }

    // 5. Renombrado Criptográfico Seguro (UUID v4)
    const secureId = crypto.randomUUID();
    const secureFilename = `${secureId}.${rawExt === 'jpeg' ? 'jpg' : rawExt}`;
    const destinationPath = path.join(SECURE_DIR, secureFilename);

    // Guardar en almacenamiento seguro fuera de la raíz pública directa
    try {
        fs.writeFileSync(destinationPath, buffer);
    } catch (err) {
        return res.status(500).json({ error: 'Error al almacenar el archivo de forma segura.' });
    }

    // URL controlada mediante controlador seguro con cabeceras estrictas
    const secureServedUrl = `/api/avatar-safe/${secureFilename}`;

    // Actualizar perfil
    userProfile.avatarUrl = secureServedUrl;
    userProfile.avatarName = `${originalName} (Almacenado como: ${secureFilename})`;
    userProfile.description = req.body.description || '';
    userProfile.lastUploadMode = 'secure';

    res.json({
        success: true,
        mode: 'secure',
        status: 'secured',
        title: '🛡️ Archivo Validado y Almacenado con Éxito',
        filename: originalName,
        savedAs: secureFilename,
        storagePath: destinationPath,
        publicUrl: secureServedUrl,
        size: req.file.size,
        clientMimeType: clientMime,
        magicBytesHex: sampleHex,
        extension: `.${rawExt}`,
        mitigationsApplied: [
            'Lista blanca estricta de extensiones (.jpg, .jpeg, .png, .gif).',
            'Validación binaria de Magic Bytes en buffer antes de persistir.',
            'Renombrado aleatorio con UUID v4 (previene Path Traversal y sobreescrituras).',
            'Almacenamiento fuera de la raíz web directa.',
            'Entrega segura con cabeceras X-Content-Type-Options: nosniff y Content-Type forzado.'
        ]
    });
});

// -----------------------------------------------------------------------
// 3. CONTROLADOR DE ACCESO PÚBLICO VULNERABLE & SIMULADOR DE EJECUCIÓN (RCE / XSS)
// -----------------------------------------------------------------------
app.get('/uploads/vulnerable/:filename', (req, res) => {
    const filename = req.params.filename;
    // Riesgo vulnerable: acceso directo sin saneamiento profundo
    const filePath = path.join(VULNERABLE_DIR, filename);

    if (!fs.existsSync(filePath)) {
        return res.status(404).send('Archivo no encontrado.');
    }

    const ext = path.extname(filename).toLowerCase();

    // DEMOSTRACIÓN ACADÉMICA DE RCE:
    // Si el archivo es .php, simulamos la ejecución que ocurriría en un servidor Apache/Nginx con PHP
    if (ext === '.php') {
        const fileContent = fs.readFileSync(filePath, 'utf-8');
        return res.send(`
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <title>Consola de Ejecución del Servidor - RCE Simulado</title>
                <style>
                    body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0b0f19; color: #e2e8f0; margin: 0; padding: 30px; }
                    .header-banner { background: #b91c1c; color: white; padding: 15px 20px; border-radius: 8px 8px 0 0; font-weight: bold; display: flex; justify-content: space-between; align-items: center; }
                    .card { background: #111827; border: 1px solid #374151; border-radius: 8px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); overflow: hidden; max-width: 900px; margin: 0 auto; }
                    .body-content { padding: 25px; }
                    .terminal { background: #000; border-radius: 6px; padding: 15px; font-family: 'Courier New', monospace; color: #10b981; line-height: 1.5; margin: 15px 0; border: 1px solid #1f2937; }
                    .terminal .cmd { color: #38bdf8; font-weight: bold; }
                    .terminal .warn { color: #ef4444; }
                    .code-preview { background: #1e293b; padding: 15px; border-radius: 6px; font-family: monospace; color: #f1f5f9; overflow-x: auto; max-height: 200px; border-left: 4px solid #f59e0b; }
                    a.btn { display: inline-block; background: #3b82f6; color: white; text-decoration: none; padding: 8px 16px; border-radius: 6px; font-weight: 500; margin-top: 15px; }
                    a.btn:hover { background: #2563eb; }
                </style>
            </head>
            <body>
                <div class="card">
                    <div class="header-banner">
                        <span>🚨 SIMULADOR ACADÉMICO: INTERPRETACIÓN DE CÓDIGO DEL LADO DEL SERVIDOR (RCE)</span>
                        <span style="font-size: 12px; background: rgba(0,0,0,0.3); padding: 4px 8px; border-radius: 4px;">CWE-434 / OWASP A03</span>
                    </div>
                    <div class="body-content">
                        <h3>Archivo Ejecutado: <code>/uploads/vulnerable/${filename}</code></h3>
                        <p>Dado que el servidor web carece de restricciones en la carpeta pública, cualquier archivo <code>.php</code> subido es procesado por el motor de scripts del servidor.</p>

                        <div class="terminal">
                            <div><span class="cmd">[Servidor Web Apache/PHP]</span> Inicializando intérprete de scripts...</div>
                            <div><span class="cmd">[Servidor Web Apache/PHP]</span> Procesando directivas del archivo <strong>${filename}</strong>...</div>
                            <div class="warn">================================================================</div>
                            <div class="warn">>>> [STDOUT]: VULNERABILIDAD RCE CONFIRMADA CON ÉXITO!</div>
                            <div>>>> Sistema: Linux academic-vulnerable-host 6.1.0 #1 SMP Debian</div>
                            <div>>>> Usuario del Proceso (UID/GID): www-data (ID: 33)</div>
                            <div>>>> Directorio de Trabajo: /var/www/html/uploads/vulnerable</div>
                            <div class="warn">================================================================</div>
                            <div><span class="cmd">[Servidor Web Apache/PHP]</span> Código ejecutado sin restricciones.</div>
                        </div>

                        <h4>Código Fuente Extraído del Archivo Subido:</h4>
                        <pre class="code-preview">${escapeHtml(fileContent)}</pre>

                        <p><a href="/" class="btn">⬅️ Regresar al Formulario de Perfil</a></p>
                    </div>
                </div>
            </body>
            </html>
        `);
    }

    // Si es HTML o SVG, se sirve con MIME correspondiente para evidenciar Stored XSS
    if (ext === '.html' || ext === '.htm') {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.sendFile(filePath);
    }

    if (ext === '.svg') {
        res.setHeader('Content-Type', 'image/svg+xml');
        return res.sendFile(filePath);
    }

    // Para imágenes u otros archivos regulares
    res.sendFile(filePath);
});

// -----------------------------------------------------------------------
// 4. CONTROLADOR DE ACCESO SEGURO (CON CABECERAS DEFENSIVAS)
// -----------------------------------------------------------------------
app.get('/api/avatar-safe/:filename', (req, res) => {
    // Sanitizar nombre de archivo para evitar Directory Traversal (../)
    const sanitizedFilename = path.basename(req.params.filename);
    const filePath = path.join(SECURE_DIR, sanitizedFilename);

    if (!fs.existsSync(filePath)) {
        return res.status(404).send('Avatar no encontrado.');
    }

    const ext = path.extname(sanitizedFilename).toLowerCase();
    const mimeMap = {
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.gif': 'image/gif'
    };

    const safeMime = mimeMap[ext] || 'application/octet-stream';

    // CABECERAS DEFENSIVAS CRÍTICAS (AppSec):
    // 1. Evita que el navegador intente adivinar o reinterpretar el MIME (previene MIME Confusion Attacks)
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // 2. Entrega con el MIME estricto comprobado
    res.setHeader('Content-Type', safeMime);
    // 3. Forzar aislamiento de contexto
    res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'");
    res.setHeader('Content-Disposition', `inline; filename="${sanitizedFilename}"`);

    res.sendFile(filePath);
});

function escapeHtml(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

app.listen(PORT, () => {
    console.log(`\n===============================================================`);
    console.log(`🛡️  LABORATORIO ACADÉMICO: Unrestricted File Upload (CWE-434)`);
    console.log(`🚀 Servidor ejecutándose en: http://localhost:${PORT}`);
    console.log(`📁 Directorio Vulnerable: uploads/vulnerable/`);
    console.log(`🛡️  Directorio Seguro:     uploads/secure/`);
    console.log(`===============================================================\n`);
});
