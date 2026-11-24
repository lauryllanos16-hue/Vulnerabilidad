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
// ESTADO DEL JUEGO DIDÁCTICO (LEADERBOARD EN MEMORIA + PERSISTENCIA LIGERA)
// =======================================================================
const leaderboardFile = path.join(UPLOADS_DIR, 'leaderboard.json');
let leaderboard = [];

try {
    if (fs.existsSync(leaderboardFile)) {
        const rawData = fs.readFileSync(leaderboardFile, 'utf-8');
        const parsed = JSON.parse(rawData);
        if (Array.isArray(parsed)) {
            leaderboard = parsed;
        }
    }
} catch (err) {
    console.warn('No se pudo cargar leaderboard.json, iniciando ranking vacío:', err.message);
    leaderboard = [];
}

function saveLeaderboardToDisk() {
    try {
        fs.writeFileSync(leaderboardFile, JSON.stringify(leaderboard, null, 2), 'utf-8');
    } catch (err) {
        console.warn('Advertencia al persistir leaderboard.json:', err.message);
    }
}

function getSortedLeaderboard() {
    return [...leaderboard].sort((a, b) => {
        if (b.score !== a.score) return b.score - a.score;
        if ((b.accuracy || 0) !== (a.accuracy || 0)) return (b.accuracy || 0) - (a.accuracy || 0);
        return (a.updatedAt || 0) - (b.updatedAt || 0);
    });
}

function sanitizePlayerName(rawName) {
    if (typeof rawName !== 'string') return 'Estudiante';
    const stripped = rawName.replace(/<[^>]*>?/gm, '').replace(/[\r\n\t]+/g, ' ').trim();
    if (!stripped) return 'Estudiante';
    return stripped.slice(0, 28);
}

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

// =======================================================================
// 5. JUEGO DIDÁCTICO UNIVERSITARIO (/juego) Y LEADERBOARD EN TIEMPO REAL
// =======================================================================
app.get('/juego', (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'game.html'));
});

app.get(['/proyector', '/juego/proyector'], (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'game.html'));
});

app.get('/favicon.ico', (req, res) => {
    res.redirect(302, '/favicon.svg');
});

app.get('/api/game/leaderboard', (req, res) => {
    const sorted = getSortedLeaderboard();
    res.json({
        success: true,
        players: sorted,
        totalPlayers: sorted.length,
        updatedAt: Date.now()
    });
});

app.post('/api/game/score', (req, res) => {
    const body = req.body || {};
    const playerId = typeof body.playerId === 'string' && body.playerId.trim()
        ? body.playerId.trim().slice(0, 64)
        : crypto.randomUUID();
    const name = sanitizePlayerName(body.name);

    const rawScore = Number(body.score);
    const score = Number.isFinite(rawScore) ? Math.max(0, Math.min(10000, Math.round(rawScore))) : 0;

    const rawAccuracy = Number(body.accuracy);
    const accuracy = Number.isFinite(rawAccuracy) ? Math.max(0, Math.min(100, Math.round(rawAccuracy))) : 0;

    const rawPhase = Number(body.phaseReached);
    const phaseReached = Number.isFinite(rawPhase) ? Math.max(1, Math.min(3, Math.round(rawPhase))) : 1;

    const badges = Array.isArray(body.badges)
        ? body.badges.filter(b => typeof b === 'string').slice(0, 10).map(b => b.replace(/<[^>]*>?/gm, '').slice(0, 40))
        : [];
    const completed = Boolean(body.completed);
    const now = Date.now();

    const existingIdx = leaderboard.findIndex(p => p.playerId === playerId);
    const entry = {
        playerId,
        name,
        score,
        phaseReached,
        accuracy,
        badges,
        completed,
        updatedAt: now
    };

    if (existingIdx >= 0) {
        leaderboard[existingIdx] = {
            ...leaderboard[existingIdx],
            ...entry,
            score: Math.max(leaderboard[existingIdx].score || 0, score)
        };
    } else {
        leaderboard.push(entry);
    }

    saveLeaderboardToDisk();

    const sorted = getSortedLeaderboard();
    const rankIndex = sorted.findIndex(p => p.playerId === playerId);

    res.json({
        success: true,
        playerId,
        rank: rankIndex >= 0 ? rankIndex + 1 : sorted.length,
        players: sorted,
        totalPlayers: sorted.length,
        updatedAt: now
    });
});

app.post('/api/game/reset-leaderboard', (req, res) => {
    leaderboard = [];
    saveLeaderboardToDisk();
    resetClassMatchState();
    res.json({
        success: true,
        players: [],
        totalPlayers: 0,
        status: classMatch.status,
        updatedAt: Date.now()
    });
});

// =======================================================================
// 6. EMPAREJAMIENTO ALEATORIO BALANCEADO (1 INSPECTOR + >=3 ATACANTES)
// =======================================================================
const PAYLOAD_SIGNATURES = {
    png_real: {
        hex: '89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52',
        ascii: '.PNG........IHDR',
        realKind: 'image',
        realFormat: 'png',
        expectedMimes: ['image/png'],
        size: '48.2 KB'
    },
    jpg_real: {
        hex: 'FF D8 FF E0 00 10 4A 46 49 46 00 01 01 01 00 48',
        ascii: 'ÿØÿà..JFIF.....H',
        realKind: 'image',
        realFormat: 'jpg',
        expectedMimes: ['image/jpeg', 'image/jpg'],
        size: '112.4 KB'
    },
    gif_real: {
        hex: '47 49 46 38 39 61 01 00 01 00 80 00 00 FF FF FF',
        ascii: 'GIF89a..........',
        realKind: 'image',
        realFormat: 'gif',
        expectedMimes: ['image/gif'],
        size: '64.0 KB'
    },
    php_rce: {
        hex: '3C 3F 70 68 70 20 73 79 73 74 65 6D 28 24 5F 47',
        ascii: '<?php system($_G',
        realKind: 'script',
        realFormat: 'php',
        expectedMimes: ['application/x-httpd-php'],
        size: '1.8 KB'
    },
    html_xss: {
        hex: '3C 21 44 4F 43 54 59 50 45 20 68 74 6D 6C 3E 3C',
        ascii: '<!DOCTYPE html><',
        realKind: 'xss',
        realFormat: 'html',
        expectedMimes: ['text/html'],
        size: '2.4 KB'
    },
    svg_xss: {
        hex: '3C 73 76 67 20 6F 6E 6C 6F 61 64 3D 61 6C 65 72',
        ascii: '<svg onload=aler',
        realKind: 'xss',
        realFormat: 'svg',
        expectedMimes: ['image/svg+xml'],
        size: '1.1 KB'
    }
};

const GROUP_CALLSIGNS = ['Alfa', 'Bravo', 'Charlie', 'Delta', 'Eco', 'Foxtrot', 'Golf', 'Hotel', 'India', 'Juliet', 'Kilo', 'Lima'];
const ROUND_DURATION_MS = 120 * 1000;
const MIN_ATTACK_COST = 50;
const PACKET_SLA_MS = Math.max(2000, Number(process.env.PACKET_SLA_MS) || 15000);

function computeInitialAttackCredits(minigameScore) {
    const bonus = Math.min(100, Math.round((Number(minigameScore) || 0) / 4));
    return 200 + bonus;
}

function getPacketAttackCost(evaluated) {
    if (!evaluated.isMalicious) return 50;
    if (evaluated.trueVector === 'spoofing' || evaluated.trueVector === 'traversal') return 80;
    return 60;
}

const classMatch = {
    status: 'waiting', // 'waiting' | 'briefing' | 'active'
    gameMode: 'multiplayer', // 'multiplayer' | 'solo'
    roundNumber: 1,
    waitingPlayers: [],
    groups: [],
    groupMap: {},
    pastInspectors: new Set()
};

function resetClassMatchState() {
    classMatch.status = 'waiting';
    classMatch.gameMode = classMatch.gameMode || 'multiplayer';
    classMatch.roundNumber = 1;
    classMatch.waitingPlayers = [];
    classMatch.groups = [];
    classMatch.groupMap = {};
    classMatch.pastInspectors = new Set();
}

function computeBalancedGroupCount(n) {
    if (!Number.isFinite(n) || n < 4) return 1;
    return Math.max(1, Math.min(Math.floor(n / 4), Math.ceil(n / 6)));
}

function computeDistributionPreview(n) {
    const count = Math.max(0, Math.round(n || 0));
    if (count === 0) {
        return {
            totalPlayers: 0,
            groupCount: 0,
            sizes: [],
            minRecommendedMet: false,
            summaryText: 'Esperando que los estudiantes completen la calibración de Magic Bytes.'
        };
    }

    const groupCount = computeBalancedGroupCount(count);
    const base = Math.floor(count / groupCount);
    const remainder = count % groupCount;
    const sizes = [];
    for (let i = 0; i < groupCount; i++) {
        sizes.push(base + (i < remainder ? 1 : 0));
    }

    const minRecommendedMet = count >= 4;
    const sizesDesc = sizes.map((sz, idx) => `Grupo ${idx + 1}: ${sz} (1 Inspector + ${Math.max(0, sz - 1)} Atacantes)`).join(' • ');
    return {
        totalPlayers: count,
        groupCount,
        sizes,
        minRecommendedMet,
        summaryText: minRecommendedMet
            ? `${count} estudiantes -> ${groupCount} grupo(s) parejo(s): ${sizesDesc}`
            : `${count} estudiante(s) en espera (recomendado mínimo 4 para tener 1 Inspector + 3 Atacantes).`
    };
}

function cryptoShuffle(arr) {
    const copy = [...arr];
    for (let i = copy.length - 1; i > 0; i--) {
        const j = crypto.randomInt(0, i + 1);
        [copy[i], copy[j]] = [copy[j], copy[i]];
    }
    return copy;
}

function createRoom(id, name, capacity) {
    return {
        id,
        name,
        capacity,
        inspectorId: null,
        serverIntegrity: 100,
        roundNumber: classMatch.roundNumber,
        roundDurationMs: ROUND_DURATION_MS,
        roundStartedAt: null,
        roundEndsAt: null,
        roundResult: null,
        members: [],
        queue: [],
        history: []
    };
}

function activateFrontPacketSla(room, refTime = Date.now()) {
    if (!room || classMatch.status !== 'active' || room.roundResult || room.queue.length === 0) {
        return;
    }
    const front = room.queue[0];
    if (!front.slaStartedAt) {
        const startAt = Math.max(refTime, front.createdAt || refTime);
        front.slaStartedAt = startAt;
        front.slaDeadlineAt = startAt + PACKET_SLA_MS;
    }
}

function processRoomQueueTimeouts(room) {
    if (!room || classMatch.status !== 'active' || room.roundResult) {
        return;
    }

    const now = Date.now();
    const cutoff = room.roundEndsAt ? Math.min(now, room.roundEndsAt) : now;
    activateFrontPacketSla(room, room.roundStartedAt || now);

    while (!room.roundResult && room.queue.length > 0) {
        const front = room.queue[0];
        if (!front.slaDeadlineAt) {
            activateFrontPacketSla(room, front.createdAt || now);
        }
        if (front.slaDeadlineAt > cutoff) {
            break;
        }

        room.queue.shift();
        const resolvedAt = front.slaDeadlineAt;
        const inspector = room.members.find(m => m.playerId === room.inspectorId);
        const sender = front.isBot ? null : room.members.find(m => m.playerId === front.senderId);

        let outcome = '';
        let hpLoss = 0;
        let senderCreditGain = 0;
        let senderScoreGain = 0;
        let verdictHeadline = '';

        if (front.isMalicious) {
            outcome = 'timeout_breach';
            hpLoss = 20;
            senderCreditGain = 120;
            senderScoreGain = 220;
            verdictHeadline = '⏱️ ¡Sin respuesta (SLA vencido)! Exploit infiltrado por inactividad: -20 HP al casero. Atacante gana +120 PTS.';
            if (sender) sender.infiltrations += 1;
        } else {
            outcome = 'timeout_dos';
            hpLoss = 15;
            senderCreditGain = 100;
            senderScoreGain = 160;
            verdictHeadline = '⏱️ ¡Sin respuesta (SLA vencido)! Foto legítima abandonada: -15 HP al casero. Atacante gana +100 PTS.';
        }

        room.serverIntegrity = Math.max(0, room.serverIntegrity - hpLoss);

        if (inspector) {
            inspector.totalCount += 1;
            syncRoomMemberToLeaderboard(inspector);
        }
        if (sender) {
            sender.totalCount += 1;
            sender.correctCount += 1;
            sender.attackCredits = (sender.attackCredits || 0) + senderCreditGain;
            sender.score = (sender.score || 0) + senderScoreGain;
            syncRoomMemberToLeaderboard(sender);
        }

        const record = {
            ...front,
            status: 'resolved',
            inspectorName: inspector ? inspector.name : 'Casero',
            inspectorAction: 'timeout',
            inspectorVector: null,
            outcome,
            inspectorPoints: 0,
            hpLoss,
            senderPoints: senderScoreGain,
            senderCreditGain,
            verdictHeadline,
            resolvedAt
        };

        room.history.unshift(record);
        if (room.history.length > 30) {
            room.history.length = 30;
        }

        if (room.serverIntegrity <= 0) {
            break;
        }
        if (room.queue.length > 0) {
            activateFrontPacketSla(room, resolvedAt);
        }
    }
}

function evaluateRoomRoundOutcome(room) {
    if (!room || classMatch.status !== 'active' || room.roundResult || room.members.length === 0) {
        return room ? room.roundResult : null;
    }

    processRoomQueueTimeouts(room);

    const now = Date.now();
    const inspector = room.members.find(m => m.playerId === room.inspectorId);
    const attackers = room.members.filter(m => m.playerId !== room.inspectorId);
    const pendingCount = room.queue.filter(q => q.status === 'pending').length;

    if (room.serverIntegrity <= 0) {
        room.serverIntegrity = 0;
        room.roundResult = {
            winner: 'attackers',
            reason: '🚨 ¡Caseta caída (0 HP)! Los atacantes vulneraron el servidor.',
            finishedAt: now
        };
        attackers.forEach(a => {
            a.score = (a.score || 0) + 150;
            a.wins = (a.wins || 0) + 1;
            syncRoomMemberToLeaderboard(a);
        });
    } else if (room.roundEndsAt && now >= room.roundEndsAt) {
        room.roundResult = {
            winner: 'inspector',
            reason: `🛡️ ¡Victoria del Casero! Resistió los 2:00 minutos con ${room.serverIntegrity} HP.`,
            finishedAt: now
        };
        if (inspector) {
            inspector.wins = (inspector.wins || 0) + 1;
            syncRoomMemberToLeaderboard(inspector);
        }
    } else if (attackers.length > 0 && pendingCount === 0 && attackers.every(a => (a.attackCredits || 0) < MIN_ATTACK_COST)) {
        room.roundResult = {
            winner: 'inspector',
            reason: '🛡️ ¡Victoria del Casero! Todos los atacantes se quedaron sin puntos (< 50 PTS) para seguir atacando.',
            finishedAt: now
        };
        if (inspector) {
            inspector.wins = (inspector.wins || 0) + 1;
            syncRoomMemberToLeaderboard(inspector);
        }
    }

    return room.roundResult;
}

function collectAllMatchPlayers() {
    const map = new Map();
    classMatch.waitingPlayers.forEach(p => {
        map.set(p.playerId, { ...p });
    });
    classMatch.groups.forEach(g => {
        g.members.forEach(m => {
            map.set(m.playerId, { ...m });
        });
    });
    return Array.from(map.values());
}

function pickRandomInspector(members) {
    if (!members.length) return null;
    const freshCandidates = members.filter(m => !classMatch.pastInspectors.has(m.playerId));
    const pool = freshCandidates.length > 0 ? freshCandidates : members;
    const chosen = pool[crypto.randomInt(0, pool.length)];
    classMatch.pastInspectors.add(chosen.playerId);
    return chosen;
}

function shuffleAndStartMatch(targetStatus = 'active') {
    const allPlayers = collectAllMatchPlayers();
    if (allPlayers.length === 0) {
        return { error: 'Aún no hay estudiantes registrados en la sala de espera.' };
    }

    if (classMatch.status === 'active' || classMatch.status === 'briefing') {
        classMatch.roundNumber += 1;
    }

    const shuffled = cryptoShuffle(allPlayers);
    const groupCount = computeBalancedGroupCount(shuffled.length);
    const newGroups = [];
    const newMap = {};

    for (let i = 0; i < groupCount; i++) {
        const id = `grupo-${i + 1}`;
        const callsign = GROUP_CALLSIGNS[i] || `#${i + 1}`;
        const room = createRoom(id, `Grupo ${i + 1} — Caseta ${callsign}`, 10);
        newGroups.push(room);
        newMap[id] = room;
    }

    shuffled.forEach((player, idx) => {
        const targetGroup = newGroups[idx % groupCount];
        const miniScore = Number(player.minigameScore ?? player.score ?? 0);
        targetGroup.members.push({
            playerId: player.playerId,
            name: player.name,
            role: 'sender',
            minigameScore: miniScore,
            attackCredits: computeInitialAttackCredits(miniScore),
            score: player.score || 0,
            correctCount: player.correctCount || 0,
            totalCount: player.totalCount || 0,
            infiltrations: player.infiltrations || 0,
            wins: player.wins || 0,
            joinedAt: player.joinedAt || Date.now()
        });
    });

    const now = Date.now();
    const isActiveImmediate = targetStatus !== 'briefing';
    newGroups.forEach(group => {
        const chosen = pickRandomInspector(group.members);
        group.inspectorId = chosen ? chosen.playerId : null;
        group.roundStartedAt = isActiveImmediate ? now : null;
        group.roundEndsAt = isActiveImmediate ? now + ROUND_DURATION_MS : null;
        group.roundResult = null;
        group.members.forEach(m => {
            m.role = m.playerId === group.inspectorId ? 'inspector' : 'sender';
            syncRoomMemberToLeaderboard(m);
        });
    });

    classMatch.waitingPlayers = [];
    classMatch.groups = newGroups;
    classMatch.groupMap = newMap;
    classMatch.status = isActiveImmediate ? 'active' : 'briefing';

    return { groups: newGroups };
}

function findPlayerGroup(playerId) {
    if (!playerId) return null;
    for (const group of classMatch.groups) {
        if (group.members.some(m => m.playerId === playerId)) {
            return group;
        }
    }
    return null;
}

function getMatchStatusPayload(playerId) {
    classMatch.groups.forEach(g => evaluateRoomRoundOutcome(g));

    const allPlayers = collectAllMatchPlayers();
    const preview = computeDistributionPreview(allPlayers.length);
    const group = playerId ? findPlayerGroup(playerId) : null;
    let assignment = null;

    if ((classMatch.status === 'active' || classMatch.status === 'briefing') && group) {
        const me = group.members.find(m => m.playerId === playerId);
        assignment = {
            roomId: group.id,
            assignedRole: me ? me.role : 'sender',
            room: summarizeRoom(group),
            members: group.members,
            queue: group.queue,
            history: group.history
        };
    }

    return {
        success: true,
        status: classMatch.status,
        gameMode: classMatch.gameMode,
        roundNumber: classMatch.roundNumber,
        totalPlayers: allPlayers.length,
        waitingPlayers: classMatch.waitingPlayers,
        preview,
        groups: classMatch.groups.map(summarizeRoom),
        assignment,
        updatedAt: Date.now()
    };
}

function evaluateCraftedPacket({ filename, clientMime, payloadType }) {
    const cleanName = String(filename || 'avatar_usuario.png')
        .replace(/[\r\n\t<>]/g, '')
        .trim()
        .slice(0, 90) || 'avatar_usuario.png';

    const cleanMime = String(clientMime || 'application/octet-stream')
        .replace(/[\r\n\t<>]/g, '')
        .trim()
        .toLowerCase()
        .slice(0, 64) || 'application/octet-stream';

    const payload = PAYLOAD_SIGNATURES[payloadType] || PAYLOAD_SIGNATURES.png_real;
    const hasTraversal = cleanName.includes('..') || cleanName.includes('/') || cleanName.includes('\\');
    const rawExt = path.extname(cleanName).toLowerCase().replace('.', '');
    const normExt = rawExt === 'jpeg' ? 'jpg' : rawExt;
    const safeImageExts = ['png', 'jpg', 'gif'];

    let isMalicious = false;
    let trueVector = null;
    let explanation = '';

    if (hasTraversal) {
        isMalicious = true;
        trueVector = 'traversal';
        explanation = `Path Traversal (CWE-22): el nombre "${cleanName}" incluye secuencias de directorio ("../" o barras) para escapar de uploads/ y sobreescribir archivos críticos si no se renombra con UUID.`;
    } else if (payload.realKind === 'script') {
        if (safeImageExts.includes(normExt)) {
            isMalicious = true;
            trueVector = 'spoofing';
            explanation = `Magic Bytes Spoofing: aparenta ser imagen (.${rawExt}) con Content-Type "${cleanMime}", pero su buffer inicia con "3C 3F 70 68 70" (<?php), código PHP ejecutable.`;
        } else {
            isMalicious = true;
            trueVector = 'rce';
            explanation = `Ejecución Remota de Código (RCE / CWE-434): archivo ".${rawExt || 'sin-ext'}" con firma binaria PHP (<?php) que permite ejecutar comandos en el servidor web.`;
        }
    } else if (payload.realKind === 'xss') {
        if (safeImageExts.includes(normExt)) {
            isMalicious = true;
            trueVector = 'spoofing';
            explanation = `Magic Bytes Spoofing: el archivo declara extensión .${rawExt}, pero sus bytes reales contienen código web activo (${payload.ascii.trim()}) en lugar de una imagen.`;
        } else {
            isMalicious = true;
            trueVector = 'xss';
            explanation = `Stored XSS: archivo .${rawExt || payload.realFormat} con carga HTML/SVG activa (${payload.ascii.trim()}) que ejecuta JavaScript bajo el mismo origen de e-Libre.`;
        }
    } else {
        if (['php', 'phtml', 'php5', 'sh', 'js', 'exe', 'jsp'].includes(rawExt)) {
            isMalicious = true;
            trueVector = 'rce';
            explanation = `Extensión no autorizada (.${rawExt}): fuera de la lista blanca estricta (.jpg, .jpeg, .png, .gif); representa riesgo de interpretación o bypass.`;
        } else if (['html', 'htm', 'svg'].includes(rawExt)) {
            isMalicious = true;
            trueVector = 'xss';
            explanation = `Extensión web no permitida (.${rawExt}): podría ser interpretada por el navegador como documento activo y facilitar Stored XSS.`;
        } else if (safeImageExts.includes(normExt) && normExt === payload.realFormat && payload.expectedMimes.includes(cleanMime)) {
            isMalicious = false;
            trueVector = null;
            explanation = `Archivo legítimo: extensión .${rawExt}, Content-Type (${cleanMime}) y Magic Bytes reales (${payload.hex.slice(0, 11)}...) coinciden sin anomalías.`;
        } else {
            isMalicious = true;
            trueVector = 'spoofing';
            explanation = `Inconsistencia de firma/MIME: la extensión (.${rawExt || 'ninguna'}) o Content-Type (${cleanMime}) no coincide con los Magic Bytes reales del formato ${payload.realFormat.toUpperCase()}.`;
        }
    }

    return {
        filename: cleanName,
        ext: rawExt ? `.${rawExt}` : '(sin ext)',
        clientMime: cleanMime,
        payloadType: payloadType in PAYLOAD_SIGNATURES ? payloadType : 'png_real',
        hex: payload.hex,
        ascii: payload.ascii,
        size: payload.size,
        isMalicious,
        trueVector,
        explanation
    };
}

function syncRoomMemberToLeaderboard(member) {
    if (!member || member.isBot) return;
    const accuracy = member.totalCount > 0
        ? Math.round((member.correctCount / member.totalCount) * 100)
        : 0;
    const now = Date.now();
    const badges = [];
    if (member.role === 'inspector' && member.correctCount >= 3) badges.push('🛡️ Centinela Caseta');
    if (member.wins >= 1 && member.role === 'inspector') badges.push('🛡️ Casero Sobreviviente');
    if (member.infiltrations >= 1) badges.push('🕵️ Infiltrador RedTeam');

    const existingIdx = leaderboard.findIndex(p => p.playerId === member.playerId);
    const entry = {
        playerId: member.playerId,
        name: member.name,
        score: Math.max(0, Math.min(10000, Math.round(member.score))),
        phaseReached: member.role === 'inspector' ? 2 : 1,
        accuracy,
        badges,
        completed: false,
        updatedAt: now
    };

    if (existingIdx >= 0) {
        leaderboard[existingIdx] = {
            ...leaderboard[existingIdx],
            ...entry,
            score: Math.max(leaderboard[existingIdx].score || 0, entry.score)
        };
    } else {
        leaderboard.push(entry);
    }
    saveLeaderboardToDisk();
}

function summarizeRoom(room) {
    const now = Date.now();
    const inspector = room.members.find(m => m.playerId === room.inspectorId);
    const attackers = room.members.filter(m => m.playerId !== room.inspectorId);
    const attackerCount = attackers.length;
    const attackersTotalCredits = attackers.reduce((sum, a) => sum + (a.attackCredits || 0), 0);
    const attackersAbleToAttack = attackers.filter(a => (a.attackCredits || 0) >= MIN_ATTACK_COST).length;
    const pending = room.queue.filter(q => q.status === 'pending');

    let remainingSeconds = Math.round(ROUND_DURATION_MS / 1000);
    if (classMatch.status === 'active' && room.roundEndsAt) {
        const refTime = room.roundResult ? room.roundResult.finishedAt : now;
        remainingSeconds = Math.max(0, Math.ceil((room.roundEndsAt - refTime) / 1000));
    }

    const activePacketSlaRemainingMs = (pending.length > 0 && pending[0].slaDeadlineAt && !room.roundResult)
        ? Math.max(0, pending[0].slaDeadlineAt - now)
        : null;

    const queuePreview = pending.slice(0, 8).map((q, idx) => ({
        packetId: q.packetId,
        senderName: q.senderName,
        filename: q.filename,
        isBot: Boolean(q.isBot),
        slaRemainingMs: (idx === 0 && q.slaDeadlineAt && !room.roundResult)
            ? Math.max(0, q.slaDeadlineAt - now)
            : null
    }));

    const recentVerdicts = room.history.slice(0, 4).map(h => ({
        packetId: h.packetId,
        senderName: h.senderName,
        filename: h.filename,
        inspectorAction: h.inspectorAction,
        outcome: h.outcome,
        hpLoss: h.hpLoss || 0,
        senderCreditGain: h.senderCreditGain || 0,
        verdictHeadline: h.verdictHeadline,
        resolvedAt: h.resolvedAt
    }));

    return {
        id: room.id,
        name: room.name,
        capacity: room.capacity,
        inspectorId: room.inspectorId,
        inspectorName: inspector ? inspector.name : null,
        attackerCount,
        attackersTotalCredits,
        attackersAbleToAttack,
        memberCount: room.members.length,
        pendingCount: pending.length,
        serverIntegrity: room.serverIntegrity,
        roundNumber: room.roundNumber,
        roundDurationSeconds: Math.round(ROUND_DURATION_MS / 1000),
        slaSeconds: Math.round(PACKET_SLA_MS / 1000),
        activePacketSlaRemainingMs,
        queuePreview,
        recentVerdicts,
        remainingSeconds,
        roundResult: room.roundResult
    };
}

// -----------------------------------------------------------------------
// ENDPOINTS DE EMPAREJAMIENTO ALEATORIO BALANCEADO
// -----------------------------------------------------------------------
app.get('/api/game/match/status', (req, res) => {
    const playerId = typeof req.query.playerId === 'string' ? req.query.playerId.trim() : '';
    res.json(getMatchStatusPayload(playerId));
});

app.post('/api/game/match/mode', (req, res) => {
    const rawMode = req.body && req.body.gameMode;
    classMatch.gameMode = rawMode === 'solo' ? 'solo' : 'multiplayer';
    res.json(getMatchStatusPayload(''));
});

app.post('/api/game/match/join', (req, res) => {
    const body = req.body || {};
    const playerId = typeof body.playerId === 'string' && body.playerId.trim()
        ? body.playerId.trim().slice(0, 64)
        : crypto.randomUUID();
    const name = sanitizePlayerName(body.name);
    const rawMini = Number(body.minigameScore);
    const minigameScore = Number.isFinite(rawMini) ? Math.max(0, Math.min(2000, Math.round(rawMini))) : 0;

    if (classMatch.status === 'waiting') {
        let player = classMatch.waitingPlayers.find(p => p.playerId === playerId);
        if (!player) {
            player = {
                playerId,
                name,
                role: 'waiting',
                minigameScore,
                attackCredits: computeInitialAttackCredits(minigameScore),
                score: minigameScore,
                correctCount: 0,
                totalCount: 0,
                infiltrations: 0,
                wins: 0,
                joinedAt: Date.now()
            };
            classMatch.waitingPlayers.push(player);
        } else {
            player.name = name;
            player.minigameScore = Math.max(player.minigameScore || 0, minigameScore);
            player.attackCredits = computeInitialAttackCredits(player.minigameScore);
            player.score = Math.max(player.score || 0, minigameScore);
        }
        syncRoomMemberToLeaderboard(player);
        return res.json({ playerId, ...getMatchStatusPayload(playerId) });
    }

    // Sala activa o briefing: si ya está asignado, actualizar nombre; si es nuevo (ingreso tardío), asignar al grupo más pequeño
    let existingGroup = findPlayerGroup(playerId);
    if (existingGroup) {
        const existingMember = existingGroup.members.find(m => m.playerId === playerId);
        if (existingMember) {
            existingMember.name = name;
            syncRoomMemberToLeaderboard(existingMember);
        }
        return res.json({ playerId, ...getMatchStatusPayload(playerId) });
    }

    if (classMatch.groups.length === 0) {
        classMatch.waitingPlayers.push({
            playerId,
            name,
            role: 'sender',
            minigameScore,
            attackCredits: computeInitialAttackCredits(minigameScore),
            score: minigameScore,
            correctCount: 0,
            totalCount: 0,
            infiltrations: 0,
            wins: 0,
            joinedAt: Date.now()
        });
        shuffleAndStartMatch(classMatch.status === 'briefing' ? 'briefing' : 'active');
        return res.json({ playerId, ...getMatchStatusPayload(playerId) });
    }

    // Buscar el grupo con menor cantidad de miembros (desempate aleatorio)
    const minLen = Math.min(...classMatch.groups.map(g => g.members.length));
    const smallestGroups = classMatch.groups.filter(g => g.members.length === minLen);
    const targetGroup = smallestGroups[crypto.randomInt(0, smallestGroups.length)];

    const assignedRole = !targetGroup.inspectorId ? 'inspector' : 'sender';
    if (assignedRole === 'inspector') {
        targetGroup.inspectorId = playerId;
        classMatch.pastInspectors.add(playerId);
    }

    const newMember = {
        playerId,
        name,
        role: assignedRole,
        minigameScore,
        attackCredits: computeInitialAttackCredits(minigameScore),
        score: minigameScore,
        correctCount: 0,
        totalCount: 0,
        infiltrations: 0,
        wins: 0,
        joinedAt: Date.now()
    };
    targetGroup.members.push(newMember);
    syncRoomMemberToLeaderboard(newMember);

    res.json({ playerId, ...getMatchStatusPayload(playerId) });
});

app.post('/api/game/match/start', (req, res) => {
    const body = req.body || {};
    const withBriefing = Boolean(body.withBriefing);
    const result = shuffleAndStartMatch(withBriefing ? 'briefing' : 'active');
    if (result.error) {
        return res.status(400).json({ success: false, error: result.error });
    }
    const playerId = typeof body.playerId === 'string' ? body.playerId.trim() : '';
    res.json(getMatchStatusPayload(playerId));
});

app.post('/api/game/match/launch', (req, res) => {
    if (classMatch.groups.length === 0) {
        return res.status(400).json({ success: false, error: 'Primero sortea los grupos antes de lanzar la partida.' });
    }
    const now = Date.now();
    classMatch.status = 'active';
    classMatch.groups.forEach(room => {
        room.roundStartedAt = now;
        room.roundEndsAt = now + ROUND_DURATION_MS;
        room.roundResult = null;
        room.serverIntegrity = 100;
        room.queue = [];
        room.history = [];
    });
    const playerId = typeof (req.body && req.body.playerId) === 'string' ? req.body.playerId.trim() : '';
    res.json(getMatchStatusPayload(playerId));
});

app.get('/api/game/rooms', (req, res) => {
    classMatch.groups.forEach(g => evaluateRoomRoundOutcome(g));
    res.json({
        success: true,
        status: classMatch.status,
        rooms: classMatch.groups.map(summarizeRoom),
        updatedAt: Date.now()
    });
});

app.get('/api/game/rooms/:roomId', (req, res) => {
    const room = classMatch.groupMap[req.params.roomId];
    if (!room) {
        return res.status(404).json({ success: false, error: 'Grupo no encontrado.' });
    }
    evaluateRoomRoundOutcome(room);
    res.json({
        success: true,
        room: summarizeRoom(room),
        members: room.members,
        queue: room.queue,
        history: room.history,
        updatedAt: Date.now()
    });
});

app.post('/api/game/rooms/:roomId/claim-booth', (req, res) => {
    const room = classMatch.groupMap[req.params.roomId];
    if (!room) return res.status(404).json({ success: false, error: 'Grupo no encontrado.' });

    const playerId = String((req.body && req.body.playerId) || '').trim();
    const member = room.members.find(m => m.playerId === playerId);
    if (!member) return res.status(403).json({ success: false, error: 'No perteneces a este grupo.' });

    if (room.inspectorId && room.inspectorId !== playerId) {
        const current = room.members.find(m => m.playerId === room.inspectorId);
        return res.status(409).json({
            success: false,
            error: `La caseta está asignada a ${current ? current.name : 'otro compañero'}.`
        });
    }

    room.inspectorId = playerId;
    classMatch.pastInspectors.add(playerId);
    room.members.forEach(m => {
        m.role = m.playerId === playerId ? 'inspector' : 'sender';
    });

    res.json({
        success: true,
        room: summarizeRoom(room),
        members: room.members
    });
});

app.post('/api/game/rooms/:roomId/rotate', (req, res) => {
    const room = classMatch.groupMap[req.params.roomId];
    if (!room) return res.status(404).json({ success: false, error: 'Grupo no encontrado.' });

    const playerId = String((req.body && req.body.playerId) || '').trim();
    if (room.inspectorId && room.inspectorId !== playerId) {
        return res.status(403).json({ success: false, error: 'Solo quien está en la caseta puede rotar el puesto al azar.' });
    }

    const others = room.members.filter(m => m.playerId !== room.inspectorId);
    if (others.length > 0) {
        const freshOthers = others.filter(m => !classMatch.pastInspectors.has(m.playerId));
        const pool = freshOthers.length > 0 ? freshOthers : others;
        const chosen = pool[crypto.randomInt(0, pool.length)];
        room.inspectorId = chosen.playerId;
        classMatch.pastInspectors.add(chosen.playerId);
        room.members.forEach(m => {
            m.role = m.playerId === room.inspectorId ? 'inspector' : 'sender';
        });
    } else {
        room.inspectorId = null;
        room.members.forEach(m => { m.role = 'sender'; });
    }

    const now = Date.now();
    room.roundNumber += 1;
    room.serverIntegrity = 100;
    room.queue = [];
    room.history = [];
    room.roundResult = null;
    room.roundStartedAt = classMatch.status === 'active' ? now : null;
    room.roundEndsAt = classMatch.status === 'active' ? now + ROUND_DURATION_MS : null;
    room.members.forEach(m => {
        m.attackCredits = computeInitialAttackCredits(m.minigameScore);
    });

    res.json({
        success: true,
        room: summarizeRoom(room),
        members: room.members
    });
});

app.post('/api/game/rooms/:roomId/submit-file', (req, res) => {
    const room = classMatch.groupMap[req.params.roomId];
    if (!room) return res.status(404).json({ success: false, error: 'Grupo no encontrado.' });

    if (classMatch.status !== 'active') {
        return res.status(400).json({ success: false, error: 'La ronda aún no inicia (esperando fin del tutorial).' });
    }

    evaluateRoomRoundOutcome(room);
    if (room.roundResult) {
        return res.status(400).json({ success: false, error: 'La ronda ya finalizó. Rota la caseta para jugar otra ronda.' });
    }

    const body = req.body || {};
    const playerId = String(body.playerId || '').trim();
    const isBot = Boolean(body.isBot);
    const member = room.members.find(m => m.playerId === playerId);
    if (!member) {
        return res.status(403).json({ success: false, error: 'Jugador no registrado en este grupo.' });
    }

    if (!isBot && room.inspectorId === playerId) {
        return res.status(400).json({ success: false, error: 'Estás en la caseta como Casero; deja que los atacantes envíen archivos o simula un paquete.' });
    }

    const pendingCount = room.queue.filter(q => q.status === 'pending').length;
    if (pendingCount >= 18) {
        return res.status(429).json({ success: false, error: 'La cola de la caseta está llena (18 expedientes pendientes).' });
    }

    const evaluated = evaluateCraftedPacket({
        filename: body.filename,
        clientMime: body.clientMime,
        payloadType: body.payloadType
    });
    const cost = getPacketAttackCost(evaluated);

    if (!isBot) {
        if ((member.attackCredits || 0) < cost) {
            return res.status(400).json({
                success: false,
                error: `Puntos insuficientes (${member.attackCredits || 0} PTS disponibles; este envío cuesta ${cost} PTS).`
            });
        }
        member.attackCredits -= cost;
    }

    const packet = {
        packetId: crypto.randomUUID().slice(0, 8).toUpperCase(),
        senderId: isBot ? 'bot-redteam' : member.playerId,
        senderName: isBot ? 'Simulador RedTeam (Bot)' : member.name,
        isBot,
        cost: isBot ? 0 : cost,
        note: typeof body.note === 'string' ? body.note.replace(/<[^>]*>?/gm, '').trim().slice(0, 80) : '',
        status: 'pending',
        createdAt: Date.now(),
        ...evaluated
    };

    room.queue.push(packet);
    activateFrontPacketSla(room, packet.createdAt);

    res.json({
        success: true,
        packet,
        room: summarizeRoom(room),
        members: room.members,
        queue: room.queue
    });
});

app.post('/api/game/rooms/:roomId/inspect', (req, res) => {
    const room = classMatch.groupMap[req.params.roomId];
    if (!room) return res.status(404).json({ success: false, error: 'Grupo no encontrado.' });

    evaluateRoomRoundOutcome(room);
    if (room.roundResult) {
        return res.status(400).json({ success: false, error: 'La ronda ya finalizó. Rota la caseta para iniciar otra ronda.' });
    }

    const body = req.body || {};
    const inspectorId = String(body.inspectorId || '').trim();
    const packetId = String(body.packetId || '').trim();
    const action = body.action === 'allow' ? 'allow' : 'block';
    const vector = typeof body.vector === 'string' ? body.vector.trim() : null;

    if (room.inspectorId !== inspectorId) {
        return res.status(403).json({ success: false, error: 'Solo el Casero sorteado puede sellar expedientes.' });
    }

    const qIdx = room.queue.findIndex(q => q.packetId === packetId && q.status === 'pending');
    if (qIdx < 0) {
        return res.status(404).json({ success: false, error: 'El expediente ya fue inspeccionado o no existe.' });
    }

    const packet = room.queue.splice(qIdx, 1)[0];
    if (room.queue.length > 0) {
        activateFrontPacketSla(room, Date.now());
    }
    const inspector = room.members.find(m => m.playerId === inspectorId);
    const sender = packet.isBot ? null : room.members.find(m => m.playerId === packet.senderId);

    let outcome = '';
    const inspectorPoints = 0;
    let hpLoss = 0;
    let senderCreditGain = 0;
    let senderScoreGain = 0;
    let verdictHeadline = '';

    if (!packet.isMalicious) {
        if (action === 'allow') {
            outcome = 'correct_allow';
            verdictHeadline = '✅ Imagen legítima aprobada (0 HP perdido).';
            if (inspector) inspector.correctCount += 1;
        } else {
            outcome = 'false_positive';
            hpLoss = 15;
            senderCreditGain = 110;
            senderScoreGain = 200;
            room.serverIntegrity = Math.max(0, room.serverIntegrity - hpLoss);
            verdictHeadline = '⚠️ Falso positivo: -15 HP al casero. Atacante gana +110 PTS de ataque.';
            if (sender) sender.infiltrations += 1;
        }
    } else {
        if (action === 'allow') {
            outcome = 'breach';
            hpLoss = 25;
            senderCreditGain = 150;
            senderScoreGain = 300;
            room.serverIntegrity = Math.max(0, room.serverIntegrity - hpLoss);
            verdictHeadline = '🚨 ¡Brecha exitosa! -25 HP al casero. Atacante gana +150 PTS de ataque.';
            if (sender) sender.infiltrations += 1;
        } else if (vector === packet.trueVector) {
            outcome = 'correct_block';
            verdictHeadline = '🛡️ Ataque bloqueado con vector exacto (0 HP perdido).';
            if (inspector) inspector.correctCount += 1;
        } else {
            outcome = 'partial_block';
            hpLoss = 10;
            senderCreditGain = 70;
            senderScoreGain = 100;
            room.serverIntegrity = Math.max(0, room.serverIntegrity - hpLoss);
            verdictHeadline = `⚡ Vector incorrecto (era "${packet.trueVector}"): -10 HP al casero. Atacante recupera +70 PTS.`;
        }
    }

    if (inspector) {
        inspector.totalCount += 1;
        syncRoomMemberToLeaderboard(inspector);
    }
    if (sender) {
        sender.totalCount += 1;
        if (senderCreditGain > 0) {
            sender.correctCount += 1;
            sender.attackCredits = (sender.attackCredits || 0) + senderCreditGain;
            sender.score = (sender.score || 0) + senderScoreGain;
        }
        syncRoomMemberToLeaderboard(sender);
    }

    evaluateRoomRoundOutcome(room);

    const record = {
        ...packet,
        status: 'resolved',
        inspectorName: inspector ? inspector.name : 'Casero',
        inspectorAction: action,
        inspectorVector: vector,
        outcome,
        inspectorPoints,
        hpLoss,
        senderPoints: senderScoreGain,
        senderCreditGain,
        verdictHeadline,
        resolvedAt: Date.now()
    };

    room.history.unshift(record);
    if (room.history.length > 30) {
        room.history.length = 30;
    }

    res.json({
        success: true,
        record,
        room: summarizeRoom(room),
        members: room.members,
        queue: room.queue,
        history: room.history
    });
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
