/**
 * ==========================================================================
 * CASETA FORENSE e-Libre (CWE-434)
 * Minijuego previo + Arena Multijugador 1 vs 5 / 1 vs Todos + Modo Solitario
 * ==========================================================================
 */

// --------------------------------------------------------------------------
// 0. DETECCIÓN DE CAPACIDADES Y POLYFILLS CONDICIONALES (modern-web-guidance)
// --------------------------------------------------------------------------
function setupOfflineCommandFallback() {
    document.addEventListener('click', (event) => {
        const trigger = event.target.closest('button[commandfor][command]');
        if (!trigger) return;
        const target = document.getElementById(trigger.getAttribute('commandfor'));
        if (!target) return;
        const cmd = trigger.getAttribute('command');
        if (cmd === 'show-modal' && typeof target.showModal === 'function' && !target.open) {
            target.showModal();
        } else if (cmd === 'close' && typeof target.close === 'function' && target.open) {
            target.close();
        } else if (cmd === 'toggle-popover' && typeof target.togglePopover === 'function') {
            target.togglePopover();
        }
    });
}

if (!('commandForElement' in HTMLButtonElement.prototype)) {
    import('https://esm.run/invokers-polyfill').catch(() => {
        setupOfflineCommandFallback();
    });
}

if (!Object.hasOwn(HTMLElement.prototype, 'popover')) {
    import('https://unpkg.com/@oddbird/popover-polyfill@latest/dist/popover.min.js').catch(() => {});
}

function initDialogFallbacks() {
    if (!('closedBy' in HTMLDialogElement.prototype)) {
        document.querySelectorAll('dialog[closedby="any"]').forEach((dialog) => {
            dialog.addEventListener('click', (event) => {
                if (event.target !== dialog) return;
                const rect = dialog.getBoundingClientRect();
                const isDialogContent = (
                    rect.top <= event.clientY &&
                    event.clientY <= rect.top + rect.height &&
                    rect.left <= event.clientX &&
                    event.clientX <= rect.left + rect.width
                );
                if (isDialogContent) return;
                dialog.close();
            });
        });
    }

    const resetDialog = document.getElementById('resetConfirmDialog');
    if (resetDialog) {
        resetDialog.addEventListener('close', () => {
            const chosen = resetDialog.returnValue;
            resetDialog.returnValue = '';
            if (chosen === 'confirm') {
                resetClassLeaderboard();
            }
        });
    }
}

// --------------------------------------------------------------------------
// 1. BANCOS DE DATOS (MINIJUEGO, PLANTILLAS 1 vs 5, MODO SOLITARIO)
// --------------------------------------------------------------------------
const MINIGAME_ROUNDS = [
    {
        filename: 'avatar_estudiante.png',
        mime: 'image/png',
        hex: '89 50 4E 47 0D 0A 1A 0A   |   .PNG....',
        isSafe: true,
        explanation: 'Firma oficial PNG (89 50 4E 47 0D 0A 1A 0A). Es una imagen auténtica.'
    },
    {
        filename: 'foto_perfil.png',
        mime: 'image/png',
        hex: '3C 3F 70 68 70 20 73 79   |   <?php sy',
        isSafe: false,
        explanation: '¡Engaño! Dice ser .png pero inicia con 3C 3F 70 68 70 (<?php). Es Magic Bytes Spoofing.'
    },
    {
        filename: 'carnet_universidad.jpg',
        mime: 'image/jpeg',
        hex: 'FF D8 FF E0 00 10 4A 46   |   ÿØÿà..JF',
        isSafe: true,
        explanation: 'Cabecera JPEG/JFIF válida (FF D8 FF E0). Archivo legítimo.'
    },
    {
        filename: 'insignia_curso.svg',
        mime: 'image/svg+xml',
        hex: '3C 73 76 67 20 6F 6E 6C   |   <svg onl',
        isSafe: false,
        explanation: '¡Peligro XSS! Archivo SVG con evento JavaScript embebido (<svg onload=...).'
    }
];

const SENDER_PRESETS = {
    normal_png: {
        filename: 'avatar_normal.png',
        mime: 'image/png',
        payloadType: 'png_real',
        note: 'Foto oficial de perfil'
    },
    normal_jpg: {
        filename: 'carnet_estudiantil.jpg',
        mime: 'image/jpeg',
        payloadType: 'jpg_real',
        note: 'Carnet capturado en celular'
    },
    spoofed_png: {
        filename: 'spoofed_script.png',
        mime: 'image/png',
        payloadType: 'php_rce',
        note: 'Avatar optimizado'
    },
    double_ext: {
        filename: 'fake_image.png.php',
        mime: 'application/octet-stream',
        payloadType: 'php_rce',
        note: 'Imagen adjunta de perfil'
    },
    xss_svg: {
        filename: 'insignia_xss.svg',
        mime: 'image/svg+xml',
        payloadType: 'svg_xss',
        note: 'Insignia vectorial de curso'
    },
    traversal_png: {
        filename: '../../../public/logo.png',
        mime: 'image/png',
        payloadType: 'png_real',
        note: 'Actualización de imagen'
    }
};

const PHASE_1_DOSSIERS = [
    {
        id: 'EXP-001',
        context: 'Sebastian Llanos intenta actualizar su foto de perfil en e-Libre.',
        filename: 'avatar_normal.png',
        ext: '.png',
        mime: 'image/png',
        size: '519 bytes',
        hexDump: 'HEX:   89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52\nASCII: .PNG........IHDR',
        expectedAction: 'allow',
        expectedVector: null,
        explanation: 'Archivo PNG legítimo: extensión (.png), Content-Type (image/png) y Magic Bytes reales (89 50 4E 47 0D 0A 1A 0A) coinciden.'
    },
    {
        id: 'EXP-002',
        context: 'Usuario anónimo envía archivo directo al campo "Imagen nueva".',
        filename: 'exploit_poc.php',
        ext: '.php',
        mime: 'application/x-httpd-php',
        size: '3.0 KB (3068 bytes)',
        hexDump: 'HEX:   3C 3F 70 68 70 20 2F 2A 20 50 6F 43 20 52 43 45\nASCII: <?php /* PoC RCE',
        expectedAction: 'block',
        expectedVector: 'rce',
        explanation: 'RCE crítico (CWE-434): el archivo es un script PHP (3C 3F 70 68 70 = "<?php") ejecutable en servidor.'
    },
    {
        id: 'EXP-003',
        context: 'Petición modificada con proxy interceptando extensión y cabecera MIME.',
        filename: 'spoofed_script.png',
        ext: '.png',
        mime: 'image/png',
        size: '199 bytes',
        hexDump: 'HEX:   3C 3F 70 68 70 0A 65 63 68 6F 20 22 52 43 45 22\nASCII: <?php.echo "RCE"',
        expectedAction: 'block',
        expectedVector: 'spoofing',
        explanation: 'Magic Bytes Spoofing: dice ser .png y image/png, pero el buffer inicia con <?php.'
    },
    {
        id: 'EXP-004',
        context: 'Compañera de clase sube fotografía tomada desde su teléfono.',
        filename: 'foto_carnet.jpg',
        ext: '.jpg',
        mime: 'image/jpeg',
        size: '142 KB',
        hexDump: 'HEX:   FF D8 FF E0 00 10 4A 46 49 46 00 01 01 01 00 48\nASCII: ÿØÿà..JFIF.....H',
        expectedAction: 'allow',
        expectedVector: null,
        explanation: 'Imagen JPEG válida: firma hexadecimal FF D8 FF estándar y extensión dentro de la lista blanca.'
    },
    {
        id: 'EXP-005',
        context: 'Estudiante intenta cargar documento web como imagen de perfil.',
        filename: 'exploit_xss.html',
        ext: '.html',
        mime: 'text/html',
        size: '1.65 KB (1692 bytes)',
        hexDump: 'HEX:   3C 21 44 4F 43 54 59 50 45 20 68 74 6D 6C 3E 0A\nASCII: <!DOCTYPE html>.',
        expectedAction: 'block',
        expectedVector: 'xss',
        explanation: 'Stored XSS: documento HTML con script ejecutable bajo el mismo origen de e-Libre.'
    },
    {
        id: 'EXP-006',
        context: 'Petición manipulada vía cURL enviando ruta relativa en filename.',
        filename: '../../../public/index.png',
        ext: '.png',
        mime: 'image/png',
        size: '1.1 KB',
        hexDump: 'HEX:   89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52\nASCII: .PNG........IHDR',
        expectedAction: 'block',
        expectedVector: 'traversal',
        explanation: 'Path Traversal (CWE-22): aunque la firma sea PNG, "../" intenta salir de uploads/ y sobreescribir archivos.'
    }
];

const PHASE_2_CHALLENGES = [
    {
        role: 'RED TEAM • ANÁLISIS DE EVASIÓN',
        title: 'Reto 1: ¿Cómo burlar una validación ingenua?',
        prompt: 'Este backend solo revisa path.extname() y req.file.mimetype. ¿Qué envío evade ambos filtros?',
        contextCode: `const ext = path.extname(req.file.originalname).toLowerCase();
const mime = req.file.mimetype;
if (['.png', '.jpg', '.gif'].includes(ext) && mime.startsWith('image/')) {
    fs.writeFileSync('uploads/public/' + req.file.originalname, req.file.buffer);
}`,
        options: [
            { label: 'A) spoofed_script.png con Content-Type: image/png', code: 'Nombre: spoofed_script.png\nContent-Type: image/png\nBuffer: <?php system($_GET["cmd"]); ?>', isCorrect: true },
            { label: 'B) exploit_poc.php sin modificar cabecera', code: 'Nombre: exploit_poc.php\nContent-Type: application/x-httpd-php', isCorrect: false },
            { label: 'C) fake_image.png.php directo', code: 'Nombre: fake_image.png.php\n(path.extname devuelve ".php")', isCorrect: false },
            { label: 'D) avatar_normal.png legítimo', code: 'Nombre: avatar_normal.png\nBuffer: 89 50 4E 47', isCorrect: false }
        ],
        explanation: 'path.extname("spoofed_script.png") devuelve ".png" y el atacante falsifica Content-Type: image/png; sin Magic Bytes el script entra al servidor.'
    },
    {
        role: 'BLUE TEAM • PARCHE 1: EXTENSIONES',
        title: 'Reto 2: Lista Blanca Estricta vs. Lista Negra',
        prompt: '¿Qué implementación bloquea variantes como .phtml, .php5 o fake_image.png.php?',
        contextCode: null,
        options: [
            { label: 'A) Lista Negra', code: "const BLOCKED = ['.php', '.exe'];\nif (BLOCKED.includes(ext)) return res.status(400).end();", isCorrect: false },
            { label: 'B) Subcadena includes()', code: "if (!originalName.includes('.png')) return res.status(400).end();", isCorrect: false },
            { label: 'C) Lista Blanca Estricta con extname', code: "const rawExt = path.extname(originalName).toLowerCase().replace('.', '');\nconst ALLOWED = ['jpg', 'jpeg', 'png', 'gif'];\nif (!ALLOWED.includes(rawExt)) return res.status(400).json({ status: 'blocked' });", isCorrect: true },
            { label: 'D) Solo atributo HTML accept', code: '<input type="file" accept=".png,.jpg">', isCorrect: false }
        ],
        explanation: 'La Lista Blanca Estricta sobre la extensión final de path.extname() solo acepta formatos permitidos explícitamente.'
    },
    {
        role: 'BLUE TEAM • PARCHE 2: MEMORIA Y MAGIC BYTES',
        title: 'Reto 3: Inspección Binaria antes de tocar el Disco',
        prompt: '¿Qué configuración evita escribir en disco archivos cuyo contenido real no es imagen?',
        contextCode: null,
        options: [
            { label: 'A) Guardar en disco y luego borrar', code: "multer({ dest: 'uploads/' })\n// borrar después si falla", isCorrect: false },
            { label: 'B) Buffer en RAM + verifyMagicBytes()', code: "const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024 } });\nif (!verifyMagicBytes(req.file.buffer, rawExt)) return res.status(400).json({ status: 'blocked' });", isCorrect: true },
            { label: 'C) Confiar en req.file.mimetype', code: "if (req.file.mimetype === 'image/png') save();", isCorrect: false },
            { label: 'D) Revisar solo mayúsculas', code: "if (originalName.toUpperCase().endsWith('PNG')) allow();", isCorrect: false }
        ],
        explanation: 'multer.memoryStorage() inspecciona los primeros bytes en buffer antes de escribir nada en el disco.'
    },
    {
        role: 'BLUE TEAM • PARCHE 3: ALMACENAMIENTO Y HEADERS',
        title: 'Reto 4: Renombrado UUID y Entrega Segura',
        prompt: '¿Cómo almacenar y entregar la imagen ya validada contra Path Traversal y MIME Confusion?',
        contextCode: null,
        options: [
            { label: 'A) Nombre original en carpeta pública', code: "fs.writeFileSync('public/uploads/' + originalName, buffer);", isCorrect: false },
            { label: 'B) UUID v4 + directorio aislado + nosniff & CSP', code: "const secureFilename = `${crypto.randomUUID()}.${safeExt}`;\nfs.writeFileSync(path.join(SECURE_DIR, secureFilename), buffer);\nres.setHeader('X-Content-Type-Options', 'nosniff');\nres.setHeader('Content-Security-Policy', \"default-src 'none'\");", isCorrect: true },
            { label: 'C) Timestamp y MIME del cliente', code: "res.setHeader('Content-Type', req.body.mime);", isCorrect: false },
            { label: 'D) Permisos chmod 777', code: "fs.chmodSync(SECURE_DIR, 0o777);", isCorrect: false }
        ],
        explanation: 'crypto.randomUUID() neutraliza ../ y sobreescrituras, el directorio aislado impide ejecución y nosniff + CSP protegen al navegador.'
    }
];

const PHASE_3_QUIZ = [
    {
        question: '¿Qué identificador CWE clasifica la vulnerabilidad de "Subida Insegura de Archivos"?',
        options: ['CWE-89 (SQL Injection)', 'CWE-434 (Unrestricted Upload of File with Dangerous Type)', 'CWE-798 (Hard-coded Credentials)', 'CWE-352 (CSRF)'],
        correctIdx: 1,
        explanation: 'CWE-434 corresponde a Unrestricted Upload of File with Dangerous Type.'
    },
    {
        question: '¿Cuál es la firma hexadecimal (Magic Bytes) inicial de un archivo PNG legítimo?',
        options: ['3C 3F 70 68', '47 49 46 38', '89 50 4E 47', 'FF D8 FF E0'],
        correctIdx: 2,
        explanation: 'Un PNG válido comienza con 89 50 4E 47 0D 0A 1A 0A.'
    },
    {
        question: '¿Qué ataque previene la cabecera HTTP "X-Content-Type-Options: nosniff"?',
        options: ['Fuerza bruta de contraseñas', 'MIME Confusion / Sniffing Attacks en el navegador', 'DoS por ancho de banda', 'Inyección SQL'],
        correctIdx: 1,
        explanation: 'Impide que el navegador reinterprete una imagen o binario como HTML/JavaScript ejecutable.'
    },
    {
        question: '¿Por qué "fake_image.png.php" burla if (filename.includes(".png"))?',
        options: ['Pesa más de 1 GB', 'Contiene ".png" en medio, pero su extensión final ejecutable es ".php"', 'Node.js lo convierte en PNG', 'Tiene dos puntos obligatorios'],
        correctIdx: 1,
        explanation: 'Es un bypass por doble extensión: el filtro ingenuo ve ".png", pero el servidor web interpreta ".php".'
    },
    {
        question: '¿Qué ocurre si un atacante sube un ".svg" con <script> a /uploads/vulnerable/ y otro usuario lo abre?',
        options: ['Stored XSS bajo el mismo origen de la plataforma', 'Cifrado automático', 'Bloqueo por UUID v4', 'Compresión segura'],
        correctIdx: 0,
        explanation: 'El navegador ejecuta el script embebido en el SVG bajo el origen de e-Libre (Stored XSS).'
    }
];

// --------------------------------------------------------------------------
// 2. ESTADO GLOBAL
// --------------------------------------------------------------------------
const state = {
    playerId: null,
    playerName: 'Sin registro',
    gameMode: 'multiplayer',
    selectedRoomId: null,
    assignedRole: 'sender',
    attackCredits: 200,
    remainingSeconds: 120,
    roundResult: null,
    minigameIndex: 0,
    minigameScore: 0,
    minigameAnswered: false,
    score: 0,
    streak: 0,
    maxStreak: 0,
    integrity: 100,
    phase: 1,
    index: 0,
    correctCount: 0,
    totalAnswered: 0,
    answeredCurrent: false,
    badges: [],
    history: [],
    completed: false,
    soundEnabled: true,
    activeScreen: 'screenLobby',
    previousScreen: 'screenLobby',
    currentBoothPacketId: null,
    lastResolvedId: null
};

let miniTimerInterval = null;
let miniTimeLeft = 10;
let quizTimerInterval = null;
let quizTimeLeft = 20;
let arenaClockInterval = null;
let boothSlaInterval = null;
let boothSlaDeadlineAt = null;
let boothSlaTotalMs = 15000;
let boothSlaRefreshRequested = false;
let projectorUiTickInterval = null;
const projectorRoomState = new Map();
let activePollInterval = null;
let audioCtx = null;

const SCREEN_HEADINGS = {
    screenLobby: 'lobbyHeading',
    screenMinigame: 'minigameHeading',
    screenWaiting: 'waitingHeading',
    screenBriefing: 'briefingHeading',
    screenArena: 'arenaHeading',
    screenGame: 'soloHeading',
    screenResults: 'resultsHeading',
    screenProjector: 'projectorHeading'
};

// --------------------------------------------------------------------------
// 3. INICIALIZACIÓN Y EVENTOS (ZERO INLINE HANDLERS)
// --------------------------------------------------------------------------
function isProjectorEntryRoute() {
    const normalizedPath = window.location.pathname.replace(/\/+$/, '');
    const params = new URLSearchParams(window.location.search);
    return normalizedPath === '/proyector'
        || normalizedPath === '/juego/proyector'
        || params.get('modo') === 'proyector'
        || params.get('proyector') === '1';
}

document.addEventListener('DOMContentLoaded', () => {
    initDialogFallbacks();

    const joinEl = document.getElementById('projectorJoinUrl');
    if (joinEl) joinEl.textContent = `${window.location.origin}/juego`;

    const savedName = localStorage.getItem('appsec_player_name');
    const nameInput = document.getElementById('playerNameInput');
    if (savedName && nameInput) nameInput.value = savedName;

    bindStaticListeners();
    updateHud();

    if (isProjectorEntryRoute()) {
        const statsEl = document.getElementById('hudStudentStats');
        if (statsEl) statsEl.hidden = true;
        document.title = 'Proyector Salón | Caseta Forense e-Libre';
        openProjectorView();
    } else {
        startLobbyPolling();
    }
});

function bindStaticListeners() {
    document.getElementById('btnToggleSound')?.addEventListener('click', toggleSound);
    document.getElementById('btnProjRefresh')?.addEventListener('click', fetchLeaderboardAndRooms);
    document.getElementById('btnProjShuffleMatch')?.addEventListener('click', () => startClassMatchFromClient(true, true));
    document.getElementById('btnProjDirectRound')?.addEventListener('click', () => startClassMatchFromClient(true, false));
    document.getElementById('btnProjOpenTutorial')?.addEventListener('click', () => openTutorialPlayer(true));
    document.getElementById('btnRefreshRooms')?.addEventListener('click', fetchLobbyStatus);

    document.querySelectorAll('.proj-mode-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
            setClassGameMode(btn.dataset.projMode);
        });
    });

    // Controles del reproductor de video tutorial
    document.getElementById('btnTutorialClose')?.addEventListener('click', closeTutorialPlayer);
    document.getElementById('btnTutPlayPause')?.addEventListener('click', toggleTutorialPlayPause);
    document.getElementById('btnTutVoice')?.addEventListener('click', toggleTutorialVoice);
    document.getElementById('btnTutRestart')?.addEventListener('click', restartTutorial);
    document.getElementById('btnTutLaunchNow')?.addEventListener('click', launchMatchFromBriefing);
    document.querySelectorAll('.tut-chap-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
            const idx = Number(btn.dataset.tutScene || 0);
            jumpToTutorialScene(idx);
        });
    });

    document.getElementById('lobbyForm')?.addEventListener('submit', handleLobbyStart);

    // Minijuego y Sala de Espera
    document.getElementById('btnMiniSafe')?.addEventListener('click', () => submitMinigameAnswer(true));
    document.getElementById('btnMiniMalicious')?.addEventListener('click', () => submitMinigameAnswer(false));
    document.getElementById('btnWaitingBackLobby')?.addEventListener('click', () => navigateScreen('screenLobby'));

    // Arena
    document.getElementById('btnLeaveArena')?.addEventListener('click', () => {
        navigateScreen('screenLobby');
    });
    document.getElementById('btnBoothAllow')?.addEventListener('click', () => inspectCurrentPacket('allow', null));
    document.getElementById('btnBoothOpenBlock')?.addEventListener('click', () => {
        document.getElementById('boothDecisionRow').hidden = true;
        document.getElementById('boothVectorPanel').hidden = false;
    });
    document.getElementById('btnBoothCancelBlock')?.addEventListener('click', () => {
        document.getElementById('boothVectorPanel').hidden = true;
        document.getElementById('boothDecisionRow').hidden = false;
    });
    document.getElementById('boothVectorPanel')?.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-booth-vector]');
        if (!btn) return;
        inspectCurrentPacket('block', btn.dataset.boothVector);
    });

    // Presets y envío de los Atacantes
    document.getElementById('senderPresetsGrid')?.addEventListener('change', (e) => {
        const radio = e.target.closest('input[name="craftPreset"]');
        if (!radio) return;
        applyCraftPreset(radio.value);
    });
    document.getElementById('craftFilename')?.addEventListener('input', updateCraftCostButton);
    document.getElementById('craftMime')?.addEventListener('change', updateCraftCostButton);
    document.getElementById('craftPayloadType')?.addEventListener('change', updateCraftCostButton);
    document.getElementById('senderCraftForm')?.addEventListener('submit', handleSenderSubmit);

    // Modo Solitario
    document.getElementById('btnSoloAllow')?.addEventListener('click', submitPhase1Allow);
    document.getElementById('btnSoloOpenBlock')?.addEventListener('click', () => {
        if (state.answeredCurrent) return;
        document.getElementById('phase1DecisionControls').hidden = true;
        document.getElementById('vectorSelector').hidden = false;
    });
    document.getElementById('btnSoloCancelBlock')?.addEventListener('click', () => {
        document.getElementById('vectorSelector').hidden = true;
        document.getElementById('phase1DecisionControls').hidden = false;
    });
    document.getElementById('vectorSelector')?.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-solo-vector]');
        if (!btn) return;
        submitPhase1Block(btn.dataset.soloVector);
    });

    document.getElementById('btnPlayAgain')?.addEventListener('click', () => {
        stopQuizTimer();
        navigateScreen('screenLobby');
    });
}

// --------------------------------------------------------------------------
// 4. VIEW TRANSITIONS Y NAVEGACIÓN CON GESTIÓN DE FOCO
// --------------------------------------------------------------------------
function navigateScreen(screenId) {
    stopPolling();
    if (screenId !== 'screenMinigame') stopMiniTimer();
    if (screenId !== 'screenGame') stopQuizTimer();
    if (screenId !== 'screenProjector') pauseTutorial();

    const applyDOMUpdate = () => {
        document.querySelectorAll('.game-screen').forEach((sec) => {
            const isTarget = sec.id === screenId;
            sec.hidden = !isTarget;
            sec.classList.toggle('is-active', isTarget);
        });
        state.activeScreen = screenId;
    };

    const routeFocus = () => {
        const headingId = SCREEN_HEADINGS[screenId];
        if (headingId) {
            document.getElementById(headingId)?.focus();
        }
    };

    if (!document.startViewTransition) {
        applyDOMUpdate();
        routeFocus();
    } else {
        const transition = document.startViewTransition(applyDOMUpdate);
        transition.finished.finally(routeFocus);
    }

    if (screenId === 'screenLobby') startLobbyPolling();
    if (screenId === 'screenWaiting' || screenId === 'screenBriefing') startWaitingPolling();
    if (screenId === 'screenArena') startArenaPolling();
    if (screenId === 'screenResults' || screenId === 'screenProjector') startLeaderboardPolling();
}

function stopBoothSlaTimer() {
    if (boothSlaInterval) {
        clearInterval(boothSlaInterval);
        boothSlaInterval = null;
    }
    boothSlaDeadlineAt = null;
    boothSlaRefreshRequested = false;
}

function stopProjectorUiTicker() {
    if (projectorUiTickInterval) {
        clearInterval(projectorUiTickInterval);
        projectorUiTickInterval = null;
    }
}

function stopPolling() {
    if (activePollInterval) {
        clearInterval(activePollInterval);
        activePollInterval = null;
    }
    if (arenaClockInterval) {
        clearInterval(arenaClockInterval);
        arenaClockInterval = null;
    }
    stopBoothSlaTimer();
    stopProjectorUiTicker();
}

function startLobbyPolling() {
    stopPolling();
    fetchLobbyStatus();
    activePollInterval = setInterval(fetchLobbyStatus, 3000);
}

function startWaitingPolling() {
    stopPolling();
    fetchMatchStatus();
    activePollInterval = setInterval(fetchMatchStatus, 2000);
}

function startArenaPolling() {
    stopPolling();
    fetchMatchStatus();
    activePollInterval = setInterval(fetchMatchStatus, 2000);
}

function startLeaderboardPolling() {
    stopPolling();
    fetchLeaderboardAndRooms();
    const intervalMs = state.activeScreen === 'screenProjector' ? 1500 : 4000;
    activePollInterval = setInterval(fetchLeaderboardAndRooms, intervalMs);
    if (state.activeScreen === 'screenProjector') {
        startProjectorUiTicker();
    }
}

// --------------------------------------------------------------------------
// 5. AUDIO SINTÉTICO Y HUD
// --------------------------------------------------------------------------
function playSound(type) {
    if (!state.soundEnabled) return;
    try {
        const AudioContextClass = window.AudioContext || window.webkitAudioContext;
        if (!AudioContextClass) return;
        if (!audioCtx) audioCtx = new AudioContextClass();
        if (audioCtx.state === 'suspended') audioCtx.resume();

        const now = audioCtx.currentTime;
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.connect(gain);
        gain.connect(audioCtx.destination);

        if (type === 'success') {
            osc.type = 'triangle';
            osc.frequency.setValueAtTime(523.25, now);
            osc.frequency.exponentialRampToValueAtTime(783.99, now + 0.14);
            gain.gain.setValueAtTime(0.11, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.24);
            osc.start(now);
            osc.stop(now + 0.25);
        } else if (type === 'error') {
            osc.type = 'sawtooth';
            osc.frequency.setValueAtTime(185, now);
            osc.frequency.linearRampToValueAtTime(110, now + 0.22);
            gain.gain.setValueAtTime(0.1, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.26);
            osc.start(now);
            osc.stop(now + 0.27);
        } else if (type === 'victory') {
            [523.25, 659.25, 783.99, 1046.5].forEach((freq, idx) => {
                const o = audioCtx.createOscillator();
                const g = audioCtx.createGain();
                o.type = 'triangle';
                o.connect(g);
                g.connect(audioCtx.destination);
                const start = now + idx * 0.08;
                o.frequency.setValueAtTime(freq, start);
                g.gain.setValueAtTime(0.1, start);
                g.gain.exponentialRampToValueAtTime(0.001, start + 0.26);
                o.start(start);
                o.stop(start + 0.28);
            });
        }
    } catch {
        // Navegador bloqueó audio automático
    }
}

function toggleSound() {
    state.soundEnabled = !state.soundEnabled;
    const btn = document.getElementById('btnToggleSound');
    const icon = document.getElementById('soundIcon');
    if (btn) btn.setAttribute('aria-pressed', String(state.soundEnabled));
    if (icon) {
        icon.className = state.soundEnabled ? 'fa-solid fa-volume-high' : 'fa-solid fa-volume-xmark';
    }
}

function updateHud() {
    document.getElementById('hudPlayerName').textContent = state.playerName;
    document.getElementById('hudStreak').textContent = String(state.streak);
    document.getElementById('hudScore').textContent = String(state.score);
    document.getElementById('hudIntegrity').textContent = `${state.integrity}%`;

    const pill = document.getElementById('hudIntegrityPill');
    if (pill) {
        pill.classList.remove('is-warning', 'is-critical');
        if (state.integrity <= 40) pill.classList.add('is-critical');
        else if (state.integrity <= 70) pill.classList.add('is-warning');
    }

    const s1 = document.getElementById('stepperPhase1');
    const s2 = document.getElementById('stepperPhase2');
    const s3 = document.getElementById('stepperPhase3');
    [s1, s2, s3].forEach((el) => el?.classList.remove('is-active', 'is-done'));
    if (state.phase === 1) s1?.classList.add('is-active');
    if (state.phase === 2) {
        s1?.classList.add('is-done');
        s2?.classList.add('is-active');
    }
    if (state.phase === 3) {
        s1?.classList.add('is-done');
        s2?.classList.add('is-done');
        s3?.classList.add('is-active');
    }
}

// --------------------------------------------------------------------------
// 6. LOBBY, CALIBRACIÓN Y SORTEO ALEATORIO BALANCEADO
// --------------------------------------------------------------------------
async function fetchLobbyStatus() {
    try {
        const url = state.playerId
            ? `/api/game/match/status?playerId=${encodeURIComponent(state.playerId)}`
            : '/api/game/match/status';
        const res = await fetch(url);
        if (!res.ok) return;
        const data = await res.json();
        renderLobbyStatus(data);
    } catch {
        // Silencioso si está desconectado
    }
}

function applyServerGameMode(rawMode) {
    const mode = rawMode === 'solo' ? 'solo' : 'multiplayer';
    state.gameMode = mode;

    const modeTitle = document.getElementById('lobbyActiveModeTitle');
    const modeDesc = document.getElementById('lobbyActiveModeDesc');
    const roomPicker = document.getElementById('roomPickerWrap');
    const btnLabel = document.getElementById('btnStartLobbyLabel');

    if (modeTitle) {
        modeTitle.textContent = mode === 'multiplayer'
            ? 'Emparejamiento Aleatorio Balanceado (1 Casero vs Atacantes)'
            : 'Misión Individual (3 Fases: Inspector, Parcheo y Quiz OWASP)';
    }
    if (modeDesc) {
        modeDesc.textContent = mode === 'multiplayer'
            ? 'Superarás la calibración de Magic Bytes y entrarás al sorteo automático de grupos del salón.'
            : 'Resolverás los retos forenses de manera individual en 3 fases progresivas.';
    }
    if (roomPicker) roomPicker.hidden = mode !== 'multiplayer';
    if (btnLabel) {
        btnLabel.textContent = mode === 'multiplayer'
            ? 'Comenzar Minijuego de Calibración'
            : 'Iniciar Misión Individual (3 Fases)';
    }

    document.getElementById('btnProjModeMulti')?.classList.toggle('is-selected', mode === 'multiplayer');
    document.getElementById('btnProjModeSolo')?.classList.toggle('is-selected', mode === 'solo');
}

async function setClassGameMode(mode) {
    try {
        const res = await fetch('/api/game/match/mode', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ gameMode: mode === 'solo' ? 'solo' : 'multiplayer' })
        });
        if (!res.ok) return;
        const data = await res.json();
        renderProjectorMatchStatus(data);
    } catch {
        // Silencioso
    }
}

function renderLobbyStatus(data) {
    applyServerGameMode(data.gameMode);

    const summaryEl = document.getElementById('lobbyClassSummary');
    const previewEl = document.getElementById('lobbyPreviewText');
    if (!summaryEl || !previewEl) return;

    const total = data.totalPlayers || 0;
    const groupsCount = (data.groups || []).length;
    if (data.status === 'active') {
        summaryEl.textContent = `Partida en curso: ${total} estudiantes distribuidos en ${groupsCount} grupo(s). Si te unes ahora entrarás al grupo con menos integrantes.`;
    } else {
        summaryEl.textContent = `${total} estudiante(s) en sala de espera listos para el sorteo aleatorio.`;
    }
    if (data.preview && data.preview.summaryText) {
        previewEl.textContent = data.preview.summaryText;
    }
}

function handleLobbyStart(event) {
    event.preventDefault();
    const input = document.getElementById('playerNameInput');
    const cleanName = (input.value || '').replace(/<[^>]*>?/gm, '').trim().slice(0, 28);
    if (!cleanName) {
        input.focus();
        return;
    }

    localStorage.setItem('appsec_player_name', cleanName);

    if (!state.playerId) {
        state.playerId = (window.crypto && crypto.randomUUID)
            ? crypto.randomUUID()
            : `p_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    }

    state.playerName = cleanName;
    state.score = 0;
    state.streak = 0;
    state.maxStreak = 0;
    state.integrity = 100;
    state.phase = 1;
    state.index = 0;
    state.correctCount = 0;
    state.totalAnswered = 0;
    state.answeredCurrent = false;
    state.badges = [];
    state.history = [];
    state.completed = false;
    state.minigameIndex = 0;
    state.minigameScore = 0;
    state.currentBoothPacketId = null;
    state.lastResolvedId = null;

    updateHud();

    if (state.gameMode === 'multiplayer') {
        navigateScreen('screenMinigame');
        loadMinigameRound();
    } else {
        navigateScreen('screenGame');
        loadPhase1Dossier();
        syncSoloScoreToServer();
    }
}

function loadMinigameRound() {
    const item = MINIGAME_ROUNDS[state.minigameIndex];
    state.minigameAnswered = false;

    document.getElementById('miniCounter').textContent = `Ronda ${state.minigameIndex + 1} / ${MINIGAME_ROUNDS.length}`;
    document.getElementById('miniHexCode').textContent = item.hex;
    document.getElementById('miniFilename').textContent = item.filename;
    document.getElementById('miniMime').textContent = item.mime;
    document.getElementById('miniScoreText').textContent = `${state.minigameScore} PTS`;
    document.getElementById('miniFeedback').hidden = true;
    document.getElementById('btnMiniSafe').disabled = false;
    document.getElementById('btnMiniMalicious').disabled = false;

    startMiniTimer();
}

function startMiniTimer() {
    stopMiniTimer();
    miniTimeLeft = 10;
    updateMiniTimerUI();

    miniTimerInterval = setInterval(() => {
        miniTimeLeft -= 1;
        updateMiniTimerUI();
        if (miniTimeLeft <= 0) {
            stopMiniTimer();
            submitMinigameAnswer(null);
        }
    }, 1000);
}

function stopMiniTimer() {
    if (miniTimerInterval) {
        clearInterval(miniTimerInterval);
        miniTimerInterval = null;
    }
}

function updateMiniTimerUI() {
    const bar = document.getElementById('miniTimerBar');
    const text = document.getElementById('miniTimerText');
    const pct = Math.max(0, (miniTimeLeft / 10) * 100);
    if (bar) {
        bar.style.setProperty('--timer-pct', `${pct}%`);
        bar.classList.toggle('is-urgent', miniTimeLeft <= 3);
    }
    if (text) text.textContent = `${miniTimeLeft}s`;
}

function submitMinigameAnswer(chosenSafe) {
    if (state.minigameAnswered) return;
    state.minigameAnswered = true;
    stopMiniTimer();

    document.getElementById('btnMiniSafe').disabled = true;
    document.getElementById('btnMiniMalicious').disabled = true;

    const item = MINIGAME_ROUNDS[state.minigameIndex];
    const isCorrect = chosenSafe !== null && chosenSafe === item.isSafe;
    let earned = 0;

    if (isCorrect) {
        earned = 100 + miniTimeLeft * 10;
        state.minigameScore += earned;
        state.score = state.minigameScore;
        state.streak += 1;
        playSound('success');
    } else {
        state.streak = 0;
        playSound('error');
    }

    document.getElementById('miniScoreText').textContent = `${state.minigameScore} PTS`;
    updateHud();

    const fb = document.getElementById('miniFeedback');
    fb.className = `feedback-banner ${isCorrect ? 'is-success' : 'is-error'}`;
    const isLast = state.minigameIndex === MINIGAME_ROUNDS.length - 1;
    const msg = chosenSafe === null
        ? '⏱️ Tiempo agotado'
        : (isCorrect ? `✅ Calibración correcta (+${earned} PTS)` : '❌ Firma mal clasificada (0 PTS)');

    fb.innerHTML = `
        <div class="feedback-title-row">
            <span>${escapeHtml(msg)}</span>
        </div>
        <p>${escapeHtml(item.explanation)}</p>
        <button type="button" class="feedback-next-btn" id="btnNextMiniRound">
            ${isLast ? 'Ir al Sorteo de Caseta' : 'Siguiente Firma'}
        </button>
    `;
    fb.hidden = false;

    document.getElementById('btnNextMiniRound')?.addEventListener('click', () => {
        if (state.minigameIndex < MINIGAME_ROUNDS.length - 1) {
            state.minigameIndex += 1;
            loadMinigameRound();
        } else {
            joinMultiplayerMatch();
        }
    });
}

// --------------------------------------------------------------------------
// 7. SALA DE ESPERA, SORTEO ALEATORIO Y ARENA ASIMÉTRICA
// --------------------------------------------------------------------------
async function joinMultiplayerMatch() {
    try {
        const res = await fetch('/api/game/match/join', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                playerId: state.playerId,
                name: state.playerName,
                minigameScore: state.minigameScore
            })
        });
        const data = await res.json();
        if (!res.ok || !data.success) {
            navigateScreen('screenLobby');
            return;
        }
        applyMatchStatusPayload(data, true);
    } catch {
        navigateScreen('screenLobby');
    }
}

async function fetchMatchStatus() {
    if (!state.playerId) return;
    try {
        const res = await fetch(`/api/game/match/status?playerId=${encodeURIComponent(state.playerId)}`);
        if (!res.ok) return;
        const data = await res.json();
        applyMatchStatusPayload(data, false);
    } catch {
        // Silencioso en polling
    }
}

async function startClassMatchFromClient(fromProjector, withBriefing = true) {
    try {
        const res = await fetch('/api/game/match/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                playerId: state.playerId || '',
                withBriefing: Boolean(withBriefing)
            })
        });
        const data = await res.json();
        if (!res.ok || !data.success) {
            const msg = data.error || 'Aún no hay estudiantes suficientes en espera.';
            const warnEl = document.getElementById('waitingMinWarning');
            const projPreview = document.getElementById('projPreviewSummary');
            if (warnEl && !fromProjector) {
                warnEl.textContent = msg;
                warnEl.hidden = false;
            }
            if (projPreview && fromProjector) {
                projPreview.textContent = msg;
            }
            return;
        }

        if (fromProjector) {
            fetchLeaderboardAndRooms();
            if (data.status === 'briefing') {
                openTutorialPlayer(true);
            }
        } else {
            applyMatchStatusPayload(data, true);
        }
    } catch {
        // Silencioso
    }
}

async function launchMatchFromBriefing() {
    pauseTutorial();
    try {
        const res = await fetch('/api/game/match/launch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ playerId: state.playerId || '' })
        });
        const data = await res.json();
        if (!res.ok || !data.success) return;

        tutorialState.matchStatus = data.status;
        if (state.activeScreen === 'screenProjector') {
            closeTutorialPlayer();
            fetchLeaderboardAndRooms();
        } else {
            applyMatchStatusPayload(data, true);
        }
    } catch {
        // Silencioso
    }
}

function applyMatchStatusPayload(data, forceNavigate) {
    tutorialState.matchStatus = data.status;

    if (data.status === 'waiting') {
        if (state.activeScreen === 'screenArena' || state.activeScreen === 'screenBriefing') {
            navigateScreen('screenLobby');
            return;
        }
        if (forceNavigate || state.activeScreen === 'screenWaiting') {
            if (state.activeScreen !== 'screenWaiting') {
                navigateScreen('screenWaiting');
            }
            renderWaitingScreen(data);
        }
        return;
    }

    if (data.status === 'briefing' && data.assignment) {
        if (state.activeScreen !== 'screenBriefing' && state.activeScreen !== 'screenProjector') {
            navigateScreen('screenBriefing');
        }
        state.selectedRoomId = data.assignment.roomId;
        renderBriefingScreen(data.assignment);
        return;
    }

    if (data.status === 'active' && data.assignment) {
        const cameFromBriefing = state.activeScreen === 'screenBriefing';
        if (state.activeScreen !== 'screenArena' && state.activeScreen !== 'screenProjector') {
            if (cameFromBriefing) playSound('victory');
            navigateScreen('screenArena');
        }
        state.selectedRoomId = data.assignment.roomId;
        renderRoomPayload(data.assignment);
    } else if (data.status !== 'waiting' && forceNavigate) {
        navigateScreen('screenWaiting');
        renderWaitingScreen(data);
    }
}

function renderBriefingScreen(assignment) {
    const room = assignment.room;
    const members = assignment.members || [];
    const role = assignment.assignedRole || 'sender';
    if (!room) return;

    const card = document.getElementById('briefingRoleCard');
    const groupBadge = document.getElementById('briefingGroupBadge');
    const roleTitle = document.getElementById('briefingRoleTitle');
    const roleDesc = document.getElementById('briefingRoleDesc');
    const listEl = document.getElementById('briefingMembersList');

    if (card) {
        card.className = `briefing-role-hero ${role === 'inspector' ? 'is-inspector' : 'is-sender'}`;
    }
    if (groupBadge) {
        groupBadge.textContent = `${room.name.toUpperCase()} • RONDA ${room.roundNumber}`;
    }
    const me = members.find((m) => m.playerId === state.playerId);
    const myCredits = me ? (me.attackCredits ?? 200) : 200;
    if (roleTitle) {
        roleTitle.textContent = role === 'inspector'
            ? '🛡️ Te tocó: CASERO (DEFENSOR DE LA CASETA)'
            : '📤 Te tocó: ATACANTE / REMITENTE';
    }
    if (roleDesc) {
        roleDesc.textContent = role === 'inspector'
            ? `Tienes 100 HP y debes aguantar 2:00 minutos contra ${room.attackerCount} atacante(s) respondiendo en <= ${room.slaSeconds || 15}s por expediente. Si no respondes a tiempo pierdes vida por inactividad.`
            : `Arrancas con ${myCredits} PTS de ataque. Enviar archivos cuesta 50–80 PTS para evitar spam; si vulneras al casero (+150 PTS), provocas falso positivo (+110 PTS) o vence su tiempo de respuesta ganas puntos.`;
    }

    if (listEl) {
        listEl.innerHTML = members.map((m) => {
            const isInsp = m.playerId === room.inspectorId;
            const isMe = m.playerId === state.playerId;
            return `
                <li class="waiting-player-chip ${isMe ? 'is-me' : ''}">
                    <strong>${escapeHtml(m.name)}${isMe ? ' (Tú)' : ''}</strong>
                    <span>${isInsp ? '🛡️ Caseta' : '📤 Atacante'}</span>
                </li>
            `;
        }).join('');
    }
}

function renderWaitingScreen(data) {
    const previewEl = document.getElementById('waitingPreviewBox');
    const warnEl = document.getElementById('waitingMinWarning');
    const listEl = document.getElementById('waitingPlayersList');

    if (previewEl && data.preview) {
        previewEl.textContent = data.preview.summaryText;
    }
    if (warnEl && data.preview) {
        warnEl.hidden = data.preview.minRecommendedMet;
        if (!data.preview.minRecommendedMet) {
            warnEl.textContent = 'Se recomiendan al menos 4 estudiantes para que cada caseta tenga mínimo 3 atacantes (puedes sortear e iniciar igual para probar).';
        }
    }

    const players = data.waitingPlayers || [];
    if (listEl) {
        listEl.innerHTML = players.map((p) => {
            const isMe = state.playerId && p.playerId === state.playerId;
            return `
                <li class="waiting-player-chip ${isMe ? 'is-me' : ''}">
                    <strong>${escapeHtml(p.name)}${isMe ? ' (Tú)' : ''}</strong>
                    <span>${p.score || 0} PTS</span>
                </li>
            `;
        }).join('');
    }
}

function formatClockMMSS(totalSec) {
    const s = Math.max(0, Math.floor(totalSec || 0));
    const mm = String(Math.floor(s / 60)).padStart(2, '0');
    const ss = String(s % 60).padStart(2, '0');
    return `${mm}:${ss}`;
}

function updateArenaTimerUI() {
    const chip = document.getElementById('arenaTimerChip');
    const txt = document.getElementById('arenaTimerText');
    if (txt) txt.textContent = formatClockMMSS(state.remainingSeconds);
    if (chip) chip.classList.toggle('is-urgent', state.remainingSeconds <= 20 && !state.roundResult);
}

function syncArenaClock(room) {
    state.remainingSeconds = Number.isFinite(room.remainingSeconds) ? room.remainingSeconds : 120;
    state.roundResult = room.roundResult || null;
    updateArenaTimerUI();

    if (arenaClockInterval) {
        clearInterval(arenaClockInterval);
        arenaClockInterval = null;
    }

    if (!state.roundResult && state.activeScreen === 'screenArena') {
        arenaClockInterval = setInterval(() => {
            if (state.roundResult || state.activeScreen !== 'screenArena') {
                clearInterval(arenaClockInterval);
                arenaClockInterval = null;
                return;
            }
            if (state.remainingSeconds > 0) {
                state.remainingSeconds -= 1;
                updateArenaTimerUI();
                if (state.remainingSeconds === 0) {
                    fetchMatchStatus();
                }
            }
        }, 1000);
    }
}

function renderRoomPayload(data) {
    const room = data.room;
    const members = data.members || [];
    const queue = data.queue || [];
    const history = data.history || [];

    if (!room) return;

    const me = members.find((m) => m.playerId === state.playerId);
    if (me) {
        state.assignedRole = me.role;
        state.score = me.score;
        state.attackCredits = me.attackCredits ?? 200;
    } else {
        state.assignedRole = room.inspectorId === state.playerId ? 'inspector' : 'sender';
    }
    state.integrity = room.serverIntegrity;
    updateHud();
    syncArenaClock(room);

    const banner = document.getElementById('arenaRoleBanner');
    if (banner) {
        banner.className = `role-reveal-banner ${state.assignedRole === 'inspector' ? 'is-inspector' : 'is-sender'}`;
        banner.textContent = state.assignedRole === 'inspector'
            ? `🛡️ CASERO (${room.name}): Aguanta 2:00 min con vida y responde cada archivo en <= ${room.slaSeconds || 15}s (si no respondes pierdes -15/-20 HP).`
            : `📤 ATACANTE (${room.name}): Tienes ${state.attackCredits} PTS de ataque. Gasta con estrategia contra ${room.inspectorName || 'el casero'}.`;
    }

    const resultBanner = document.getElementById('arenaRoundResultBanner');
    if (resultBanner) {
        if (room.roundResult) {
            resultBanner.hidden = false;
            resultBanner.className = `round-result-banner ${room.roundResult.winner === 'inspector' ? 'is-inspector-win' : 'is-attackers-win'}`;
            resultBanner.textContent = `${room.roundResult.reason} — El presentador iniciará la siguiente ronda desde el proyector.`;
        } else {
            resultBanner.hidden = true;
        }
    }

    document.getElementById('arenaRoomBadge').textContent = `${room.name.toUpperCase()} • RONDA ${room.roundNumber}`;
    document.getElementById('arenaIntegrityText').textContent = `${room.serverIntegrity} HP`;
    document.getElementById('arenaIntegrityMeter')?.style.setProperty('--integrity-pct', `${room.serverIntegrity}%`);
    document.getElementById('arenaMemberCount').textContent = `${members.length} (1 vs ${room.attackerCount})`;

    const membersEl = document.getElementById('arenaMembersList');
    membersEl.innerHTML = members.map((m) => {
        const isInsp = m.playerId === room.inspectorId;
        const isMe = m.playerId === state.playerId;
        const statusTag = isInsp
            ? `❤️ ${room.serverIntegrity} HP`
            : `⚡ ${m.attackCredits ?? 0} PTS`;
        return `
            <li class="member-item ${isInsp ? 'is-inspector' : ''} ${isMe ? 'is-me' : ''}">
                <div>
                    <strong>${escapeHtml(m.name)}${isMe ? ' (Tú)' : ''}</strong>
                    <div class="member-role-tag">${isInsp ? '🛡️ CASERO' : '📤 ATACANTE'}</div>
                </div>
                <span><strong>${statusTag}</strong></span>
            </li>
        `;
    }).join('');

    const historyEl = document.getElementById('arenaHistoryList');
    if (!history.length) {
        historyEl.innerHTML = '<li class="history-item">Sin archivos sellados aún en esta ronda.</li>';
    } else {
        historyEl.innerHTML = history.slice(0, 10).map((h) => {
            const isBreach = h.outcome === 'breach'
                || h.outcome === 'false_positive'
                || h.outcome === 'partial_block'
                || h.outcome === 'timeout_breach'
                || h.outcome === 'timeout_dos';
            return `
                <li class="history-item ${isBreach ? 'is-breach' : 'is-safe'}">
                    <strong>${escapeHtml(h.filename)}</strong> (${escapeHtml(h.senderName)})<br>
                    <span>${escapeHtml(h.verdictHeadline)}</span>
                </li>
            `;
        }).join('');
    }

    if (history.length > 0 && history[0].inspectorAction === 'timeout' && state.lastResolvedId !== history[0].packetId) {
        state.lastResolvedId = history[0].packetId;
        if (state.assignedRole === 'inspector') {
            renderBoothInspectFeedback(history[0], true);
        }
    }

    const roundFinished = Boolean(room.roundResult);
    document.getElementById('btnBoothAllow').disabled = roundFinished;
    document.getElementById('btnBoothOpenBlock').disabled = roundFinished;

    const inspPanel = document.getElementById('arenaInspectorPanel');
    const sendPanel = document.getElementById('arenaSenderPanel');

    if (state.assignedRole === 'inspector') {
        inspPanel.hidden = false;
        sendPanel.hidden = true;
        renderInspectorQueue(queue, room);
    } else {
        inspPanel.hidden = true;
        sendPanel.hidden = false;
        stopBoothSlaTimer();
        const slaWrap = document.getElementById('boothSlaWrap');
        if (slaWrap) slaWrap.hidden = true;
        const pendingCount = queue.filter((q) => q.status === 'pending').length;
        document.getElementById('senderQueueChip').textContent = `En cola: ${pendingCount}`;
        document.getElementById('senderCreditsChip').textContent = `⚡ ${state.attackCredits} PTS de ataque`;
        updateCraftCostButton();
    }
}

function updateBoothSlaUI() {
    const wrap = document.getElementById('boothSlaWrap');
    const textEl = document.getElementById('boothSlaText');
    const fillEl = document.getElementById('boothSlaFill');
    if (!wrap || !boothSlaDeadlineAt) return;

    const remMs = Math.max(0, boothSlaDeadlineAt - Date.now());
    const remSec = Math.ceil(remMs / 1000);
    const pct = Math.min(100, Math.max(0, (remMs / boothSlaTotalMs) * 100));
    const urgent = remSec <= 5;

    if (textEl) textEl.textContent = `${remSec}s`;
    if (fillEl) {
        fillEl.style.setProperty('--timer-pct', `${pct}%`);
        fillEl.classList.toggle('is-urgent', urgent);
    }
    wrap.classList.toggle('is-urgent', urgent);

    if (remMs <= 0 && !boothSlaRefreshRequested) {
        boothSlaRefreshRequested = true;
        fetchMatchStatus();
    }
}

function startBoothSlaTimer() {
    if (boothSlaInterval) clearInterval(boothSlaInterval);
    boothSlaRefreshRequested = false;
    updateBoothSlaUI();
    boothSlaInterval = setInterval(updateBoothSlaUI, 250);
}

function renderInspectorQueue(queue, room) {
    const pending = queue.filter((q) => q.status === 'pending');
    document.getElementById('arenaQueueCount').textContent = String(pending.length);

    const emptyBox = document.getElementById('arenaQueueEmpty');
    const dossierBox = document.getElementById('arenaCurrentDossier');
    const slaWrap = document.getElementById('boothSlaWrap');

    if (!pending.length || room?.roundResult) {
        emptyBox.hidden = false;
        dossierBox.hidden = true;
        if (slaWrap) slaWrap.hidden = true;
        stopBoothSlaTimer();
        state.currentBoothPacketId = null;
        return;
    }

    emptyBox.hidden = true;
    dossierBox.hidden = false;

    const pkt = pending[0];
    boothSlaTotalMs = ((room && room.slaSeconds) || 15) * 1000;
    const remMs = Number.isFinite(room?.activePacketSlaRemainingMs)
        ? room.activePacketSlaRemainingMs
        : (pkt.slaDeadlineAt ? Math.max(0, pkt.slaDeadlineAt - Date.now()) : boothSlaTotalMs);
    boothSlaDeadlineAt = Date.now() + Math.max(0, remMs);
    if (slaWrap) slaWrap.hidden = false;
    startBoothSlaTimer();

    if (state.currentBoothPacketId === pkt.packetId) {
        return;
    }

    state.currentBoothPacketId = pkt.packetId;
    document.getElementById('boothSenderName').textContent = pkt.senderName;
    document.getElementById('boothPacketId').textContent = `PKT-${pkt.packetId}`;
    document.getElementById('boothFilename').textContent = pkt.filename;
    document.getElementById('boothExt').textContent = pkt.ext;
    document.getElementById('boothMime').textContent = pkt.clientMime;
    document.getElementById('boothMetaNote').textContent = pkt.note ? `${pkt.size} • "${pkt.note}"` : pkt.size;
    document.getElementById('boothHexDump').textContent = `HEX:   ${pkt.hex}\nASCII: ${pkt.ascii}`;

    document.getElementById('boothDecisionRow').hidden = false;
    document.getElementById('boothVectorPanel').hidden = true;
}

function renderBoothInspectFeedback(rec, playSfx = true) {
    const ok = rec.outcome === 'correct_allow' || rec.outcome === 'correct_block';
    if (playSfx) playSound(ok ? 'success' : 'error');

    const fb = document.getElementById('arenaInspectFeedback');
    if (!fb) return;
    fb.className = `feedback-banner ${ok ? 'is-success' : 'is-error'}`;
    const hpLabel = rec.hpLoss > 0 ? `Casero: -${rec.hpLoss} HP` : 'Casero: 0 HP perdido';
    const atkLabel = rec.senderCreditGain > 0 ? `+${rec.senderCreditGain} PTS ataque` : 'Sin recarga';
    fb.innerHTML = `
        <div class="feedback-title-row">
            <span>${escapeHtml(rec.verdictHeadline)}</span>
            <span>${hpLabel} | ${escapeHtml(rec.senderName)}: ${atkLabel}</span>
        </div>
        <p>${escapeHtml(rec.explanation)}</p>
    `;
    fb.hidden = false;
}

async function inspectCurrentPacket(action, vector) {
    if (!state.currentBoothPacketId) return;
    try {
        const res = await fetch(`/api/game/rooms/${encodeURIComponent(state.selectedRoomId)}/inspect`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                inspectorId: state.playerId,
                packetId: state.currentBoothPacketId,
                action,
                vector
            })
        });
        const data = await res.json();
        if (!res.ok || !data.success) {
            state.currentBoothPacketId = null;
            fetchMatchStatus();
            return;
        }

        state.lastResolvedId = data.record.packetId;
        renderBoothInspectFeedback(data.record, true);

        state.currentBoothPacketId = null;
        renderRoomPayload(data);
    } catch {
        // Silencioso
    }
}

function computeClientCraftCost() {
    const filename = (document.getElementById('craftFilename')?.value || '').trim();
    const mime = (document.getElementById('craftMime')?.value || '').trim().toLowerCase();
    const payloadType = document.getElementById('craftPayloadType')?.value || 'png_real';

    if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) return 80;

    const ext = filename.includes('.') ? filename.split('.').pop().toLowerCase() : '';
    const normExt = ext === 'jpeg' ? 'jpg' : ext;
    const safeExts = ['png', 'jpg', 'gif'];

    if (payloadType === 'php_rce' || payloadType === 'html_xss' || payloadType === 'svg_xss') {
        return safeExts.includes(normExt) ? 80 : 60;
    }

    if (['php', 'phtml', 'php5', 'sh', 'js', 'exe', 'jsp', 'html', 'htm', 'svg'].includes(ext)) {
        return 60;
    }

    const expectedMimes = {
        png_real: ['image/png'],
        jpg_real: ['image/jpeg', 'image/jpg'],
        gif_real: ['image/gif']
    };
    const expectedFmt = payloadType.split('_')[0];
    if (normExt === expectedFmt && (expectedMimes[payloadType] || []).includes(mime)) {
        return 50;
    }
    return 80;
}

function updateCraftCostButton() {
    const sendBtn = document.getElementById('btnSendPacket');
    if (!sendBtn) return;

    if (state.roundResult) {
        sendBtn.disabled = true;
        sendBtn.innerHTML = '<i class="fa-solid fa-flag-checkered" aria-hidden="true"></i> Ronda finalizada';
        return;
    }

    const cost = computeClientCraftCost();
    if (state.attackCredits < cost) {
        sendBtn.disabled = true;
        sendBtn.innerHTML = `<i class="fa-solid fa-ban" aria-hidden="true"></i> Sin puntos (${state.attackCredits}/${cost} PTS)`;
    } else {
        sendBtn.disabled = false;
        sendBtn.innerHTML = `<i class="fa-solid fa-paper-plane" aria-hidden="true"></i> Enviar Archivo (-${cost} PTS)`;
    }
}

function applyCraftPreset(presetKey) {
    const preset = SENDER_PRESETS[presetKey];
    if (!preset) return;
    document.getElementById('craftFilename').value = preset.filename;
    document.getElementById('craftMime').value = preset.mime;
    document.getElementById('craftPayloadType').value = preset.payloadType;
    document.getElementById('craftNote').value = preset.note;
    updateCraftCostButton();
}

async function handleSenderSubmit(event) {
    event.preventDefault();
    const statusEl = document.getElementById('senderStatusMsg');
    const sendBtn = document.getElementById('btnSendPacket');
    sendBtn.disabled = true;

    try {
        const res = await fetch(`/api/game/rooms/${encodeURIComponent(state.selectedRoomId)}/submit-file`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                playerId: state.playerId,
                name: state.playerName,
                filename: document.getElementById('craftFilename').value,
                clientMime: document.getElementById('craftMime').value,
                payloadType: document.getElementById('craftPayloadType').value,
                note: document.getElementById('craftNote').value
            })
        });
        const data = await res.json();
        if (res.ok && data.success) {
            playSound('success');
            statusEl.textContent = `📤 "${data.packet.filename}" enviado (-${data.packet.cost} PTS).`;
            renderRoomPayload(data);
        } else {
            playSound('error');
            statusEl.textContent = data.error || 'No se pudo enviar el archivo.';
        }
    } catch {
        statusEl.textContent = 'Error de conexión al enviar el archivo.';
    } finally {
        updateCraftCostButton();
    }
}

// --------------------------------------------------------------------------
// 8. MODO SOLITARIO (3 FASES)
// --------------------------------------------------------------------------
function awardSoloPoints(basePoints) {
    state.streak += 1;
    if (state.streak > state.maxStreak) state.maxStreak = state.streak;
    const total = basePoints + (state.streak - 1) * 25;
    state.score += total;
    state.correctCount += 1;
    state.totalAnswered += 1;
    return total;
}

function penalizeSoloMistake(loss) {
    state.streak = 0;
    state.integrity = Math.max(0, state.integrity - loss);
    state.totalAnswered += 1;
}

function loadPhase1Dossier() {
    document.getElementById('phase1Container').hidden = false;
    document.getElementById('phase2Container').hidden = true;
    document.getElementById('phase3Container').hidden = true;

    const item = PHASE_1_DOSSIERS[state.index];
    state.answeredCurrent = false;

    document.getElementById('phase1Counter').textContent = `Expediente ${state.index + 1} / ${PHASE_1_DOSSIERS.length}`;
    document.getElementById('dossierContext').textContent = item.context;
    document.getElementById('dossierId').textContent = item.id;
    document.getElementById('dossierFilename').textContent = item.filename;
    document.getElementById('dossierExt').textContent = item.ext;
    document.getElementById('dossierMime').textContent = item.mime;
    document.getElementById('dossierSize').textContent = item.size;
    document.getElementById('dossierHexDump').textContent = item.hexDump;

    document.getElementById('phase1DecisionControls').hidden = false;
    document.getElementById('vectorSelector').hidden = true;
    document.getElementById('phase1Feedback').hidden = true;
}

function submitPhase1Allow() {
    if (state.answeredCurrent) return;
    state.answeredCurrent = true;
    const item = PHASE_1_DOSSIERS[state.index];
    const ok = item.expectedAction === 'allow';
    evaluatePhase1(ok, item, ok ? 'Aprobado correctamente' : '¡BRECHA! Permitiste pasar un archivo peligroso.');
}

function submitPhase1Block(chosenVector) {
    if (state.answeredCurrent) return;
    state.answeredCurrent = true;
    const item = PHASE_1_DOSSIERS[state.index];
    let ok = false;
    let headline = '';

    if (item.expectedAction === 'allow') {
        headline = '¡Falso positivo! Bloqueaste una imagen legítima.';
    } else if (item.expectedVector === chosenVector) {
        ok = true;
        headline = '¡Amenaza neutralizada con el vector exacto!';
    } else {
        headline = `Vector distinto al real (${item.expectedVector}).`;
    }
    evaluatePhase1(ok, item, headline);
}

function evaluatePhase1(isCorrect, item, headline) {
    document.getElementById('phase1DecisionControls').hidden = true;
    document.getElementById('vectorSelector').hidden = true;

    const earned = isCorrect ? awardSoloPoints(150) : 0;
    if (!isCorrect) penalizeSoloMistake(item.expectedAction === 'block' ? 20 : 10);
    playSound(isCorrect ? 'success' : 'error');

    state.history.push({ phaseLabel: 'Fase 1', itemTitle: item.filename, isCorrect, detail: item.explanation });
    updateHud();
    syncSoloScoreToServer();

    const fb = document.getElementById('phase1Feedback');
    const isLast = state.index === PHASE_1_DOSSIERS.length - 1;
    fb.className = `feedback-banner ${isCorrect ? 'is-success' : 'is-error'}`;
    fb.innerHTML = `
        <div class="feedback-title-row">
            <span>${isCorrect ? '🛡️' : '🚨'} ${escapeHtml(headline)}</span>
            <span>${isCorrect ? `+${earned} PTS` : '0 PTS'}</span>
        </div>
        <p>${escapeHtml(item.explanation)}</p>
        <button type="button" class="feedback-next-btn" id="btnNextSolo1">
            ${isLast ? 'Ir a Fase 2: Parcheo server.js' : 'Siguiente Expediente'}
        </button>
    `;
    fb.hidden = false;

    document.getElementById('btnNextSolo1')?.addEventListener('click', () => {
        if (state.index < PHASE_1_DOSSIERS.length - 1) {
            state.index += 1;
            loadPhase1Dossier();
        } else {
            if (state.history.slice(0, PHASE_1_DOSSIERS.length).every((h) => h.isCorrect)) {
                state.badges.push('🔍 Ojo de Halcón (Magic Bytes)');
            }
            state.phase = 2;
            state.index = 0;
            updateHud();
            loadPhase2Challenge();
        }
    });
}

function loadPhase2Challenge() {
    document.getElementById('phase1Container').hidden = true;
    document.getElementById('phase2Container').hidden = false;
    document.getElementById('phase3Container').hidden = true;

    const ch = PHASE_2_CHALLENGES[state.index];
    state.answeredCurrent = false;

    document.getElementById('phase2Counter').textContent = `Reto ${state.index + 1} / ${PHASE_2_CHALLENGES.length}`;
    document.getElementById('p2RoleBadge').textContent = ch.role;
    document.getElementById('p2Title').textContent = ch.title;
    document.getElementById('p2Prompt').textContent = ch.prompt;

    const codeWrap = document.getElementById('p2ContextCodeWrap');
    if (ch.contextCode) {
        codeWrap.hidden = false;
        document.getElementById('p2ContextCode').textContent = ch.contextCode;
    } else {
        codeWrap.hidden = true;
    }

    const grid = document.getElementById('p2OptionsGrid');
    grid.innerHTML = '';
    ch.options.forEach((opt, idx) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'code-option-btn';
        btn.innerHTML = `<strong>${escapeHtml(opt.label)}</strong><pre>${escapeHtml(opt.code)}</pre>`;
        btn.addEventListener('click', () => submitPhase2Option(idx));
        grid.appendChild(btn);
    });

    document.getElementById('phase2Feedback').hidden = true;
}

function submitPhase2Option(chosenIdx) {
    if (state.answeredCurrent) return;
    state.answeredCurrent = true;

    const ch = PHASE_2_CHALLENGES[state.index];
    const buttons = document.querySelectorAll('#p2OptionsGrid .code-option-btn');
    const isCorrect = ch.options[chosenIdx].isCorrect;

    buttons.forEach((btn, idx) => {
        btn.disabled = true;
        if (ch.options[idx].isCorrect) btn.classList.add('is-correct');
        else if (idx === chosenIdx && !isCorrect) btn.classList.add('is-wrong');
    });

    const earned = isCorrect ? awardSoloPoints(200) : 0;
    if (!isCorrect) penalizeSoloMistake(15);
    playSound(isCorrect ? 'success' : 'error');

    state.history.push({ phaseLabel: 'Fase 2', itemTitle: ch.title, isCorrect, detail: ch.explanation });
    updateHud();
    syncSoloScoreToServer();

    const fb = document.getElementById('phase2Feedback');
    const isLast = state.index === PHASE_2_CHALLENGES.length - 1;
    fb.className = `feedback-banner ${isCorrect ? 'is-success' : 'is-error'}`;
    fb.innerHTML = `
        <div class="feedback-title-row">
            <span>${isCorrect ? '🛠️ ¡Parche correcto!' : '⚠️ Código vulnerable'}</span>
            <span>${isCorrect ? `+${earned} PTS` : '0 PTS'}</span>
        </div>
        <p>${escapeHtml(ch.explanation)}</p>
        <button type="button" class="feedback-next-btn" id="btnNextSolo2">
            ${isLast ? 'Ir a Fase 3: Ráfaga OWASP' : 'Siguiente Reto'}
        </button>
    `;
    fb.hidden = false;

    document.getElementById('btnNextSolo2')?.addEventListener('click', () => {
        if (state.index < PHASE_2_CHALLENGES.length - 1) {
            state.index += 1;
            loadPhase2Challenge();
        } else {
            state.phase = 3;
            state.index = 0;
            updateHud();
            loadPhase3Question();
        }
    });
}

function loadPhase3Question() {
    document.getElementById('phase1Container').hidden = true;
    document.getElementById('phase2Container').hidden = true;
    document.getElementById('phase3Container').hidden = false;

    const q = PHASE_3_QUIZ[state.index];
    state.answeredCurrent = false;

    document.getElementById('phase3Counter').textContent = `Pregunta ${state.index + 1} / ${PHASE_3_QUIZ.length}`;
    document.getElementById('p3Question').textContent = q.question;
    document.getElementById('phase3Feedback').hidden = true;

    const letters = ['A', 'B', 'C', 'D'];
    const grid = document.getElementById('p3OptionsGrid');
    grid.innerHTML = '';
    q.options.forEach((opt, idx) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'quiz-option-btn';
        btn.innerHTML = `<span class="quiz-opt-letter">${letters[idx]}</span><span>${escapeHtml(opt)}</span>`;
        btn.addEventListener('click', () => submitPhase3Answer(idx));
        grid.appendChild(btn);
    });

    startQuizTimer();
}

function startQuizTimer() {
    stopQuizTimer();
    quizTimeLeft = 20;
    updateQuizTimerUI();

    quizTimerInterval = setInterval(() => {
        quizTimeLeft -= 1;
        updateQuizTimerUI();
        if (quizTimeLeft <= 0) {
            stopQuizTimer();
            submitPhase3Answer(-1);
        }
    }, 1000);
}

function stopQuizTimer() {
    if (quizTimerInterval) {
        clearInterval(quizTimerInterval);
        quizTimerInterval = null;
    }
}

function updateQuizTimerUI() {
    const bar = document.getElementById('p3TimerBar');
    const txt = document.getElementById('p3TimerText');
    const pct = Math.max(0, (quizTimeLeft / 20) * 100);
    if (bar) {
        bar.style.setProperty('--timer-pct', `${pct}%`);
        bar.classList.toggle('is-urgent', quizTimeLeft <= 6);
    }
    if (txt) txt.textContent = `${quizTimeLeft}s`;
}

function submitPhase3Answer(chosenIdx) {
    if (state.answeredCurrent) return;
    state.answeredCurrent = true;
    stopQuizTimer();

    const q = PHASE_3_QUIZ[state.index];
    const buttons = document.querySelectorAll('#p3OptionsGrid .quiz-option-btn');
    const isCorrect = chosenIdx === q.correctIdx;

    buttons.forEach((btn, idx) => {
        btn.disabled = true;
        if (idx === q.correctIdx) btn.classList.add('is-correct');
        else if (idx === chosenIdx && !isCorrect) btn.classList.add('is-wrong');
    });

    const speedBonus = isCorrect ? quizTimeLeft * 5 : 0;
    const earned = isCorrect ? awardSoloPoints(150) + speedBonus : 0;
    if (isCorrect) state.score += speedBonus;
    else penalizeSoloMistake(10);

    playSound(isCorrect ? 'success' : 'error');
    state.history.push({ phaseLabel: 'Fase 3', itemTitle: q.question, isCorrect, detail: q.explanation });
    updateHud();
    syncSoloScoreToServer();

    const fb = document.getElementById('phase3Feedback');
    const isLast = state.index === PHASE_3_QUIZ.length - 1;
    const title = chosenIdx === -1 ? '⏱️ Tiempo agotado' : (isCorrect ? '⚡ ¡Correcto!' : '❌ Incorrecto');
    fb.className = `feedback-banner ${isCorrect ? 'is-success' : 'is-error'}`;
    fb.innerHTML = `
        <div class="feedback-title-row">
            <span>${title}</span>
            <span>${isCorrect ? `+${earned} PTS` : '0 PTS'}</span>
        </div>
        <p>${escapeHtml(q.explanation)}</p>
        <button type="button" class="feedback-next-btn" id="btnNextSolo3">
            ${isLast ? 'Ver Resultados Finales' : 'Siguiente Pregunta'}
        </button>
    `;
    fb.hidden = false;

    document.getElementById('btnNextSolo3')?.addEventListener('click', () => {
        if (state.index < PHASE_3_QUIZ.length - 1) {
            state.index += 1;
            loadPhase3Question();
        } else {
            finishSoloGame();
        }
    });
}

async function finishSoloGame() {
    stopQuizTimer();
    state.completed = true;
    const accuracy = state.totalAnswered > 0 ? Math.round((state.correctCount / state.totalAnswered) * 100) : 0;

    if (state.integrity === 100) state.badges.push('🛡️ Servidor Intacto (100%)');
    if (state.maxStreak >= 5) state.badges.push('🔥 Racha 5+');
    if (accuracy >= 90) state.badges.push('🏆 Maestro CWE-434');
    if (!state.badges.length) state.badges.push('🎓 Aprendiz AppSec');

    let rankTitle = '💻 Desarrollador Junior AppSec';
    let icon = '💻';
    if (state.score >= 2800 && accuracy >= 85) {
        rankTitle = '👑 CISO / Arquitecto AppSec';
        icon = '👑';
    } else if (state.score >= 1900) {
        rankTitle = '🛡️ Analista SOC Nivel 2';
        icon = '🛡️';
    } else if (state.score >= 1100) {
        rankTitle = '⚔️ Defensor Blue Team';
        icon = '⚔️';
    }

    document.getElementById('certIcon').textContent = icon;
    document.getElementById('certRankTitle').textContent = rankTitle;
    document.getElementById('certPlayerLabel').textContent = state.playerName;
    document.getElementById('resScore').textContent = String(state.score);
    document.getElementById('resAccuracy').textContent = `${accuracy}%`;
    document.getElementById('resIntegrity').textContent = `${state.integrity}%`;

    document.getElementById('resBadgesList').innerHTML = state.badges
        .map((b) => `<li class="badge-chip">${escapeHtml(b)}</li>`)
        .join('');

    document.getElementById('reviewList').innerHTML = state.history
        .map((h) => `
            <li class="review-item ${h.isCorrect ? '' : 'is-wrong'}">
                <strong>${h.isCorrect ? '✅' : '❌'} [${escapeHtml(h.phaseLabel)}] ${escapeHtml(h.itemTitle)}</strong><br>
                <span>${escapeHtml(h.detail)}</span>
            </li>
        `).join('');

    playSound('victory');
    navigateScreen('screenResults');

    const syncRes = await syncSoloScoreToServer();
    if (syncRes?.rank) document.getElementById('resRank').textContent = `#${syncRes.rank}`;
    if (Array.isArray(syncRes?.players)) renderLeaderboardList('resultsLeaderboardContainer', syncRes.players);
}

// --------------------------------------------------------------------------
// 9. LEADERBOARD & MODO PROYECTOR
// --------------------------------------------------------------------------
async function syncSoloScoreToServer() {
    if (!state.playerId) return null;
    const accuracy = state.totalAnswered > 0 ? Math.round((state.correctCount / state.totalAnswered) * 100) : 0;
    try {
        const res = await fetch('/api/game/score', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                playerId: state.playerId,
                name: state.playerName,
                score: state.score,
                phaseReached: state.phase,
                accuracy,
                badges: state.badges,
                completed: state.completed
            })
        });
        if (!res.ok) return null;
        return await res.json();
    } catch {
        return null;
    }
}

async function fetchLeaderboardAndRooms() {
    try {
        const [lbRes, matchRes] = await Promise.all([
            fetch('/api/game/leaderboard'),
            fetch('/api/game/match/status')
        ]);

        if (lbRes.ok) {
            const lbData = await lbRes.json();
            const players = lbData.players || [];
            renderLeaderboardList('resultsLeaderboardContainer', players);
            renderProjectorBoard(players, lbData.updatedAt);
        }

        if (matchRes.ok) {
            const matchData = await matchRes.json();
            renderProjectorMatchStatus(matchData);
        }
    } catch {
        // Silencioso durante polling
    }
}

// --------------------------------------------------------------------------
// 10. REPRODUCTOR DE VIDEO TUTORIAL CON VOZ NEURAL EN PROYECTOR (6 ESCENAS)
// --------------------------------------------------------------------------
const TUTORIAL_SCENES = [
    {
        start: 0,
        end: 16.12,
        audioSrc: '/audio/tut-scene-0.mp3',
        pill: 'ESCENA 1 DE 6 • DINÁMICA DEL JUEGO',
        title: 'Casero de Supervivencia vs. Atacantes con Puntos',
        subtitle: 'Bienvenidos a la Caseta Forense de e-Libre. En cada grupo, 1 estudiante al azar defiende la caseta con 100 HP por 2 minutos (sin sumar puntos), mientras los atacantes gastan puntos en cada envío para evitar spam.'
    },
    {
        start: 16.12,
        end: 39.59,
        audioSrc: '/audio/tut-scene-1.mp3',
        pill: 'ESCENA 2 DE 6 • REPASO DE ATAQUES (1/2)',
        title: 'RCE / Doble Extensión y Magic Bytes Spoofing',
        subtitle: 'Repaso 1: RCE (.php o .png.php) intenta ejecutar código en el servidor. Spoofing disfraza scripts como imágenes; el Casero los rechaza cuando el Buffer Hex no coincide con PNG, JPEG ni GIF.'
    },
    {
        start: 39.59,
        end: 61.62,
        audioSrc: '/audio/tut-scene-2.mp3',
        pill: 'ESCENA 3 DE 6 • REPASO DE ATAQUES (2/2)',
        title: 'Stored XSS y Path Traversal',
        subtitle: 'Repaso 2: Stored XSS (.html o .svg con scripts) roba sesiones en el navegador. Path Traversal usa ../ para escapar de uploads/ y sobrescribir archivos del sistema, incluso con un PNG real.'
    },
    {
        start: 61.62,
        end: 85.74,
        audioSrc: '/audio/tut-scene-3.mp3',
        pill: 'ESCENA 4 DE 6 • ECONOMÍA ANTI-SPAM',
        title: 'Cómo gastan y recuperan puntos los Atacantes',
        subtitle: 'Enviar una foto real cuesta 50 PTS y un exploit 60 u 80 PTS. Si cuelas un ataque: -25 HP al Casero y +150 PTS para ti. Un falso positivo quita -15 HP al Casero y te da +110 PTS.'
    },
    {
        start: 85.74,
        end: 108.15,
        audioSrc: '/audio/tut-scene-4.mp3',
        pill: 'ESCENA 5 DE 6 • INSPECCIÓN EN CASETA',
        title: 'Revisa el Buffer Hex y clasifica el vector exacto',
        subtitle: 'No confíes en el nombre ni en el Content-Type: verifica siempre los Magic Bytes reales. Si bloqueas con el vector incorrecto pierdes -10 HP y el atacante recupera +70 PTS.'
    },
    {
        start: 108.15,
        end: 125.62,
        audioSrc: '/audio/tut-scene-5.mp3',
        pill: 'ESCENA 6 DE 6 • VICTORIA Y ARRANQUE',
        title: '¿Cómo gana cada bando? ¡Miren sus celulares!',
        subtitle: 'El Casero gana si resiste 2 minutos o deja a todos con menos de 50 PTS. Los atacantes ganan al bajar la caseta a 0 HP. Recuerden usar el Manual Forense. ¡Comienza la ronda!'
    }
];

const tutorialState = {
    isOpen: false,
    isPlaying: false,
    elapsed: 0,
    totalDuration: 125.62,
    sceneIdx: 0,
    voiceEnabled: true,
    timerId: null,
    advanceTimeoutId: null,
    lastSpokenScene: -1,
    matchStatus: 'waiting'
};

let tutorialAudio = null;
let tutorialAudioSceneIdx = -1;

function clearTutorialAdvanceTimeout() {
    if (tutorialState.advanceTimeoutId) {
        clearTimeout(tutorialState.advanceTimeoutId);
        tutorialState.advanceTimeoutId = null;
    }
}

function resetTutorialAudio() {
    clearTutorialAdvanceTimeout();
    if (tutorialAudio) {
        try {
            tutorialAudio.onended = null;
            tutorialAudio.onerror = null;
            tutorialAudio.pause();
            tutorialAudio.currentTime = 0;
        } catch {
            // Ignorar error de limpieza de audio
        }
    }
    tutorialAudioSceneIdx = -1;
    stopTutorialSpeech();
}

function finishTutorialSequence() {
    pauseTutorial();
    tutorialState.elapsed = tutorialState.totalDuration;
    renderTutorialFrame();
    const autoCheck = document.getElementById('chkTutAutoLaunch');
    if (autoCheck?.checked && tutorialState.matchStatus === 'briefing') {
        launchMatchFromBriefing();
    }
}

function openTutorialPlayer(autoPlay = true) {
    const stage = document.getElementById('projectorTutorialStage');
    if (!stage) return;
    resetTutorialAudio();
    stage.hidden = false;
    tutorialState.isOpen = true;
    tutorialState.elapsed = 0;
    tutorialState.sceneIdx = 0;
    tutorialState.lastSpokenScene = -1;
    renderTutorialFrame();
    if (autoPlay) {
        playTutorial();
    }
}

function closeTutorialPlayer() {
    pauseTutorial();
    resetTutorialAudio();
    tutorialState.isOpen = false;
    const stage = document.getElementById('projectorTutorialStage');
    if (stage) stage.hidden = true;
}

function playTutorial() {
    if (tutorialState.elapsed >= tutorialState.totalDuration) {
        resetTutorialAudio();
        tutorialState.elapsed = 0;
        tutorialState.sceneIdx = 0;
        tutorialState.lastSpokenScene = -1;
    }
    if (tutorialState.timerId) clearInterval(tutorialState.timerId);
    tutorialState.isPlaying = true;
    updateTutorialControlsUI();
    renderTutorialFrame();

    const activeScene = TUTORIAL_SCENES[tutorialState.sceneIdx];
    if (tutorialState.voiceEnabled && activeScene && tutorialAudio && tutorialAudio.paused && tutorialAudioSceneIdx === tutorialState.sceneIdx) {
        tutorialAudio.play().catch(() => {});
    }

    tutorialState.timerId = setInterval(() => {
        if (!tutorialState.isPlaying) return;
        const idx = tutorialState.sceneIdx;
        const scene = TUTORIAL_SCENES[idx];
        const audioPlaying = Boolean(
            tutorialState.voiceEnabled
            && tutorialAudio
            && !tutorialAudio.paused
            && !tutorialAudio.ended
            && tutorialAudioSceneIdx === idx
        );

        if (audioPlaying && scene) {
            tutorialState.elapsed = Math.min(scene.end - 0.05, scene.start + (tutorialAudio.currentTime || 0));
            renderTutorialFrame();
            return;
        }

        tutorialState.elapsed = Math.min(tutorialState.totalDuration, tutorialState.elapsed + 0.25);
        renderTutorialFrame();

        if (tutorialState.elapsed >= tutorialState.totalDuration) {
            finishTutorialSequence();
        }
    }, 250);
}

function pauseTutorial() {
    tutorialState.isPlaying = false;
    clearTutorialAdvanceTimeout();
    if (tutorialState.timerId) {
        clearInterval(tutorialState.timerId);
        tutorialState.timerId = null;
    }
    if (tutorialAudio) {
        try {
            tutorialAudio.pause();
        } catch {
            // Ignorar si aún no estaba cargado
        }
    }
    stopTutorialSpeech();
    updateTutorialControlsUI();
}

function toggleTutorialPlayPause() {
    if (tutorialState.isPlaying) pauseTutorial();
    else playTutorial();
}

function restartTutorial() {
    resetTutorialAudio();
    tutorialState.elapsed = 0;
    tutorialState.sceneIdx = 0;
    tutorialState.lastSpokenScene = -1;
    playTutorial();
}

function jumpToTutorialScene(idx) {
    const target = TUTORIAL_SCENES[idx];
    if (!target) return;
    resetTutorialAudio();
    tutorialState.elapsed = target.start;
    tutorialState.sceneIdx = idx;
    tutorialState.lastSpokenScene = -1;
    renderTutorialFrame();
}

function toggleTutorialVoice() {
    tutorialState.voiceEnabled = !tutorialState.voiceEnabled;
    if (!tutorialState.voiceEnabled) {
        clearTutorialAdvanceTimeout();
        if (tutorialAudio) {
            try {
                tutorialAudio.pause();
            } catch {
                // Ignorar
            }
        }
        stopTutorialSpeech();
    } else if (tutorialState.isPlaying) {
        const idx = tutorialState.sceneIdx;
        const scene = TUTORIAL_SCENES[idx];
        if (scene) {
            const offset = Math.max(0, tutorialState.elapsed - scene.start);
            playSceneAudio(idx, offset, true);
        }
    }
    updateTutorialControlsUI();
}

function stopTutorialSpeech() {
    try {
        if ('speechSynthesis' in window) {
            window.speechSynthesis.cancel();
        }
    } catch {
        // Ignorar si speechSynthesis no está disponible
    }
}

function speakTutorialFallback(text) {
    if (!tutorialState.voiceEnabled || !tutorialState.isPlaying) return;
    try {
        if (!('speechSynthesis' in window)) return;
        window.speechSynthesis.cancel();
        const utter = new SpeechSynthesisUtterance(text);
        utter.lang = 'es-ES';
        utter.rate = 1.05;
        const voices = window.speechSynthesis.getVoices();
        const esVoice = voices.find((v) => v.lang && v.lang.toLowerCase().startsWith('es'));
        if (esVoice) utter.voice = esVoice;
        window.speechSynthesis.speak(utter);
    } catch {
        // Silencioso si el navegador restringe voz sintética
    }
}

function playSceneAudio(sceneIdx, startOffsetSec = 0, forceReload = false) {
    if (!tutorialState.voiceEnabled || !tutorialState.isPlaying) return;
    const scene = TUTORIAL_SCENES[sceneIdx];
    if (!scene || !scene.audioSrc) return;

    stopTutorialSpeech();
    clearTutorialAdvanceTimeout();

    if (!tutorialAudio) {
        tutorialAudio = new Audio();
        tutorialAudio.preload = 'auto';
    }

    if (!forceReload && tutorialAudioSceneIdx === sceneIdx && tutorialAudio.paused && tutorialAudio.src) {
        tutorialAudio.play().catch(() => {});
        return;
    }

    try {
        tutorialAudio.onended = null;
        tutorialAudio.onerror = null;
        tutorialAudio.pause();
    } catch {
        // Ignorar
    }

    tutorialAudioSceneIdx = sceneIdx;
    tutorialAudio.src = scene.audioSrc;

    const applySeek = () => {
        if (startOffsetSec > 0.25 && Number.isFinite(tutorialAudio.duration)) {
            tutorialAudio.currentTime = Math.min(startOffsetSec, Math.max(0, tutorialAudio.duration - 0.3));
        } else {
            tutorialAudio.currentTime = 0;
        }
    };

    if (tutorialAudio.readyState >= 1) {
        applySeek();
    } else {
        tutorialAudio.addEventListener('loadedmetadata', applySeek, { once: true });
    }

    tutorialAudio.onended = () => {
        if (!tutorialState.isPlaying || tutorialState.sceneIdx !== sceneIdx) return;
        if (sceneIdx < TUTORIAL_SCENES.length - 1) {
            tutorialState.advanceTimeoutId = setTimeout(() => {
                tutorialState.advanceTimeoutId = null;
                if (!tutorialState.isPlaying || tutorialState.sceneIdx !== sceneIdx) return;
                const nextIdx = sceneIdx + 1;
                tutorialState.elapsed = TUTORIAL_SCENES[nextIdx].start;
                tutorialState.lastSpokenScene = -1;
                renderTutorialFrame();
            }, 300);
        } else {
            finishTutorialSequence();
        }
    };

    tutorialAudio.onerror = () => {
        if (tutorialAudioSceneIdx !== sceneIdx) return;
        tutorialAudioSceneIdx = -1;
        speakTutorialFallback(scene.subtitle);
    };

    tutorialAudio.play().catch(() => {
        // Si el navegador bloqueó audio automático, el reloj avanza los subtítulos visualmente
    });
}

function updateTutorialControlsUI() {
    const playBtn = document.getElementById('btnTutPlayPause');
    const voiceBtn = document.getElementById('btnTutVoice');
    const viewport = document.getElementById('tutorialViewport');
    const launchBtn = document.getElementById('btnTutLaunchNow');

    if (playBtn) playBtn.textContent = tutorialState.isPlaying ? 'Pausar' : 'Reproducir';
    if (voiceBtn) voiceBtn.textContent = tutorialState.voiceEnabled ? 'Voz Neural: Activa' : 'Voz Neural: Silenciada';
    if (viewport) viewport.classList.toggle('is-paused', !tutorialState.isPlaying);
    if (launchBtn) {
        launchBtn.hidden = tutorialState.matchStatus !== 'briefing';
    }
}

function renderTutorialFrame() {
    const t = tutorialState.elapsed;
    let activeIdx = TUTORIAL_SCENES.findIndex((s) => t >= s.start && t < s.end);
    if (activeIdx === -1) activeIdx = TUTORIAL_SCENES.length - 1;

    const sceneChanged = activeIdx !== tutorialState.sceneIdx || tutorialState.lastSpokenScene === -1;
    tutorialState.sceneIdx = activeIdx;
    const scene = TUTORIAL_SCENES[activeIdx];

    document.getElementById('tutorialPhasePill').textContent = scene.pill;
    document.getElementById('tutorialStageTitle').textContent = scene.title;
    document.getElementById('tutorialSubtitle').textContent = scene.subtitle;

    document.getElementById('tutorialClock').textContent = `${formatClockMMSS(t)} / ${formatClockMMSS(tutorialState.totalDuration)}`;
    const pct = Math.min(100, (t / tutorialState.totalDuration) * 100);
    document.getElementById('tutTimelineBar')?.style.setProperty('--tut-progress', `${pct}%`);

    for (let i = 0; i < TUTORIAL_SCENES.length; i++) {
        const el = document.getElementById(`tutScene${i}`);
        if (el) {
            const show = i === activeIdx;
            el.hidden = !show;
            el.classList.toggle('is-entering', show && sceneChanged);
        }
    }

    document.querySelectorAll('.tut-chap-btn').forEach((btn) => {
        btn.classList.toggle('is-current', Number(btn.dataset.tutScene) === activeIdx);
    });

    updateTutorialControlsUI();

    if (tutorialState.isPlaying && tutorialState.lastSpokenScene !== activeIdx) {
        tutorialState.lastSpokenScene = activeIdx;
        const offset = Math.max(0, tutorialState.elapsed - scene.start);
        playSceneAudio(activeIdx, offset, true);
    }
}

function getNpcAvatarSvg(variant) {
    if (variant === 'casero') {
        return `<svg class="proj-npc-svg" viewBox="0 0 36 40" aria-hidden="true">
            <circle cx="18" cy="11" r="6" fill="#93c5fd"/>
            <path d="M8 34c0-7 4-11 10-11s10 4 10 11Z" fill="#1d4ed8"/>
            <path d="M18 22l7 3v5c0 4-3 6-7 8-4-2-7-4-7-8v-5Z" fill="#38bdf8" stroke="#e0f2fe" stroke-width="1.2"/>
        </svg>`;
    }
    if (variant === 'hacker') {
        return `<svg class="proj-npc-svg" viewBox="0 0 36 40" aria-hidden="true">
            <path d="M10 14c0-6 16-6 16 0v3H10Z" fill="#991b1b"/>
            <circle cx="18" cy="13" r="5" fill="#fecaca"/>
            <path d="M7 35c0-8 5-12 11-12s11 4 11 12Z" fill="#7f1d1d"/>
            <rect x="21" y="21" width="9" height="11" rx="1.5" fill="#dc2626" stroke="#fee2e2" stroke-width="1.2"/>
            <path d="M25.5 23v4M25.5 29v1" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/>
        </svg>`;
    }
    if (variant === 'safe') {
        return `<svg class="proj-npc-svg" viewBox="0 0 36 40" aria-hidden="true">
            <circle cx="18" cy="11" r="5.5" fill="#bbf7d0"/>
            <path d="M8 35c0-7.5 4.5-11.5 10-11.5s10 4 10 11.5Z" fill="#15803d"/>
            <rect x="21" y="21" width="9" height="11" rx="1.5" fill="#22c55e" stroke="#dcfce7" stroke-width="1.2"/>
            <path d="M23.5 26.5l1.5 1.5 3-3" fill="none" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/>
        </svg>`;
    }
    return `<svg class="proj-npc-svg" viewBox="0 0 36 40" aria-hidden="true">
        <circle cx="18" cy="11" r="5.5" fill="#cbd5e1"/>
        <path d="M8 35c0-7.5 4.5-11.5 10-11.5s10 4 10 11.5Z" fill="#334155"/>
        <rect x="21" y="21" width="9" height="11" rx="1.5" fill="#0ea5e9" stroke="#e0f2fe" stroke-width="1.2"/>
        <path d="M23 25h5M23 28h5" stroke="#fff" stroke-width="1.2" stroke-linecap="round"/>
    </svg>`;
}

function getVerdictStageVisuals(verdict) {
    if (!verdict) {
        return {
            gateClass: '',
            stampText: 'EN CASETA',
            actorClass: '',
            avatar: 'waiting',
            badge: '',
            hasActor: false
        };
    }

    const out = verdict.outcome;
    if (out === 'correct_allow') {
        return {
            gateClass: 'gate-open',
            stampText: '✅ PASA',
            actorClass: 'is-pass',
            avatar: 'safe',
            badge: '✅ Foto aprobada',
            hasActor: true
        };
    }
    if (out === 'breach') {
        return {
            gateClass: 'gate-open is-breach-gate',
            stampText: '💥 BRECHA',
            actorClass: 'is-breach',
            avatar: 'hacker',
            badge: `💥 Infiltrado (-${verdict.hpLoss || 25} HP)`,
            hasActor: true
        };
    }
    if (out === 'correct_block') {
        return {
            gateClass: 'gate-closed',
            stampText: '🛡️ STOP',
            actorClass: 'is-blocked',
            avatar: 'hacker',
            badge: '🛡️ Bloqueo exacto',
            hasActor: true
        };
    }
    if (out === 'false_positive') {
        return {
            gateClass: 'gate-closed is-warn-gate',
            stampText: '⚠️ FALSO +',
            actorClass: 'is-blocked is-warn',
            avatar: 'safe',
            badge: `⚠️ Bloqueo erróneo (-${verdict.hpLoss || 15} HP)`,
            hasActor: true
        };
    }
    if (out === 'partial_block') {
        return {
            gateClass: 'gate-closed is-warn-gate',
            stampText: '⚡ VECTOR',
            actorClass: 'is-blocked is-warn',
            avatar: 'hacker',
            badge: `⚡ Vector mal (-${verdict.hpLoss || 10} HP)`,
            hasActor: true
        };
    }
    if (out === 'timeout_breach') {
        return {
            gateClass: 'gate-alarm',
            stampText: '⏱️ SLA!',
            actorClass: 'is-breach',
            avatar: 'hacker',
            badge: `⏱️ Sin respuesta (-${verdict.hpLoss || 20} HP)`,
            hasActor: true
        };
    }
    return {
        gateClass: 'gate-alarm',
        stampText: '⏱️ SLA!',
        actorClass: 'is-breach',
        avatar: 'safe',
        badge: `⏱️ Abandono cola (-${verdict.hpLoss || 15} HP)`,
        hasActor: true
    };
}

function createProjectorStageCard(roomId) {
    const card = document.createElement('article');
    card.className = 'proj-stage-card';
    card.dataset.roomId = roomId;
    card.innerHTML = `
        <header class="proj-stage-head">
            <div class="proj-stage-title">
                <strong data-proj-name>Grupo</strong>
                <span class="proj-stage-sub" data-proj-sub>Casero: -</span>
            </div>
            <div class="proj-stage-metrics">
                <div class="proj-hp-wrap">
                    <div class="proj-hp-row">
                        <span>Caseta HP</span>
                        <strong data-proj-hp-text>100 HP</strong>
                    </div>
                    <div class="proj-hp-bar">
                        <div class="proj-hp-fill" data-proj-hp-fill></div>
                    </div>
                </div>
                <span class="proj-clock-chip" data-proj-clock>02:00</span>
                <span class="counter-chip" data-proj-atk-chip>⚡ 0 PTS</span>
            </div>
        </header>

        <div class="proj-checkpoint-lane">
            <div class="proj-queue-zone">
                <span class="proj-zone-label">FILA DE SOLICITUDES (<span data-proj-queue-count>0</span>)</span>
                <div class="proj-npc-line" data-proj-npc-line>
                    <span class="proj-queue-empty">Sin solicitudes en cola</span>
                </div>
            </div>

            <div class="proj-booth-zone">
                <span class="proj-booth-stamp" data-proj-booth-stamp>EN CASETA</span>
                <div class="proj-booth-cabin" data-proj-booth-cabin>
                    <div class="proj-booth-roof" aria-hidden="true"></div>
                    ${getNpcAvatarSvg('casero')}
                    <span class="proj-booth-casero-name" data-proj-casero-name>Casero</span>
                    <div class="proj-barrier-wrap" aria-hidden="true">
                        <div class="proj-barrier-post"></div>
                        <div class="proj-barrier-arm"></div>
                    </div>
                </div>
            </div>

            <div class="proj-exit-zone">
                <span class="proj-zone-label">VEREDICTO</span>
                <div class="proj-exit-track">
                    <div class="proj-exit-slot" data-proj-exit-slot></div>
                    <div class="proj-server-box" aria-hidden="true">
                        <i class="fa-solid fa-server"></i>
                        <span>e-Libre</span>
                    </div>
                </div>
            </div>
        </div>

        <footer class="proj-stage-foot" data-proj-foot>
            Esperando primer archivo en ventanilla...
        </footer>
    `;
    return card;
}

function renderProjectorNpcQueueHtml(queuePreview, pendingCount, slaRemainingMs, roundResult) {
    if (!queuePreview || !queuePreview.length) {
        return '<span class="proj-queue-empty">Cola vacía — casero libre</span>';
    }
    const visible = queuePreview.slice(0, 5);
    const hiddenCount = Math.max(0, (pendingCount || queuePreview.length) - visible.length);
    const moreChip = hiddenCount > 0 ? `<span class="proj-queue-more">+${hiddenCount}</span>` : '';

    const items = visible.map((pkt, idx) => {
        const isFront = idx === 0;
        let slaHtml = '';
        if (isFront && !roundResult && Number.isFinite(slaRemainingMs)) {
            const sec = Math.ceil(Math.max(0, slaRemainingMs) / 1000);
            const cls = sec <= 4 ? 'is-urgent' : (sec <= 7 ? 'is-warn' : '');
            slaHtml = `<span class="proj-npc-sla ${cls}" data-proj-sla>${sec}s</span>`;
        }
        return `
            <div class="proj-npc ${isFront ? 'is-at-window' : ''}">
                ${slaHtml}
                ${getNpcAvatarSvg('waiting')}
                <span class="proj-npc-file" title="${escapeHtml(pkt.filename)}">${escapeHtml(pkt.filename)}</span>
                <span class="proj-npc-name">${escapeHtml(pkt.senderName)}</span>
            </div>
        `;
    }).join('');

    return items + moreChip;
}

function tickProjectorStageClocks() {
    if (state.activeScreen !== 'screenProjector') return;
    const wrap = document.getElementById('projectorRoomsSummary');
    if (!wrap) return;
    const now = Date.now();

    Array.from(wrap.children).forEach((card) => {
        const roomId = card.dataset.roomId;
        const rState = projectorRoomState.get(roomId);
        if (!rState) return;

        if (!rState.roundResult && rState.matchStatus === 'active' && rState.roundEndsClientAt) {
            const remSec = Math.max(0, Math.ceil((rState.roundEndsClientAt - now) / 1000));
            const clockEl = card.querySelector('[data-proj-clock]');
            if (clockEl) {
                clockEl.textContent = formatClockMMSS(remSec);
                clockEl.classList.toggle('is-urgent', remSec <= 20);
            }
        }

        if (!rState.roundResult && rState.activeSlaClientDeadline) {
            const slaEl = card.querySelector('[data-proj-sla]');
            if (slaEl) {
                const sec = Math.max(0, Math.ceil((rState.activeSlaClientDeadline - now) / 1000));
                slaEl.textContent = `${sec}s`;
                slaEl.classList.toggle('is-urgent', sec <= 4);
                slaEl.classList.toggle('is-warn', sec > 4 && sec <= 7);
            }
        }

        if (!rState.roundResult && rState.lastVerdictAt && now - rState.lastVerdictAt > 3500) {
            const cabinEl = card.querySelector('[data-proj-booth-cabin]');
            const stampEl = card.querySelector('[data-proj-booth-stamp]');
            if (cabinEl && cabinEl.className !== 'proj-booth-cabin') {
                cabinEl.className = 'proj-booth-cabin';
            }
            if (stampEl && stampEl.textContent !== 'EN CASETA') {
                stampEl.textContent = 'EN CASETA';
            }
        }
    });
}

function startProjectorUiTicker() {
    stopProjectorUiTicker();
    projectorUiTickInterval = setInterval(tickProjectorStageClocks, 250);
}

function renderProjectorLiveStages(rooms, matchStatus) {
    const section = document.getElementById('projectorLiveStageSection');
    const wrap = document.getElementById('projectorRoomsSummary');
    if (!wrap) return;

    if (!rooms || !rooms.length) {
        projectorRoomState.clear();
        wrap.innerHTML = '';
        if (section) section.hidden = true;
        return;
    }

    if (section) section.hidden = false;
    wrap.classList.toggle('is-single', rooms.length === 1);

    const activeIds = new Set(rooms.map((r) => r.id));
    Array.from(wrap.children).forEach((child) => {
        if (!activeIds.has(child.dataset.roomId)) {
            projectorRoomState.delete(child.dataset.roomId);
            child.remove();
        }
    });

    const now = Date.now();
    rooms.forEach((r) => {
        let card = Array.from(wrap.children).find((el) => el.dataset.roomId === r.id);
        if (!card) {
            card = createProjectorStageCard(r.id);
            wrap.appendChild(card);
        }

        const prev = projectorRoomState.get(r.id) || {
            queueKey: '',
            lastVerdictId: null,
            lastVerdictAt: 0
        };

        card.classList.toggle('is-critical', r.serverIntegrity <= 30 && !r.roundResult);
        card.classList.toggle('is-finished', Boolean(r.roundResult));

        card.querySelector('[data-proj-name]').textContent = r.name;
        card.querySelector('[data-proj-sub]').textContent = `Casero: ${r.inspectorName || 'Sin asignar'} • Activos: ${r.attackersAbleToAttack}/${r.attackerCount}`;
        card.querySelector('[data-proj-casero-name]').textContent = r.inspectorName || 'Casero';
        card.querySelector('[data-proj-hp-text]').textContent = `${r.serverIntegrity} HP`;
        card.querySelector('[data-proj-atk-chip]').textContent = `⚡ ${r.attackersTotalCredits} PTS`;
        card.querySelector('[data-proj-queue-count]').textContent = String(r.pendingCount || 0);

        const hpFill = card.querySelector('[data-proj-hp-fill]');
        if (hpFill) {
            hpFill.style.setProperty('--hp-pct', `${Math.max(0, Math.min(100, r.serverIntegrity))}%`);
            hpFill.classList.toggle('is-warn', r.serverIntegrity <= 60 && r.serverIntegrity > 30);
            hpFill.classList.toggle('is-crit', r.serverIntegrity <= 30);
        }

        const clockEl = card.querySelector('[data-proj-clock]');
        if (clockEl) {
            clockEl.textContent = formatClockMMSS(r.remainingSeconds);
            clockEl.classList.toggle('is-urgent', r.remainingSeconds <= 20 && !r.roundResult);
        }

        const queuePreview = r.queuePreview || [];
        const queueKey = `${queuePreview.map((q) => q.packetId).join(',')}|${r.pendingCount || 0}|${Boolean(r.roundResult)}`;
        const npcLine = card.querySelector('[data-proj-npc-line]');
        if (npcLine && prev.queueKey !== queueKey) {
            npcLine.innerHTML = renderProjectorNpcQueueHtml(
                queuePreview,
                r.pendingCount,
                r.activePacketSlaRemainingMs,
                r.roundResult
            );
        }

        const latest = (r.recentVerdicts && r.recentVerdicts[0]) || null;
        if (latest && prev.lastVerdictId !== latest.packetId) {
            const vis = getVerdictStageVisuals(latest);
            const cabinEl = card.querySelector('[data-proj-booth-cabin]');
            const stampEl = card.querySelector('[data-proj-booth-stamp]');
            const exitSlot = card.querySelector('[data-proj-exit-slot]');
            if (cabinEl) cabinEl.className = `proj-booth-cabin ${vis.gateClass}`.trim();
            if (stampEl) stampEl.textContent = vis.stampText;
            if (exitSlot && vis.hasActor) {
                exitSlot.innerHTML = `
                    <div class="proj-exit-actor ${vis.actorClass}">
                        ${getNpcAvatarSvg(vis.avatar)}
                        <span class="proj-npc-file">${escapeHtml(latest.filename)}</span>
                        <span class="proj-exit-badge">${escapeHtml(vis.badge)}</span>
                    </div>
                `;
            }
            prev.lastVerdictId = latest.packetId;
            prev.lastVerdictAt = now;
        } else if (!latest) {
            const cabinEl = card.querySelector('[data-proj-booth-cabin]');
            const stampEl = card.querySelector('[data-proj-booth-stamp]');
            const exitSlot = card.querySelector('[data-proj-exit-slot]');
            if (cabinEl) cabinEl.className = 'proj-booth-cabin';
            if (stampEl) stampEl.textContent = 'EN CASETA';
            if (exitSlot) exitSlot.innerHTML = '';
            prev.lastVerdictId = null;
            prev.lastVerdictAt = 0;
        }

        const footEl = card.querySelector('[data-proj-foot]');
        if (footEl) {
            footEl.className = 'proj-stage-foot';
            if (r.roundResult) {
                footEl.classList.add(r.roundResult.winner === 'inspector' ? 'is-inspector-win' : 'is-attackers-win');
                footEl.textContent = r.roundResult.reason;
            } else if (latest) {
                footEl.textContent = `${latest.filename} (${latest.senderName}): ${latest.verdictHeadline}`;
            } else {
                footEl.textContent = `SLA en ventanilla: ${r.slaSeconds || 15}s máx. Esperando solicitudes de atacantes...`;
            }
        }

        projectorRoomState.set(r.id, {
            queueKey,
            lastVerdictId: prev.lastVerdictId,
            lastVerdictAt: prev.lastVerdictAt,
            matchStatus,
            roundResult: r.roundResult || null,
            roundEndsClientAt: (matchStatus === 'active' && !r.roundResult)
                ? now + (Number(r.remainingSeconds) || 0) * 1000
                : null,
            activeSlaClientDeadline: (!r.roundResult && Number.isFinite(r.activePacketSlaRemainingMs))
                ? now + r.activePacketSlaRemainingMs
                : null
        });
    });

    tickProjectorStageClocks();
}

function renderProjectorMatchStatus(matchData) {
    tutorialState.matchStatus = matchData.status || 'waiting';
    updateTutorialControlsUI();
    if (matchData.gameMode) {
        applyServerGameMode(matchData.gameMode);
    }

    const waitingEl = document.getElementById('projWaitingCount');
    const stateEl = document.getElementById('projMatchState');
    const previewEl = document.getElementById('projPreviewSummary');
    const tutLiveBadge = document.getElementById('tutLiveGroupsBadge');

    const waitingCount = (matchData.waitingPlayers || []).length;
    if (waitingEl) waitingEl.textContent = String(waitingCount);
    if (stateEl) {
        if (matchData.status === 'active') stateEl.textContent = `En curso (Ronda ${matchData.roundNumber || 1})`;
        else if (matchData.status === 'briefing') stateEl.textContent = `Video Tutorial (Ronda ${matchData.roundNumber || 1})`;
        else stateEl.textContent = 'En espera de sorteo';
    }
    if (previewEl && matchData.preview) {
        previewEl.textContent = matchData.preview.summaryText;
    }

    const rooms = matchData.groups || [];
    if (tutLiveBadge) {
        tutLiveBadge.textContent = rooms.length > 0
            ? `${rooms.length} grupo(s) sorteado(s): ${rooms.map((r) => `${r.name.split('—')[0].trim()} (Caseta: ${r.inspectorName || '?'})`).join(' • ')}`
            : 'Vista previa de demostración (los grupos se mostrarán al sortear)';
    }

    renderProjectorLiveStages(rooms, matchData.status || 'waiting');
}

function renderLeaderboardList(containerId, players) {
    const el = document.getElementById(containerId);
    if (!el) return;

    if (!players.length) {
        el.innerHTML = '<li class="lb-row"><span class="lb-meta">Aún no hay puntajes registrados en esta ronda.</span></li>';
        return;
    }

    el.innerHTML = players.map((p, idx) => {
        const rank = idx + 1;
        const isMe = state.playerId && p.playerId === state.playerId;
        const topClass = rank <= 3 ? `top-${rank}` : '';
        return `
            <li class="lb-row ${isMe ? 'is-me' : ''}">
                <div class="lb-left">
                    <span class="lb-rank ${topClass}">${rank}</span>
                    <div>
                        <div><strong>${escapeHtml(p.name)}${isMe ? ' (Tú)' : ''}</strong></div>
                        <div class="lb-meta">Precisión: ${p.accuracy || 0}%</div>
                    </div>
                </div>
                <div class="lb-score">${p.score} PTS</div>
            </li>
        `;
    }).join('');
}

function renderProjectorBoard(players, updatedAt) {
    document.getElementById('projTotalPlayers').textContent = String(players.length);
    document.getElementById('projLastSync').textContent = new Date(updatedAt || Date.now()).toLocaleTimeString('es-CO');

    const podium = document.getElementById('projectorPodium');
    const medals = ['🥇', '🥈', '🥉'];
    const top3 = players.slice(0, 3);
    podium.innerHTML = top3.map((p, idx) => `
        <div class="podium-slot rank-${idx + 1}">
            <div class="podium-medal" aria-hidden="true">${medals[idx]}</div>
            <div><strong>${escapeHtml(p.name)}</strong></div>
            <div class="podium-score">${p.score} PTS</div>
            <div class="lb-meta">Precisión ${p.accuracy || 0}%</div>
        </div>
    `).join('');

    renderLeaderboardList('projectorLeaderboardList', players);
}

function openProjectorView() {
    if (state.activeScreen !== 'screenProjector') {
        state.previousScreen = state.activeScreen;
    }
    navigateScreen('screenProjector');
}

async function resetClassLeaderboard() {
    try {
        const res = await fetch('/api/game/reset-leaderboard', { method: 'POST' });
        if (res.ok) {
            state.selectedRoomId = null;
            state.previousScreen = 'screenLobby';
            projectorRoomState.clear();
            fetchLeaderboardAndRooms();
        }
    } catch {
        // Silencioso
    }
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
