/**
 * ==========================================================================
 * LÓGICA DEL CLIENTE: Laboratorio AppSec CWE-434 (Subida Insegura de Archivos)
 * ==========================================================================
 */

let currentLabMode = 'vulnerable'; // 'vulnerable' | 'secure'
let stagedFile = null;

document.addEventListener('DOMContentLoaded', () => {
    initDropZone();
    loadProfile();
});

// ==========================================================================
// 1. CAMBIO DE MODO DEL LABORATORIO (VULNERABLE vs SEGURO)
// ==========================================================================
function setLabMode(mode) {
    currentLabMode = mode;
    const btnVuln = document.getElementById('btnModeVulnerable');
    const btnSec = document.getElementById('btnModeSecure');
    const telemetryEndpoint = document.getElementById('telemetryEndpoint');

    if (mode === 'vulnerable') {
        btnVuln.classList.add('active');
        btnSec.classList.remove('active');
        telemetryEndpoint.innerText = '/api/upload-vulnerable (Sin Filtros)';
        updateConsoleBadge('Modo Vulnerable Activo', 'vulnerable-alert');
    } else {
        btnSec.classList.add('active');
        btnVuln.classList.remove('active');
        telemetryEndpoint.innerText = '/api/upload-secure (AppSec Defensivo)';
        updateConsoleBadge('Modo Seguro Activo', 'secure-success');
    }
}

// ==========================================================================
// 2. CARGA RÁPIDA DE ARCHIVOS DE PRUEBA ACADÉMICOS
// ==========================================================================
async function loadTestFile(filename) {
    try {
        const response = await fetch(`/test_files/${filename}`);
        if (!response.ok) throw new Error('No se pudo cargar el archivo');
        const blob = await response.blob();
        
        // Crear un objeto File legítimo
        let mimeType = blob.type;
        if (filename.endsWith('.php')) mimeType = 'application/x-httpd-php';
        if (filename.endsWith('.png')) mimeType = 'image/png';
        if (filename.endsWith('.html')) mimeType = 'text/html';

        const file = new File([blob], filename, { type: mimeType });
        setStagedFile(file);
    } catch (err) {
        alert('Error al cargar archivo de prueba: ' + err.message);
    }
}

// ==========================================================================
// 3. GESTIÓN DEL DRAG & DROP Y SELECCIÓN DE ARCHIVOS
// ==========================================================================
function initDropZone() {
    const dropZone = document.getElementById('dropZone');

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'), false);
    });

    dropZone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            setStagedFile(files[0]);
        }
    });
}

function triggerFileInput() {
    document.getElementById('fileInput').click();
}

function handleFileSelected(event) {
    const file = event.target.files[0];
    if (file) {
        setStagedFile(file);
    }
}

async function setStagedFile(file) {
    stagedFile = file;

    // Actualizar vista del Dropzone
    document.getElementById('dropZoneContent').style.display = 'none';
    const displayBox = document.getElementById('selectedFileDisplay');
    displayBox.style.display = 'block';

    document.getElementById('selectedFileNameDisplay').innerText = file.name;
    document.getElementById('selectedFileMetaDisplay').innerText = `${formatBytes(file.size)} • ${file.type || 'Tipo desconocido'}`;

    // Actualizar icono según tipo
    const iconBox = document.getElementById('fileIconBox');
    const ext = file.name.split('.').pop().toLowerCase();
    if (['jpg', 'jpeg', 'png', 'gif'].includes(ext)) {
        iconBox.innerHTML = '<i class="fa-solid fa-file-image" style="color: #10b981;"></i>';
    } else if (['php', 'js', 'sh', 'py'].includes(ext)) {
        iconBox.innerHTML = '<i class="fa-solid fa-file-code" style="color: #ef4444;"></i>';
    } else if (['html', 'htm'].includes(ext)) {
        iconBox.innerHTML = '<i class="fa-solid fa-code" style="color: #f59e0b;"></i>';
    } else {
        iconBox.innerHTML = '<i class="fa-solid fa-file"></i>';
    }

    // Inspección en caliente de Magic Bytes en el cliente
    const sampleBytes = await readSampleMagicBytes(file);

    // Actualizar columna de telemetría en la consola AppSec
    document.getElementById('telemetryName').innerText = file.name;
    document.getElementById('telemetryExt').innerText = '.' + ext;
    document.getElementById('telemetryMime').innerText = file.type || 'application/octet-stream';
    document.getElementById('telemetrySize').innerText = `${file.size} bytes (${formatBytes(file.size)})`;
    document.getElementById('telemetryMagic').innerText = sampleBytes;

    updateConsoleBadge('Archivo Cargado (Listo para Enviar)', 'vulnerable-alert');
}

function clearSelectedFile(event) {
    if (event) event.stopPropagation();
    stagedFile = null;
    document.getElementById('fileInput').value = '';
    document.getElementById('dropZoneContent').style.display = 'block';
    document.getElementById('selectedFileDisplay').style.display = 'none';

    document.getElementById('telemetryName').innerText = '-';
    document.getElementById('telemetryExt').innerText = '-';
    document.getElementById('telemetryMime').innerText = '-';
    document.getElementById('telemetrySize').innerText = '-';
    document.getElementById('telemetryMagic').innerText = '-';
}

function readSampleMagicBytes(file) {
    return new Promise((resolve) => {
        const reader = new FileReader();
        const slice = file.slice(0, 8);
        reader.onload = (e) => {
            const arr = new Uint8Array(e.target.result);
            let hex = [];
            for (let i = 0; i < arr.length; i++) {
                hex.push(arr[i].toString(16).padStart(2, '0').toUpperCase());
            }
            resolve(hex.join(' ') || 'N/A');
        };
        reader.onerror = () => resolve('Error de lectura');
        reader.readAsArrayBuffer(slice);
    });
}

// ==========================================================================
// 4. ENVÍO DEL FORMULARIO Y AUDITORÍA DE RESULTADOS
// ==========================================================================
async function handleFormSubmit(event) {
    event.preventDefault();

    if (!stagedFile) {
        alert('Por favor seleccione o arrastre un archivo primero.');
        return;
    }

    const endpoint = currentLabMode === 'vulnerable' ? '/api/upload-vulnerable' : '/api/upload-secure';
    const formData = new FormData();
    formData.append('avatar', stagedFile);
    formData.append('description', document.getElementById('imageDescription').value);

    const submitBtn = document.getElementById('btnSubmitForm');
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Procesando...';

    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            body: formData
        });

        const data = await response.json();
        renderAuditResults(data, response.status);
    } catch (err) {
        alert('Error en la comunicación con el backend: ' + err.message);
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fa-solid fa-floppy-disk"></i> Actualizar información personal';
    }
}

// ==========================================================================
// 5. RENDERIZADO DE TELEMETRÍA Y SIMULACIÓN DE IMPACTO
// ==========================================================================
function renderAuditResults(data, httpStatus) {
    // Actualizar telemetría de backend
    document.getElementById('telemetrySavedAs').innerText = data.savedAs || '(Ninguno)';
    document.getElementById('telemetryDiskPath').innerText = data.storagePath || '(Bloqueado antes de persistir)';
    document.getElementById('telemetryUrl').innerText = data.publicUrl || 'N/A';

    const verdictBox = document.getElementById('telemetryVerdictBox');

    if (data.mode === 'vulnerable' && data.success) {
        // CASO VULNERABLE: Aceptado sin validaciones
        const isExploit = data.exploitSimulation != null;
        updateConsoleBadge('🚨 Vulnerabilidad Explotada', 'vulnerable-alert');

        let html = `
            <div class="verdict-box danger">
                <strong>${data.title}</strong>
                <p>El servidor almacenó el archivo en una ruta accesible vía web sin cambiar el nombre ni comprobar su contenido real.</p>
                <div style="margin-top: 6px;">
                    <a href="${data.publicUrl}" target="_blank" class="verdict-action-btn">
                        <i class="fa-solid fa-arrow-up-right-from-square"></i> Abrir / Ejecutar Archivo en Servidor Web
                    </a>
                </div>
            </div>
        `;
        verdictBox.innerHTML = html;

        // Mostrar Modal de Impacto
        showExploitModal({
            title: isExploit ? `⚠️ Explotación Confirmada: ${data.exploitSimulation.detectedType}` : 'Archivo Aceptado (Sin Filtro Defensivo)',
            isDanger: true,
            body: `
                <p>El archivo <strong>${escapeHtml(data.filename)}</strong> fue aceptado y guardado en <code>${escapeHtml(data.storagePath)}</code>.</p>
                ${isExploit ? `
                    <div style="background: #fee2e2; border-left: 4px solid #ef4444; padding: 12px; margin: 15px 0; color: #991b1b; border-radius: 4px;">
                        <strong>Impacto Demostrado:</strong><br>
                        ${data.exploitSimulation.recommendation}
                    </div>
                ` : `
                    <p style="color: #059669; font-weight: 500;">Se subió una imagen estándar, pero debido a la falta de controles, cualquier script también habría sido admitido.</p>
                `}
                <div style="margin-top: 15px;">
                    <a href="${data.publicUrl}" target="_blank" class="btn-submit-moodle" style="text-decoration: none;">
                        <i class="fa-solid fa-terminal"></i> Ver archivo servido por la URL pública
                    </a>
                </div>
            `
        });

        // Actualizar avatar en UI si es imagen visualizable
        const ext = (data.extension || '').toLowerCase();
        if (['.jpg', '.jpeg', '.png', '.gif'].includes(ext)) {
            updateAvatarUI(data.publicUrl, data.filename);
        } else {
            // Mostrar imagen de alerta de script
            updateAvatarUI('/img/script_warning.svg', data.filename, true);
        }

    } else if (data.mode === 'secure' && data.success) {
        // CASO SEGURO: Aceptado y protegido
        updateConsoleBadge('🛡️ Archivo Seguro y Protegido', 'secure-success');

        let html = `
            <div class="verdict-box success">
                <strong>${data.title}</strong>
                <p>Se validaron Magic Bytes, se sanitizó el nombre con UUID y se asignó almacenamiento protegido.</p>
                <div style="margin-top: 6px; font-size: 11px; color: #86efac;">
                    UUID Asignado: <code>${data.savedAs}</code>
                </div>
            </div>
        `;
        verdictBox.innerHTML = html;

        showExploitModal({
            title: '✅ Validación Exitosa y Remediación Aplicada',
            isDanger: false,
            body: `
                <p>El archivo <strong>${escapeHtml(data.filename)}</strong> cumplió con todos los controles AppSec:</p>
                <ul style="margin: 10px 0 10px 20px; line-height: 1.6;">
                    ${data.mitigationsApplied.map(m => `<li>${m}</li>`).join('')}
                </ul>
                <p>Almacenado de forma segura como: <code>${escapeHtml(data.savedAs)}</code></p>
            `
        });

        updateAvatarUI(data.publicUrl, data.filename);

    } else {
        // CASO SEGURO: Bloqueo exitoso de ataque
        updateConsoleBadge('🛑 Ataque Bloqueado', 'secure-blocked');

        let html = `
            <div class="verdict-box blocked">
                <strong>${data.title}</strong>
                <p>${data.reason}</p>
                <div style="margin-top: 6px; font-size: 11px; color: #fde68a;">
                    Control Activo: <strong>${data.cweMitigated}</strong>
                </div>
            </div>
        `;
        verdictBox.innerHTML = html;

        showExploitModal({
            title: '🛡️ Ataque Neutralizado por Controles AppSec',
            isDanger: false,
            body: `
                <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px; margin: 15px 0; color: #92400e; border-radius: 4px;">
                    <strong>Motivo del Rechazo:</strong><br>
                    ${data.reason}
                </div>
                <p>El servidor no persistió el archivo en disco, evitando por completo la ejecución de código (RCE) o Cross-Site Scripting (XSS).</p>
            `
        });
    }
}

// ==========================================================================
// 6. ACTUALIZACIÓN VISUAL DEL PERFIL EN LA UI (RÉPLICA e-Libre)
// ==========================================================================
function updateAvatarUI(url, filename, isScript = false) {
    const heroInitials = document.getElementById('mainHeroInitials');
    const heroImg = document.getElementById('mainHeroImg');
    const headerAvatar = document.getElementById('headerAvatarCircle');
    const currentImgText = document.getElementById('currentImageText');
    const currentImgPreview = document.getElementById('currentImagePreviewBox');
    const previewThumbnail = document.getElementById('previewThumbnail');
    const previewFilename = document.getElementById('previewFilename');

    if (url) {
        heroInitials.style.display = 'none';
        heroImg.style.display = 'block';
        heroImg.src = url;

        headerAvatar.innerHTML = `<img src="${url}" alt="Avatar">`;

        currentImgText.style.display = 'none';
        currentImgPreview.style.display = 'flex';
        previewThumbnail.src = url;
        previewFilename.innerText = filename;
    } else {
        heroInitials.style.display = 'block';
        heroImg.style.display = 'none';
        headerAvatar.innerHTML = 'SL';

        currentImgText.style.display = 'inline';
        currentImgText.innerText = 'Ninguno';
        currentImgPreview.style.display = 'none';
    }
}

async function loadProfile() {
    try {
        const res = await fetch('/api/profile');
        const data = await res.json();
        if (data.avatarUrl) {
            updateAvatarUI(data.avatarUrl, data.avatarName);
        }
    } catch (e) {
        console.error('Error al cargar perfil inicial', e);
    }
}

async function resetAvatar() {
    if (!confirm('¿Desea restablecer el avatar?')) return;
    try {
        await fetch('/api/reset', { method: 'POST' });
        updateAvatarUI(null, null);
        clearSelectedFile();
        document.getElementById('telemetryVerdictBox').className = 'verdict-box waiting';
        document.getElementById('telemetryVerdictBox').innerHTML = '<p>Seleccione o cargue uno de los archivos de prueba para analizar el comportamiento del servidor.</p>';
        updateConsoleBadge('Listo para auditar', '');
    } catch (e) {
        alert('Error al reiniciar avatar');
    }
}

function resetForm() {
    clearSelectedFile();
    document.getElementById('imageDescription').value = '';
}

// ==========================================================================
// 7. COMPONENTES INTERACTIVOS (ACORDEÓN, CONSOLA, MODAL)
// ==========================================================================
function toggleAccordion(headerEl) {
    const arrow = headerEl.querySelector('.accordion-arrow');
    const content = headerEl.nextElementSibling;
    if (!content) return;

    if (content.classList.contains('closed')) {
        content.classList.remove('closed');
        arrow.style.transform = 'rotate(0deg)';
    } else {
        content.classList.add('closed');
        arrow.style.transform = 'rotate(-90deg)';
    }
}

function toggleConsoleDrawer() {
    const drawer = document.getElementById('appSecConsole');
    const icon = document.getElementById('consoleToggleIcon');
    drawer.classList.toggle('collapsed');
    if (drawer.classList.contains('collapsed')) {
        icon.className = 'fa-solid fa-chevron-up';
    } else {
        icon.className = 'fa-solid fa-chevron-down';
    }
}

function updateConsoleBadge(text, className) {
    const badge = document.getElementById('consoleBadge');
    badge.innerText = text;
    badge.className = 'badge-status ' + className;
}

function showExploitModal({ title, isDanger, body }) {
    const modal = document.getElementById('exploitModal');
    const header = document.getElementById('modalHeader');
    document.getElementById('modalTitle').innerHTML = (isDanger ? '<i class="fa-solid fa-triangle-exclamation"></i> ' : '<i class="fa-solid fa-shield-check"></i> ') + title;
    header.className = 'modal-header ' + (isDanger ? '' : 'success');
    document.getElementById('modalBody').innerHTML = body;
    modal.style.display = 'flex';
}

function closeExploitModal() {
    document.getElementById('exploitModal').style.display = 'none';
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
