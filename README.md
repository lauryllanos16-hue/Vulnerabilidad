# 🛡️ Laboratorio Académico: Subida Insegura de Archivos (Unrestricted File Upload)

> **Clasificación:** CWE-434 / OWASP Top 10 (A04:2021 – Insecure Design / A03:2021 – Injection)  
> **Escenario:** Réplica de la plataforma institucional de edición de perfil (`e-Libre` / Moodle) + Juego didáctico multijugador **"Caseta Forense e-Libre | Reto CWE-434"**.  
> **Enlace público del juego:** https://servidor.tailb4ac82.ts.net/juego  
> **Objetivo Académico:** Demostrar cómo la falta de controles en la carga de archivos permite la Ejecución Remota de Código (RCE) y Stored XSS, enseñar controles defensivos multicapa (AppSec) y consolidar el aprendizaje mediante un juego interactivo en clase.

---

## 📋 Tabla de Contenidos
1. [Enlace Público y Despliegue](#-enlace-público-y-despliegue)
2. [Arquitectura del Proyecto](#-arquitectura-del-proyecto)
3. [Puesta en Marcha Local y con Docker](#-puesta-en-marcha-local-y-con-docker)
4. [Archivos de Prueba Incluidos](#-archivos-de-prueba-incluidos)
5. [Guía de Demostración en Clase (Paso a Paso)](#-guía-de-demostración-en-clase-paso-a-paso)
6. [Análisis Técnico de la Vulnerabilidad vs. Remediación](#-análisis-técnico-de-la-vulnerabilidad-vs-remediación)
7. [Resumen de Controles Defensivos (Defense in Depth)](#-resumen-de-controles-defensivos-defense-in-depth)
8. [Modo Juego Didáctico para Clase (`/juego` y `/proyector`)](#-modo-juego-didáctico-para-clase-juego-y-proyector)
9. [Herramientas de IA Utilizadas y Aporte al Desarrollo](#-herramientas-de-ia-utilizadas-y-aporte-al-desarrollo)

---

## 🌐 Enlace Público y Despliegue

El proyecto está desplegado en contenedor Docker (`node:20-slim`, puerto `8085:3000`) sobre servidor Debian y expuesto públicamente mediante **Tailscale Funnel**:

- **Juego interactivo para estudiantes:** https://servidor.tailb4ac82.ts.net/juego
- **Consola exclusiva del presentador (Proyector del salón):** https://servidor.tailb4ac82.ts.net/proyector
- **Laboratorio práctico `e-Libre` (Modo Vulnerable / Modo Seguro):** https://servidor.tailb4ac82.ts.net/

---

## 🏛️ Arquitectura del Proyecto

```text
├── server.js                    # Servidor Express: flujo vulnerable, flujo seguro, simulador RCE, API del juego y SLA
├── package.json                 # Dependencias y scripts del proyecto
├── Dockerfile                   # Imagen Node 20 Slim lista para producción
├── docker-compose.yml           # Orquestación del servicio lab-cwe434 (puerto 8085 -> 3000)
├── render.yaml                  # Configuración alternativa de despliegue
├── .gitignore                   # Exclusiones de control de versiones
├── public/                      # Frontend interactivo
│   ├── index.html               # Interfaz de laboratorio (Réplica de e-Libre / Moodle)
│   ├── game.html                # Juego didáctico "Caseta Forense e-Libre | Reto CWE-434" y consola Proyector
│   ├── favicon.svg              # Ícono vectorial de la plataforma
│   ├── audio/                   # Pistas MP3 narradas con voz neural para el tutorial (escenas 0 a 5)
│   │   ├── tut-scene-0.mp3
│   │   ├── tut-scene-1.mp3
│   │   ├── tut-scene-2.mp3
│   │   ├── tut-scene-3.mp3
│   │   ├── tut-scene-4.mp3
│   │   └── tut-scene-5.mp3
│   ├── css/
│   │   ├── style.css            # Estilos institucionales + Drawer de telemetría AppSec
│   │   └── game.css             # Arquitectura CSS con @layer, tema forense y escenario animado del proyector
│   ├── js/
│   │   ├── app.js               # Control de estados, Drag & Drop y llamadas a la API del laboratorio
│   │   └── game.js              # Calibración, arena 1 vs N, SLA anti-inactividad, modo solitario y proyector animado
│   └── img/
│       └── script_warning.svg   # Placeholder visual para scripts no interpretables
├── uploads/
│   ├── vulnerable/              # Directorio público sin restricciones (Escenario Inseguro)
│   └── secure/                  # Directorio protegido fuera de la raíz web directa (Escenario Seguro)
└── test_files/                  # Archivos de prueba para las demostraciones
    ├── avatar_normal.png        # Imagen PNG legítima con Magic Bytes válidos
    ├── exploit_poc.php          # PoC inofensivo de WebShell / RCE
    ├── exploit_xss.html         # PoC de Stored Cross-Site Scripting (XSS)
    ├── spoofed_script.png       # Script PHP camuflado con extensión .png (Falso Magic Byte)
    └── fake_image.png.php       # Intento de bypass por doble extensión
```

---

## 🚀 Puesta en Marcha Local y con Docker

### Opción A: Ejecución local con Node.js
- **Prerrequisito:** Node.js v18 o superior.
1. Instalar dependencias:
   ```bash
   npm install
   ```
2. Iniciar el servidor:
   ```bash
   npm start
   ```
3. Abrir en el navegador:
   - Laboratorio `e-Libre`: `http://localhost:3000/`
   - Juego para estudiantes: `http://localhost:3000/juego`
   - Consola de proyector: `http://localhost:3000/proyector`

### Opción B: Ejecución con Docker Compose
```bash
docker compose up -d --build
```
Expone el servicio en `http://localhost:8085` (variables `PORT=3000`, `NODE_ENV=production`).

---

## 🧪 Archivos de Prueba Incluidos

| Archivo | Tipo / Extensión | Propósito de la Demostración |
| :--- | :--- | :--- |
| `avatar_normal.png` | Imagen PNG legítima | Comprobar el flujo de usuario normal (Magic Bytes `89 50 4E 47...`). |
| `exploit_poc.php` | Script PHP (PoC académico) | Evidenciar RCE (Ejecución Remota de Código) en el servidor web. |
| `exploit_xss.html` | Documento HTML con JS | Evidenciar Stored XSS afectando la sesión de otros usuarios. |
| `spoofed_script.png` | Script PHP con extensión `.png` | Demostrar cómo engañar validaciones débiles basadas solo en extensión. |
| `fake_image.png.php` | Archivo con doble extensión | Demostrar bypass de validaciones que usan `includes(".png")` en vez de `extname()`. |

---

## 🎙️ Guía de Demostración en Clase (Paso a Paso)

### 🔴 Demostración 1: El Flujo Vulnerable (CWE-434)
1. En la barra superior, verifique que esté seleccionado el **Modo Vulnerable** (botón rojo activo).
2. Haga clic en el botón rápido **`exploit_poc.php`** (o arrastre el archivo desde `test_files/`).
3. Observe la **Consola de Auditoría AppSec** en la parte inferior:
   - Detecta la extensión `.php`.
   - Lee los Magic Bytes reales (`3C 3F 70 68...` = `<?php`).
4. Haga clic en **"Actualizar información personal"**:
   - El servidor almacena el archivo directamente en `uploads/vulnerable/exploit_poc.php`.
   - Se despliega el modal de impacto.
5. Haga clic en **"Ver archivo servido por la URL pública"**:
   - Se abrirá la consola de ejecución del servidor demostrando que el código PHP fue interpretado, comprometiendo los privilegios del proceso `www-data` (RCE).

### 🟡 Demostración 2: Stored Cross-Site Scripting (XSS)
1. En Modo Vulnerable, cargue **`exploit_xss.html`**.
2. Guarde los cambios y abra el enlace público:
   - El navegador ejecutará el código JavaScript embebido bajo el mismo origen (`Same-Origin`), demostrando el robo simulado de tokens de sesión.

### 🟢 Demostración 3: Aplicación de la Solución Defensiva (AppSec)
1. Cambie el interruptor superior a **Modo Seguro (Remediado)** (botón verde activo).
2. Intente subir **`exploit_poc.php`**:
   - 🛑 **Resultado:** Bloqueado de inmediato por **Lista Blanca Estricta de Extensiones** (CWE-434 neutralizado).
3. Intente subir **`spoofed_script.png`** (el archivo renombrado a `.png` pero que contiene código PHP):
   - 🛑 **Resultado:** El filtro de extensiones se supera, pero la **Validación de Magic Bytes** detecta que los primeros bytes no corresponden a la firma oficial de un archivo PNG (`89 50 4E 47 0D 0A 1A 0A`). El archivo es descartado en memoria sin tocar el disco.
4. Cargue **`avatar_normal.png`**:
   - ✅ **Resultado:** Pasa todos los controles. El archivo es renombrado aleatoriamente con un **UUID v4** (ej. `a9b2...png`), almacenado en una carpeta aislada y servido mediante un endpoint seguro con cabeceras `X-Content-Type-Options: nosniff`.

---

## 🔍 Análisis Técnico de la Vulnerabilidad vs. Remediación

```
                      ┌────────────────────────────────────────┐
                      │    Archivo Subido por el Cliente       │
                      └──────────────────┬─────────────────────┘
                                         │
                   ┌─────────────────────┴─────────────────────┐
                   ▼                                           ▼
       [ ESCENARIO VULNERABLE ]                    [ ESCENARIO DEFENSIVO ]
   - destination: uploads/vulnerable           1. Carga a memoria (Buffer)
   - filename: originalname                    2. Lista blanca estricta (.png, .jpg)
   - Sin inspección de contenido               3. Verificación binaria de Magic Bytes
   - Servido directo por URL                   4. Renombrado criptográfico con UUID
                   │                           5. Servido con cabecera "nosniff"
                   ▼                                           │
         🚨 RCE / Stored XSS                                   ▼
        Sistema Comprometido                     🛡️ Almacenamiento Aislado y Seguro
```

---

## 🛡️ Resumen de Controles Defensivos (Defense in Depth)

1. **Lista Blanca Estricta (Extension Whitelisting):**  
   Nunca utilice listas negras (prohibir `.php`, `.exe`, etc.), pues los atacantes utilizan variantes (`.phtml`, `.php5`, `.phar`). Defina únicamente lo permitido: `jpg, jpeg, png, gif`.
2. **Inspección de Magic Bytes (Firmas Binarias):**  
   El encabezado `Content-Type` enviado por el navegador y la extensión pueden falsificarse fácilmente. Comprobar los primeros 4 a 8 bytes del búfer garantiza la autenticidad del formato.
3. **Renombrado Criptográfico con UUID:**  
   Impide ataques de sobreescritura de archivos críticos y neutraliza intentos de *Directory Traversal* (`../../../etc/passwd`).
4. **Almacenamiento Fuera de la Raíz Web (Non-executable Storage):**  
   Los archivos no deben residir en carpetas donde el servidor web tenga activada la interpretación de scripts.
5. **Cabeceras HTTP Defensivas:**  
   `X-Content-Type-Options: nosniff` impide que navegadores antiguos ejecuten código malicioso reinterpretando un archivo binario.

---

## 🎮 Modo Juego Didáctico para Clase (`/juego` y `/proyector`)

El proyecto incluye el juego interactivo **"Caseta Forense e-Libre | Reto CWE-434"**, optimizado para jugar desde celulares (`/juego`) con consola de proyección independiente (`/proyector`) pensada para grupos de clase (30+ estudiantes simultáneos).

### 1. Flujo de la clase entre `/proyector` y `/juego`
1. **Consola exclusiva del presentador (`/proyector`):**
   - Solo el presentador controla desde `/proyector` la **modalidad activa** (`Grupos 1 vs N` o `Misión Individual de 3 Fases`), el **sorteo de grupos**, la reproducción del **video tutorial**, el lanzamiento directo de rondas y el reinicio del ranking (`POST /api/game/reset-leaderboard`).
   - Los estudiantes en `/juego` ven la modalidad seleccionada automáticamente en modo lectura, sin acceso al proyector ni botones para forzar sorteos.
2. **Calibración previa de Magic Bytes (`screenMinigame`):**
   - Antes de pasar a la sala de espera, cada estudiante resuelve 4 rondas contrarreloj (`10s` cada una) distinguiendo firmas binarias reales (`89 50 4E 47`, `FF D8 FF E0`) de cargas maliciosas (`<?php`, `<svg onload=`). La puntuación obtenida otorga un bono inicial de créditos de ataque.
3. **Emparejamiento aleatorio balanceado (`computeBalancedGroupCount`):**
   - Al sortear desde el proyector, `server.js` distribuye automáticamente a los estudiantes conectados en grupos parejos garantizando **1 Casero/Inspector al azar + al menos 3 Atacantes** por caseta (por ejemplo, 30 estudiantes → 5 casetas de 1 vs 5).
4. **Video tutorial animado con Voz Neural (6 escenas, `02:05`):**
   - Al pulsar **"Sortear Grupos + Video Tutorial"**, los celulares entran en la pantalla de *Briefing* mostrando el grupo y rol asignados mientras el proyector reproduce un tutorial animado de 6 escenas narrado con voz neural (`public/audio/tut-scene-0.mp3` a `tut-scene-5.mp3`), repasando la dinámica y los 4 vectores de ataque (**RCE / Doble Extensión**, **Magic Bytes Spoofing**, **Stored XSS** y **Path Traversal**). Al terminar el tutorial, la partida arranca automáticamente en todos los dispositivos.

### 2. Mecánicas de supervivencia y economía anti-spam
- **Defensa del Casero (`100 HP • 2:00` minutos + SLA `15s`):**
  - El Casero inspecciona la extensión, el `Content-Type` y el volcado Hex/ASCII de cada archivo entrante y decide entre **Permitir** o **Bloquear** clasificando el vector exacto (`rce`, `spoofing`, `xss` o `traversal`). No gana puntos por archivo: su meta es resistir los 2 minutos o dejar a los atacantes sin créditos (`< 50 PTS`).
  - **Penalización anti-inactividad (SLA 15s):** El expediente en ventanilla tiene un límite de `15s` para ser respondido. Si el Casero no responde a tiempo, pierde **`-20 HP`** (si era exploit, `+120 PTS` de ataque al remitente) o **`-15 HP`** (si era imagen real abandonada, `+100 PTS` al remitente).
- **Economía de los Atacantes (anti-spam):**
  - Cada envío consume créditos de ataque: **`-50 PTS`** (imagen legítima usada como señuelo para provocar falso positivo), **`-60 PTS`** (RCE o Stored XSS) u **`-80 PTS`** (Magic Bytes Spoofing o Path Traversal).
  - Si logran vulnerar la caseta (`breach`, `-25 HP`) recuperan **`+150 PTS`**; si provocan un falso positivo (`-15 HP`) ganan **`+110 PTS`**; y si el Casero bloquea con vector incorrecto (`-10 HP`) recuperan **`+70 PTS`**. Si el bloqueo es exacto, el Casero conserva su vida y el atacante pierde los puntos invertidos.
- **Escenario animado en vivo en `/proyector`:**
  - Muestra cada caseta activa simultáneamente con su **fila de NPCs**, temporizador SLA en ventanilla, barrera móvil animada (sube al aprobar o sufrir brecha, baja al detener solicitudes, parpadea al vencer el SLA), barra de HP y podio Top 3 actualizado en vivo.
- **Modo alternativo — Misión Individual (3 Fases):**
  - Desde `/proyector` también se puede activar la modalidad individual (`solo`) de 3 fases: (1) Inspector de Firewall (6 casos), (2) Parcheo de código en `server.js` (4 retos) y (3) Ráfaga OWASP (5 preguntas contrarreloj).

---

## 🤖 Herramientas de IA Utilizadas y Aporte al Desarrollo

Durante el diseño, implementación y despliegue de este proyecto se utilizaron herramientas de Inteligencia Artificial integradas en el flujo de ingeniería:

| Herramienta de IA | Rol y Aporte Concreto al Proyecto |
| :--- | :--- |
| **Antigravity (Agente de Ingeniería de Software con modelos Gemini)** | • **Arquitectura Backend (`server.js`):** Diseño de la lógica de emparejamiento aleatorio balanceado con `crypto.randomInt`, sistema anti-spam basado en créditos de ataque, motor de evaluación forense de paquetes (`evaluateCraftedPacket`) y mecanismo SLA anti-inactividad en memoria (`15s`).<br>• **Interfaz y Experiencia Web (`public/game.html`, `public/css/game.css`, `public/js/game.js`):** Implementación del tablero didáctico aplicando buenas prácticas modernas de desarrollo web (`@layer` en CSS, `<dialog>` nativo con *light dismiss*, Popover API, View Transitions API, propiedades lógicas y `color-mix(in oklab, ...)`), junto con el escenario animado de NPCs SVG para el proyector.<br>• **Integración de Audio, Pruebas y Despliegue:** Refactorización y pruebas automatizadas *end-to-end* del flujo multijugador y SLA en puertos locales de prueba, contenerización en Docker (`Dockerfile`, `docker-compose.yml`) y publicación en el servidor Debian con Tailscale Funnel. |
| **Google Cloud Text-to-Speech (`es-US-Chirp3-HD-Charon`)** | • **Narración del Video Tutorial (`public/audio/tut-scene-0.mp3`..`5.mp3`):** Generación de las 6 pistas de audio en español con voz neural de alta definición (procesadas y normalizadas con `ffmpeg`) para explicar de forma clara al curso las reglas del juego y los 4 vectores de ataque CWE-434 al iniciar la partida en el proyector. |
