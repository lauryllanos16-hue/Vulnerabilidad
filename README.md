# 🛡️ Laboratorio Académico: Subida Insegura de Archivos (Unrestricted File Upload)

> **Clasificación:** CWE-434 / OWASP Top 10 (A04:2021 – Insecure Design / A03:2021 – Injection)  
> **Escenario:** Réplica de la plataforma institucional de edición de perfil (`e-Libre` / Moodle).  
> **Objetivo Académico:** Demostrar cómo la falta de controles en la carga de archivos permite la Ejecución Remota de Código (RCE) y Stored XSS, y enseñar la implementación de controles defensivos multicapa (AppSec).

---

## 📋 Tabla de Contenidos
1. [Arquitectura del Proyecto](#-arquitectura-del-proyecto)
2. [Puesta en Marcha Local](#-puesta-en-marcha-local)
3. [Archivos de Prueba Incluidos](#-archivos-de-prueba-incluidos)
4. [Guía de Demostración en Clase (Paso a Paso)](#-guía-de-demostración-en-clase-paso-a-paso)
5. [Análisis Técnico de la Vulnerabilidad vs. Remediación](#-análisis-técnico-de-la-vulnerabilidad-vs-remediación)
6. [Resumen de Controles Defensivos (Defense in Depth)](#-resumen-de-controles-defensivos-defense-in-depth)

---

## 🏛️ Arquitectura del Proyecto

```text
├── server.js               # Servidor Express: Endpoints vulnerable, seguro y simulador RCE
├── package.json            # Dependencias del proyecto
├── .gitignore              # Exclusiones de control de versiones
├── public/                 # Frontend interactivo
│   ├── index.html          # Interfaz gráfica (Réplica fiel de e-Libre / Moodle)
│   ├── css/
│   │   └── style.css       # Estilos visuales institucionales + Drawer de telemetría AppSec
│   ├── js/
│   │   └── app.js          # Control de estados, Drag & Drop y llamadas a la API
│   └── img/
│       └── script_warning.svg # Placeholder visual para scripts no interpretables
├── uploads/
│   ├── vulnerable/         # Directorio público sin restricciones (Escenario Inseguro)
│   └── secure/             # Directorio protegido fuera de la raíz web directa (Escenario Seguro)
└── test_files/             # Archivos de prueba para las demostraciones
    ├── avatar_normal.png   # Imagen PNG legítima con Magic Bytes válidos
    ├── exploit_poc.php     # PoC inofensivo de WebShell / RCE
    ├── exploit_xss.html    # PoC de Stored Cross-Site Scripting (XSS)
    ├── spoofed_script.png  # Script PHP camuflado con extensión .png (Falso Magic Byte)
    └── fake_image.png.php  # Intento de bypass por doble extensión
```

---

## 🚀 Puesta en Marcha Local

### Prerrequisitos
- **Node.js** (v18 o superior).

### Instalación y Ejecución
1. Instalar dependencias:
   ```bash
   npm install
   ```
2. Iniciar el servidor del laboratorio:
   ```bash
   npm start
   ```
3. Abrir en el navegador:
   ```text
   http://localhost:3000
   ```

---

## 🧪 Archivos de Prueba Incluidos

| Archivo | Tipo / Extensión | Propósito de la Demostración |
| :--- | :--- | :--- |
| `avatar_normal.png` | Imagen PNG legítima | Comprobar el flujo de usuario normal (Magic bytes `89 50 4E 47...`). |
| `exploit_poc.php` | Script PHP (PoC académico) | Evidenciar RCE (Ejecución Remota de Código) en el servidor web. |
| `exploit_xss.html` | Documento HTML con JS | Evidenciar Stored XSS afectando la sesión de otros usuarios. |
| `spoofed_script.png` | Script PHP con extensión `.png` | Demostrar cómo engañar validaciones débiles basadas solo en extensión. |

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
