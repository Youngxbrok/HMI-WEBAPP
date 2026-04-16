# TitanControl-HMI

> Interface industrial HMI para operarios de maquinaria pesada.

## Stack

- **Backend**: Node.js + Express
- **DB**: SQLite (via `sqlite3`) — almacenada en `/data/`
- **Auth**: Sessions (`express-session`) + bcrypt
- **Views**: EJS templates
- **Biométrico**: Web Speech API + getUserMedia (cámara)

## Estructura

```
titancontrol/
├── server.js          # Express app, rutas, middleware
├── database.js        # Toda la lógica SQLite
├── package.json
├── Dockerfile
├── data/              # DB persistente (creada en runtime)
└── views/
    ├── login.ejs
    ├── register.ejs
    ├── biometric.ejs  # Escaneo facial + voz
    ├── dashboard.ejs  # Panel principal
    └── 404.ejs
```

## Inicio rápido

```bash
npm install
npm start
# → http://localhost:1943
# Credenciales: admin@titancontrol.io / Titan2024!
```

## Docker

```bash
docker build -t titancontrol-hmi .
docker run -p 1943:1943 -v titancontrol_data:/data titancontrol-hmi
```

## Flujo de autenticación

1. **Login** → valida email + password (bcrypt)
2. **Biométrico** → activa cámara (Face Frame overlay) + Web Speech API (transcripción)
3. **Dashboard** → métricas, control de voz, parada de emergencia, log de actividad

## Tablas SQLite

| Tabla | Campos clave |
|-------|-------------|
| `users` | id, username, email, passwordHash, role, isActive, lastLoginAt |
| `activity_logs` | id, userId, username, eventType, detail, ipAddress, createdAt |

## Eventos registrados

`LOGIN_SUCCESS`, `LOGIN_FAILURE`, `BIOMETRIC_PASS`, `BIOMETRIC_FAIL`,
`VOICE_COMMAND`, `EMERGENCY_STOP`, `LOGOUT`
