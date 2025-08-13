import express from 'express';
import WebSocket from 'ws';
import crypto from 'crypto';
import cors from 'cors';

const BACKEND_WS_URL = process.env.WS_URL || 'ws://109.107.116.142:9575/agents';
const SITE_ID = process.env.SITE_ID || 'default-site';
const DEVICE_ID = process.env.DEVICE_ID || crypto.randomUUID();

// Estado WS
let ws;

// Conexión WS saliente al backend
function connectWS() {
    ws = new WebSocket(BACKEND_WS_URL, {
        // aquí puedes añadir headers o certificados si usas mTLS/JWT
    });

    ws.on('open', () => {
        // Registrar agente
        ws.send(JSON.stringify({
            type: 'register',
            site_id: SITE_ID,
            device_id: DEVICE_ID,
            device_name: `agent-${DEVICE_ID.slice(0, 6)}`,
            capabilities: { db: 'postgres', version: '16', features: ['query', 'health'] }
        }));
        console.log('[WS] conectado y registrado');
    });

    ws.on('message', async (raw) => {
        const msg = JSON.parse(raw);
        if (msg.type === 'task') {
            // Ejecuta la tarea (aquí harías la consulta real a tu BD local)
            const { task_id, action, payload } = msg;
            try {
                if (action === 'query') {
                    // TODO: reemplazar por consulta real (pg/mysql/sqlserver)
                    const result = await simulateQuery(payload);
                    ws.send(JSON.stringify({ type: 'task_result', task_id, ok: true, result }));
                } else if (action === 'health') {
                    ws.send(JSON.stringify({ type: 'task_result', task_id, ok: true, result: { status: 'ok' } }));
                } else {
                    ws.send(JSON.stringify({ type: 'task_result', task_id, ok: false, error: 'acción no soportada' }));
                }
            } catch (err) {
                ws.send(JSON.stringify({ type: 'task_result', task_id, ok: false, error: String(err) }));
            }
        }
    });

    ws.on('close', () => {
        console.log('[WS] cerrado, reconectando en 2s');
        setTimeout(connectWS, 2000);
    });

    ws.on('error', (e) => {
        console.error('[WS] error', e.message);
        ws.close();
    });
}

// Simulación de consulta (sustituir por lógica real)
function simulateQuery(payload) {
    const { query_template, params } = payload;
    return new Promise((resolve) => {
        setTimeout(() => {
            if (query_template.includes('orders')) {
                resolve([{ id: params[0], status: 'PAID', amount: 150.0 }]);
            } else {
                resolve([{ count: 1 }]);
            }
        }, 120);
    });
}

const AGENT_PORT = Number(process.env.AGENT_PORT || 17321);

// Servidor local para /claim (loopback)
const app = express();
app.use(express.json());

//app.use(cors());
app.use(cors({
  origin: '*',  // Permitir peticiones desde cualquier origen
}));

// CORS: limita al dominio de tu app web
app.use((req, res, next) => {
    const allowedOrigins = [
        'https://tuapp.com',
        'https://www.tuapp.com',
        'http://localhost:3000' // útil en desarrollo
    ];
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Vary', 'Origin');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    }
    next();
});

// /claim: recibe pairing_token desde el navegador y lo reenvía al backend por WS
app.post('/claim', (req, res) => {
    const { pairing_token, origin } = req.body || {};
    console.log('Received claim request:', { pairing_token, origin });
    if (!pairing_token) return res.status(400).send('missing token');

    if (!ws || ws.readyState !== WebSocket.OPEN) {
        return res.status(503).send('ws not ready');
    }

    // Opcional: valida origin contra tu dominio
    ws.send(JSON.stringify({ type: 'claim_pairing', pairing_token }));
    res.status(200).send('ok');
});

// Bind solo loopback (no se expone en la red)
app.listen(AGENT_PORT, '127.0.0.1', () => {
    console.log(`Agente escuchando /claim en http://127.0.0.1:${AGENT_PORT}`);
});

connectWS();