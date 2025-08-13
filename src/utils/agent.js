import express from 'express';
import cors from 'cors';
import { invoke } from '@tauri-apps/api';

const BACKEND_WS_URL = process.env.WS_URL || 'ws://109.107.116.142:9575/agents';

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

async function LlamadaBackend() {
    const params = { comando: 'cargarTrabajadores', empresa: '' };
    const response = await invoke('api_command_py', { inputJson: JSON.stringify(params) });

    const payload = typeof response === 'string' ? JSON.parse(response) : response;
    let entries;
    if (typeof payload.result === 'string') {
        const lvl1 = JSON.parse(payload.result);
        entries = JSON.parse(lvl1).result;
    } else {
        entries = payload.result;
    }
    if (!Array.isArray(entries)) throw new Error('Formato inesperado de entries');
};



// /claim: recibe pairing_token desde el navegador y lo reenvía al backend por WS
app.post('/consulta-backend', async(req, res) => {
    const { pairing_token, origin } = req.body || {};
    console.log('Received claim request:', { pairing_token, origin });
    await LlamadaBackend();
    console.log('Backend called successfully');
    res.status(200).send('ok');
});

// Bind solo loopback (no se expone en la red)
app.listen(AGENT_PORT, '127.0.0.1', () => {
    console.log(`Agente escuchando /claim en http://127.0.0.1:${AGENT_PORT}`);
});

connectWS();