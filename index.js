const https = require('https');
const http  = require('http');
const url   = require('url');

const CLIENT_ID     = process.env.OAUTH_CLIENT_ID;
const CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET;
const PORT          = process.env.PORT || 3000;

function send(res, status, body, type) {
  res.writeHead(status, { 'Content-Type': type || 'text/html; charset=utf-8' });
  res.end(body);
}

http.createServer((req, res) => {
  const parsed   = url.parse(req.url, true);
  const pathname = parsed.pathname;

  // GET /auth  → redirect to GitHub
  if (pathname === '/auth') {
    const scope = parsed.query.scope || 'repo,user';
    const state = parsed.query.state || '';
    const ghUrl =
      'https://github.com/login/oauth/authorize' +
      '?client_id=' + encodeURIComponent(CLIENT_ID) +
      '&scope='     + encodeURIComponent(scope) +
      '&state='     + encodeURIComponent(state);
    res.writeHead(302, { Location: ghUrl });
    res.end();
    return;
  }

  // GET /callback  → exchange code → postMessage token
  if (pathname === '/callback') {
    const code  = parsed.query.code || '';
    const state = parsed.query.state || '';
    const body  = JSON.stringify({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET, code });

    const options = {
      hostname: 'github.com',
      path:     '/login/oauth/access_token',
      method:   'POST',
      headers:  { 'Content-Type': 'application/json', Accept: 'application/json',
                  'Content-Length': Buffer.byteLength(body) }
    };

    const ghReq = https.request(options, ghRes => {
      let raw = '';
      ghRes.on('data', c => raw += c);
      ghRes.on('end', () => {
        let msg;
        try {
          const d = JSON.parse(raw);
          if (d.error) {
            msg = 'authorization:github:error:' + JSON.stringify({ error: d.error });
          } else {
            msg = 'authorization:github:success:' + JSON.stringify({ token: d.access_token, provider: 'github' });
          }
        } catch(e) { msg = 'authorization:github:error:' + JSON.stringify({ error: 'parse_error' }); }

        send(res, 200,
          `<!doctype html><html><body><script>` +
          `(window.opener||window.parent).postMessage(${JSON.stringify(msg)},'*');` +
          `window.close();` +
          `</script></body></html>`
        );
      });
    });

    ghReq.on('error', e => send(res, 500, 'OAuth error: ' + e.message, 'text/plain'));
    ghReq.write(body);
    ghReq.end();
    return;
  }

  send(res, 200, 'GGdove OAuth Proxy — OK', 'text/plain');

}).listen(PORT, () => console.log('OAuth proxy listening on port', PORT));
