const https = require('https');
const http  = require('http');
const qs    = require('querystring');

const CLIENT_ID     = process.env.OAUTH_CLIENT_ID;
const CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET;
const PORT          = process.env.PORT || 3000;

function send(res, status, body, type) {
  res.writeHead(status, {
    'Content-Type': type || 'text/html; charset=utf-8',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(body);
}

function getPathname(reqUrl) {
  try { return new URL('http://x' + reqUrl).pathname; }
  catch(e) { return reqUrl.split('?')[0]; }
}

function getQuery(reqUrl) {
  try { return Object.fromEntries(new URL('http://x' + reqUrl).searchParams); }
  catch(e) {
    const q = reqUrl.split('?')[1] || '';
    return qs.parse(q);
  }
}

// Two-step handshake: popup sends "authorizing:github" first,
// waits for CMS to reply, then sends the token.
// This is the pattern Decap CMS / Sveltia CMS expects.
function callbackPage(provider, token) {
  const successMsg = 'authorization:' + provider + ':success:' +
    JSON.stringify({ token: token, provider: provider });
  return '<!doctype html><html><body><script>' +
    'var provider=' + JSON.stringify(provider) + ';' +
    'var successMsg=' + JSON.stringify(successMsg) + ';' +
    'window.addEventListener("message",function(e){' +
    '  if(e.data==="authorizing:"+provider){' +
    '    window.opener.postMessage(successMsg,e.origin);' +
    '    window.close();' +
    '  }' +
    '});' +
    'window.opener.postMessage("authorizing:"+provider,"*");' +
    '</script></body></html>';
}

function errorPage(provider, error) {
  const errMsg = 'authorization:' + provider + ':error:' +
    JSON.stringify({ error: error });
  return '<!doctype html><html><body><script>' +
    'var provider=' + JSON.stringify(provider) + ';' +
    'var errMsg=' + JSON.stringify(errMsg) + ';' +
    'window.opener.postMessage(errMsg,"*");' +
    'window.close();' +
    '</script></body></html>';
}

http.createServer((req, res) => {
  const pathname = getPathname(req.url);
  const query    = getQuery(req.url);

  console.log('[request]', req.method, pathname);

  if (pathname === '/' || pathname === '/health') {
    return send(res, 200, 'GGdove OAuth Proxy — OK', 'text/plain');
  }

  // GET /auth → redirect to GitHub OAuth
  if (pathname === '/auth') {
    const provider = query.provider || 'github';
    const scope    = query.scope || 'repo,user';
    const state    = query.state || '';
    const ghUrl =
      'https://github.com/login/oauth/authorize' +
      '?client_id='  + encodeURIComponent(CLIENT_ID) +
      '&scope='      + encodeURIComponent(scope) +
      '&state='      + encodeURIComponent(state);
    console.log('[auth] provider=' + provider + ' redirecting to GitHub');
    res.writeHead(302, { Location: ghUrl });
    return res.end();
  }

  // GET /callback → exchange code for token, do two-step handshake
  if (pathname === '/callback') {
    const provider = 'github';
    const code     = query.code  || '';
    const state    = query.state || '';
    console.log('[callback] code:', code ? code.substring(0,8)+'...' : 'MISSING');

    if (!code) {
      return send(res, 200, errorPage(provider, 'missing_code'));
    }

    const postBody = qs.stringify({
      client_id: CLIENT_ID, client_secret: CLIENT_SECRET, code: code, state: state
    });

    const options = {
      hostname: 'github.com',
      path:     '/login/oauth/access_token',
      method:   'POST',
      headers: {
        'Content-Type':   'application/x-www-form-urlencoded',
        'Accept':         'application/json',
        'Content-Length': Buffer.byteLength(postBody)
      }
    };

    let done = false;
    const ghReq = https.request(options, ghRes => {
      let raw = '';
      ghRes.on('data', c => raw += c);
      ghRes.on('end', () => {
        if (done) return; done = true;
        console.log('[callback] GitHub raw:', raw.substring(0, 120));
        try {
          const d = JSON.parse(raw);
          if (d.error || !d.access_token) {
            console.log('[callback] error from GitHub:', d.error);
            send(res, 200, errorPage(provider, d.error || 'no_token'));
          } else {
            console.log('[callback] success, sending handshake page');
            send(res, 200, callbackPage(provider, d.access_token));
          }
        } catch(e) {
          console.error('[callback] parse error:', e.message);
          send(res, 200, errorPage(provider, 'parse_error'));
        }
      });
    });

    ghReq.on('error', e => {
      if (done) return; done = true;
      console.error('[callback] network error:', e.message);
      send(res, 200, errorPage(provider, 'network_error'));
    });
    ghReq.setTimeout(10000, () => {
      if (done) return; done = true;
      ghReq.destroy();
      send(res, 200, errorPage(provider, 'timeout'));
    });
    ghReq.write(postBody);
    ghReq.end();
    return;
  }

  send(res, 404, 'Not found', 'text/plain');

}).listen(PORT, () => console.log('OAuth proxy listening on port', PORT));
