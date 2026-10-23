export default {
  async fetch(request, env, ctx) {
    // 1. Enforce Basic Authentication Security Check
    const authHeader = request.headers.get('Authorization');
    if (!authHeader) return createAuthResponse();

    try {
      const base64Str = authHeader.split(' '); 
      const decoded = atob(base64Str).split(':');
      if (decoded[0] !== env.PROXY_USER || decoded[1] !== env.PROXY_PASS) {
        return createAuthResponse();
      }
    } catch (err) {
      return createAuthResponse();
    }

    const proxyUrl = new URL(request.url);
    const proxyOrigin = proxyUrl.origin;
    
    const targetBase = env.TARGET_URL.replace(/\/$/, ""); 
    const targetHost = new URL(targetBase).hostname;

    let destinationUrl = "";
    let upstreamHost = targetHost;

    // Asset route multiplexer
    if (proxyUrl.pathname.startsWith('/__proxy_asset_cloudinary/')) {
      destinationUrl = "https://cloudinary.com" + proxyUrl.pathname.replace('/__proxy_asset_cloudinary', '') + proxyUrl.search;
      upstreamHost = "://cloudinary.com";
    } else if (proxyUrl.pathname.startsWith('/__proxy_asset_ctfassets/')) {
      destinationUrl = "https://ctfassets.net" + proxyUrl.pathname.replace('/__proxy_asset_ctfassets', '') + proxyUrl.search;
      upstreamHost = "images.ctfassets.net";
    } else {
      destinationUrl = targetBase + proxyUrl.pathname + proxyUrl.search;
      upstreamHost = targetHost;
    }

    // Clone incoming headers and spoof routing metrics
    let newHeaders = new Headers(request.headers);
    newHeaders.set("Host", upstreamHost);
    newHeaders.set("Referer", `https://${upstreamHost}/`);
    newHeaders.delete("Authorization"); 

    const modifiedRequest = new Request(destinationUrl, {
      method: request.method,
      headers: newHeaders,
      body: request.body,
      redirect: "manual"
    });

    try {
      const response = await fetch(modifiedRequest);
      const contentType = response.headers.get("content-type") || "";

      // Intercept and rewrite downstream HTTP redirection pointers
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get("Location");
        if (location) {
          let rewrittenLocation = location;
          if (location.includes(targetHost)) {
            rewrittenLocation = location.replace(`https://${targetHost}`, proxyOrigin);
          } else if (location.startsWith('/')) {
            rewrittenLocation = proxyOrigin + location;
          }
          let redirectResponse = new Response(`Redirecting`, { status: response.status });
          redirectResponse.headers.set("Location", rewrittenLocation);
          return redirectResponse;
        }
      }

      // Intercept and alter cookie scopes to match your proxy endpoint domain
      let finalHeaders = new Headers(response.headers);
      if (finalHeaders.has("Set-Cookie")) {
        const cookies = finalHeaders.get("Set-Cookie");
        const rewrittenCookies = cookies.replace(new RegExp(`domain=\\.?${targetHost}`, 'gi'), `domain=${proxyUrl.hostname}`);
        finalHeaders.set("Set-Cookie", rewrittenCookies);
      }

      // Process streaming HTML DOM translations
      if (contentType.includes("text/html")) {
        // Dynamic JS Patch: Overrides browser navigation APIs on client side execution layers
        const injectionScript = `
          <script>
            (function() {
              const targetHost = "${targetHost}";
              const proxyOrigin = "${proxyOrigin}";
              
              // Intercept dynamic pushState/replaceState layout modifications
              const _pushState = history.pushState;
              const _replaceState = history.replaceState;
              
              history.pushState = function(state, title, url) {
                if (url && url.includes(targetHost)) url = url.replace(targetHost, window.location.host);
                return _pushState.apply(this, [state, title, url]);
              };
              history.replaceState = function(state, title, url) {
                if (url && url.includes(targetHost)) url = url.replace(targetHost, window.location.host);
                return _replaceState.apply(this, [state, title, url]);
              };

              // Re-route dynamically spawned fetch/XHR network sequences
              const _oldFetch = window.fetch;
              window.fetch = function(input, init) {
                if (typeof input === 'string' && input.includes(targetHost)) {
                  input = input.replace('https://' + targetHost, proxyOrigin);
                }
                return _oldFetch(input, init);
              };
            })();
          </script>
        `;

        const rewriter = new HTMLRewriter()
          .on("head", new ElementInjector(injectionScript))
          .on("a", new AttributeRewriter("href", targetHost, proxyOrigin))
          .on("link", new AttributeRewriter("href", targetHost, proxyOrigin))
          .on("form", new AttributeRewriter("action", targetHost, proxyOrigin))
          .on("script", new AttributeRewriter("src", targetHost, proxyOrigin))
          .on("img", new AttributeRewriter("src", targetHost, proxyOrigin));

        const transformedResponse = rewriter.transform(response);
        let htmlResponse = new Response(transformedResponse.body, {
          status: response.status,
          headers: finalHeaders
        });
        htmlResponse.headers.set("Access-Control-Allow-Origin", "*");
        htmlResponse.headers.delete("Content-Security-Policy");
        return htmlResponse;
      }

      return new Response(response.body, { status: response.status, headers: finalHeaders });

    } catch (err) {
      return new Response("Proxy Engine Core Fault: " + err.stack, { status: 500 });
    }
  }
};

class ElementInjector {
  constructor(content) { this.content = content; }
  element(element) { element.prepend(this.content, { html: true }); }
}

class AttributeRewriter {
  constructor(attributeName, targetHost, proxyOrigin) {
    this.attributeName = attributeName;
    this.targetHost = targetHost;
    this.proxyOrigin = proxyOrigin;
  }
  element(element) {
    const attributeValue = element.getAttribute(this.attributeName);
    if (attributeValue) {
      let newValue = attributeValue;
      if (newValue.includes(this.targetHost)) {
        newValue = newValue.replaceAll(`https://${this.targetHost}`, this.proxyOrigin);
        newValue = newValue.replaceAll(`http://${this.targetHost}`, this.proxyOrigin);
      }
      if (newValue.includes("://cloudinary.com")) {
        newValue = newValue.replace(/^https?:\/\/res\.cloudinary\.com/, `${this.proxyOrigin}/__proxy_asset_cloudinary`);
      }
      if (newValue.includes("images.ctfassets.net")) {
        newValue = newValue.replace(/^https?:\/\/images\.ctfassets\.net/, `${this.proxyOrigin}/__proxy_asset_ctfassets`);
      }
      element.setAttribute(this.attributeName, newValue);
    }
  }
}

function createAuthResponse() {
  return new Response('Unauthorized Access', {
    status: 401,
    headers: { 'WWW-Authenticate': 'Basic realm="Secure Gateway Pipeline", charset="UTF-8"' }
  });
}

