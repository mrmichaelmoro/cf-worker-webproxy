export default {
  async fetch(request, env, ctx) {
    // 1. Enforce Basic Authentication Security Check
    const authHeader = request.headers.get('Authorization');
    if (!authHeader) return createAuthResponse();

    try {
      const base64Str = authHeader.split(' ')[1]; 
      const decoded = atob(base64Str).split(':');
      if (decoded[0] !== env.PROXY_USER || decoded[1] !== env.PROXY_PASS) {
        return createAuthResponse();
      }
    } catch (err) {
      return createAuthResponse();
    }

    // 2. Parse Incoming Routing States
    const proxyUrl = new URL(request.url);
    const proxyOrigin = proxyUrl.origin;
    
    // Resolve upstream endpoint from configuration
    const targetBase = env.TARGET_URL.replace(/\/$/, ""); 
    const targetHost = new URL(targetBase).hostname;

    let destinationUrl = "";
    let upstreamHost = targetHost;

    // 3. Dynamic Sub-Domain Asset Mapping Layer
    // Maps inbound proxy patterns cleanly to the target asset engines
    if (proxyUrl.pathname.startsWith('/__proxy_asset_cloudinary/')) {
      destinationUrl = "https://cloudinary.com" + proxyUrl.pathname.replace('/__proxy_asset_cloudinary', '') + proxyUrl.search;
      upstreamHost = "://cloudinary.com";
    } else if (proxyUrl.pathname.startsWith('/__proxy_asset_ctfassets/')) {
      destinationUrl = "https://ctfassets.net" + proxyUrl.pathname.replace('/__proxy_asset_ctfassets', '') + proxyUrl.search;
      upstreamHost = "images.ctfassets.net";
    } else {
      // Default to core target host routing
      destinationUrl = targetBase + proxyUrl.pathname + proxyUrl.search;
      upstreamHost = targetHost;
    }

    // 4. Construct Spoofed Upstream Network Request
    let newHeaders = new Headers(request.headers);
    newHeaders.set("Host", upstreamHost);
    newHeaders.set("Referer", `https://${upstreamHost}/`);
    // Mask security identification markers
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

      // Handle transparent HTTP upstream redirect states cleanly
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get("Location");
        if (location) {
          let rewrittenLocation = location;
          if (location.includes(targetHost)) {
            rewrittenLocation = location.replace(`https://${targetHost}`, proxyOrigin);
          } else if (location.startsWith('/')) {
            rewrittenLocation = proxyOrigin + location;
          }
          let redirectResponse = new Response(`Redirecting to ${rewrittenLocation}`, { status: response.status });
          redirectResponse.headers.set("Location", rewrittenLocation);
          return redirectResponse;
        }
      }

      // 5. Streaming DOM Engine Rewriter
      // If payload is HTML, dynamically catch and modify asset strings on the fly
      if (contentType.includes("text/html")) {
        const rewriter = new HTMLRewriter()
          .on("a", new AttributeRewriter("href", targetHost, proxyOrigin))
          .on("link", new AttributeRewriter("href", targetHost, proxyOrigin))
          .on("form", new AttributeRewriter("action", targetHost, proxyOrigin))
          .on("script", new AttributeRewriter("src", targetHost, proxyOrigin))
          // Intercept hardcoded asset subdomains
          .on("img", new AttributeRewriter("src", targetHost, proxyOrigin))
          .on("[src]", new AttributeRewriter("src", targetHost, proxyOrigin))
          .on("[href]", new AttributeRewriter("href", targetHost, proxyOrigin));

        const transformedResponse = rewriter.transform(response);
        let finalResponse = new Response(transformedResponse.body, transformedResponse);
        finalResponse.headers.set("Access-Control-Allow-Origin", "*");
        finalResponse.headers.delete("Content-Security-Policy"); // Drop restriction policies blocking re-routes
        return finalResponse;
      }

      // Return raw structural buffers (JS, images, data vectors) untouched
      let passThroughResponse = new Response(response.body, response);
      passThroughResponse.headers.set("Access-Control-Allow-Origin", "*");
      return passThroughResponse;

    } catch (err) {
      return new Response("Complete Proxy Layer Error: " + err.stack, { status: 500 });
    }
  }
};

// 6. DOM Attribute Parsing Engine
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
      
      // Convert true target links into local proxy points
      if (newValue.includes(this.targetHost)) {
        newValue = newValue.replaceAll(`https://${this.targetHost}`, this.proxyOrigin);
        newValue = newValue.replaceAll(`http://${this.targetHost}`, this.proxyOrigin);
      }
      // Handle cloud asset integrations securely through your worker paths
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
    headers: {
      'WWW-Authenticate': 'Basic realm="Secure Cloud Terminal Access", charset="UTF-8"'
    }
  });
}

