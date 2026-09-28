"""
Uçtan uca test için sahte OIDC kimlik sağlayıcı (Keycloak / Entra ID yerine).

Açılışta RSA anahtarı üretir (repoda private key yok). Uçlar:
  GET  /.well-known/openid-configuration   discovery
  GET  /certs                              JWKS (public key)
  POST /mint   {"sub", "preferred_username", "groups", "aud"?, "exp_in"?}  -> {"token": ...}
       Gerçek IdP'nin token ucunun yerine: testler istedikleri kimlikle token alır.
"""
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = os.environ.get("OIDC_ISSUER", "http://mock-oidc:9200")
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
KID = "e2e-1"
JWK = {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key())), "kid": KID, "alg": "RS256", "use": "sig"}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/.well-known/openid-configuration":
            return self._json({"issuer": ISSUER, "jwks_uri": f"{ISSUER}/certs"})
        if self.path == "/certs":
            return self._json({"keys": [JWK]})
        self._json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path != "/mint":
            return self._json({"error": "not found"}, 404)
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])) or b"{}")
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": req.get("aud", "telveguard"), "iat": now,
                  "exp": now + int(req.get("exp_in", 300)),
                  **{k: req[k] for k in ("sub", "preferred_username", "groups") if k in req}}
        self._json({"token": jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": KID})})

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9200), Handler).serve_forever()
