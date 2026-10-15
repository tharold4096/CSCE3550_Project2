from http.server import BaseHTTPRequestHandler, HTTPServer
import json 
import jwt
from urllib.parse import urlparse, parse_qs
import keys

#Default from assignment
PORT = 8080

#the handling class for JWKS
class JWKSHandler(BaseHTTPRequestHandler):


    #Check if the path passed into this function is known by the server (Used for extraneous commands)
    def known_path(self):
        path = urlparse(self.path).path
        #Return true if known, throw 404 and false if not known
        if path == "/.well-known/jwks.json" or path == "/auth":
            return True
        else:
            self.send_error(404)
            return False

    #Handle GET requests
    def do_GET(self):
        
        
        path = urlparse(self.path).path
        if path == "/.well-known/jwks.json":
            
            body = json.dumps(keys.jwks_wrapper()).encode() #Converts the JWKS to a JSON string and then encodes it to bytes to be sent
            self.send_response(200) #Sends OK
            self.send_header("Content-Type", "application/json") 
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/auth":
            self.send_response(405) #Can't GET on this path, only POST
            self.send_header("Allow", "POST")
            self.end_headers()
        else:
            self.send_error(404) #If the path isn't know, send a 404 error
    def do_POST(self):

        path = urlparse(self.path).path
        if path == "/auth":

            #get the content length
            content_length = int(self.headers.get('Content-Length', 0))

            #Use the content length to eat the body of the request, so that it does not cause issues in parsing later on
            body = self.rfile.read(content_length)

            
            query = parse_qs(urlparse(self.path).query, keep_blank_values=True)
            #CHeck for expired values in query
            expired = "expired" in query


            key = keys.signing_selector(expired)
            if key is None:
                self.send_error(500)
                return

            #encode the JWT with the correct key and return it
            token = jwt.encode(
                {"sub": "userABC", "exp": key.expiry},
                key.private_key,
                algorithm="RS256",
                headers={"kid": key.kid},
            )            
            self.send_response(200) #Send OK
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"token": token}).encode())

        elif path == "/.well-known/jwks.json":
            self.send_response(405)
            self.send_header("Allow", "GET")
            self.end_headers()
            return
        else:
            self.send_error(404)


    #Extraneous methods, all return 405
    def do_PUT(self):
        if self.known_path():
            self.send_error(405)
    def do_DELETE(self):
        if self.known_path():
            self.send_error(405)
    def do_PATCH(self):
        if self.known_path():
            self.send_error(405)
    def do_HEAD(self):
        if self.known_path():
            self.send_error(405)
     
if __name__ == "__main__":
    keys.ensure_keys()
    with HTTPServer(("", PORT), JWKSHandler) as httpd:
        print(f"JWKS server on http://localhost:{PORT}")
        try:
            httpd.serve_forever() #Serve the server until a keyboard interrupt
        except KeyboardInterrupt:
            print("\nStopping web server")




