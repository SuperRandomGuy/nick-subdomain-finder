from flask import Flask, render_template, Response
import json
import time
from subdomain_finder import find_subdomains_iterative

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/stream_search/<domain>')
def stream_search(domain):
    def generate():
        # On utilise le générateur défini dans subdomain_finder.py
        for progress_data in find_subdomains_iterative(domain):
            # Format Server-Sent Events (SSE)
            # data: <json>\n\n
            yield f"data: {json.dumps(progress_data)}\n\n"
            
    return Response(generate(), mimetype='text/event-stream')

if __name__ == '__main__':
    print("Lancement du serveur web...")
    print("Ouvrez votre navigateur à l'adresse : http://127.0.0.1:5000")
    app.run(debug=True, threaded=True)
