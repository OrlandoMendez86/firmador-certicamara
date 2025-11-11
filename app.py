import sys
import os
import base64
import json
import requests
import hashlib
import copy
import logging
import io  # Necesario para manejar archivos en memoria

from flask import Flask, request, jsonify, render_template, send_file
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pdf_signer.log'),
        logging.StreamHandler(sys.stdout)  # Envia logs a la terminal
    ]
)

# --- INICIALIZACIÓN DE FLASK ---
app = Flask(__name__)

# --- CONSTANTES "QUEMADAS" ---

# 1. Claves de Encriptación 3DES (de tu app original)
KEY_STRING = "94025048109D4EEF11D93737"
IV_STRING = "EEF11D93"

# 2. Credenciales de API de Firma (¡CORREGIDAS! Sacadas de tu pdf_signer.py)
SIGN_URL = "https://7dj9742die.execute-api.us-east-1.amazonaws.com/test/sign/pdf"
SIGN_USER_ID = "CPAETST"
SIGN_PASSWORD = "p4XUiGQzE3DEWoia2/TVQQ=="
SIGN_CONTENT_TYPE = "application/json"

# 3. Credenciales de API de Certificados (Estas ya estaban bien)
CERT_URL = "https://7dj9742die.execute-api.us-east-1.amazonaws.com/test/listCertificate"
CERT_USER_ID = "CPAETST"
CERT_PASSWORD = "p4XUiGQzE3DEWoia2/TVQQ=="


# --- LÓGICA DE NEGOCIO (Encriptación) ---

def encrypt_3des(plain_text):
    """Encriptar texto con 3DES usando el algoritmo de Certicámara"""
    try:
        key_bytes = base64.b64decode(KEY_STRING.encode('utf-8'))
        md5_hash = hashlib.md5(key_bytes).digest()
        key_24_bytes = bytearray(24)
        key_24_bytes[0:16] = md5_hash
        key_24_bytes[16:24] = md5_hash[0:8]
        iv_bytes = IV_STRING.encode('utf-8')
        cipher = DES3.new(bytes(key_24_bytes), DES3.MODE_CBC, iv_bytes)
        plain_bytes = plain_text.encode('utf-8')
        padded_text = pad(plain_bytes, DES3.block_size)
        encrypted_bytes = cipher.encrypt(padded_text)
        encrypted_base64 = base64.b64encode(encrypted_bytes).decode('utf-8')
        logging.info("Texto encriptado con 3DES.")
        return encrypted_base64
    except Exception as e:
        logging.error(f"Error al encriptar con 3DES: {str(e)}")
        raise


# --- RUTAS DE LA APLICACIÓN WEB ---

@app.route("/")
def index():
    """Sirve la página web principal (index.html)"""
    return render_template("index.html")


@app.route("/api/get-certificates", methods=['POST'])
def get_certificates():
    """Endpoint para obtener la lista de seriales."""
    try:
        data = request.json
        nuip = data.get('nuip')
        password = data.get('password')

        if not nuip or not password:
            return jsonify({"error": "Faltan NUIP o password"}), 400

        headers = {
            'userId': CERT_USER_ID,
            'password': CERT_PASSWORD,
            'Content-Type': 'application/json'
        }
        payload = {"nuip": nuip, "password": password}
        
        logging.info(f"Consultando certificados para NUIP: {nuip}")
        response = requests.post(CERT_URL, headers=headers, json=payload, timeout=30)
        
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({"error": "Error del servidor de certificados", "details": response.text}), response.status_code
            
    except Exception as e:
        logging.error(f"Error interno en /api/get-certificates: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/sign-pdf", methods=['POST'])
def sign_pdf_route():
    """Endpoint para firmar el documento (AHORA COMPLETO)"""
    try:
        data = request.form
        files = request.files
        
        if 'pdf_file' not in files or files['pdf_file'].filename == '':
            return jsonify({"error": "No se envió ningún archivo PDF."}), 400
            
        pdf_file = files['pdf_file']
        
        # 1. Leer el archivo PDF y convertirlo a Base64
        pdf_bytes = pdf_file.read()
        file_base64 = base64.b64encode(pdf_bytes).decode('utf-8')
        
        # 2. Encriptar password del usuario
        cert_password = data.get('cert_password')
        encrypted_password = encrypt_3des(cert_password)

        # 3. Construir el payload BASE
        payload = {
            "signReason": "Firma PDF",
            "signLocation": "Colombia",
            "ltv": data.get('ltv') == 'true',
            "verifyDocument": True, # Asumimos esto
            "fileToSignBytes": file_base64,
            "returnSignedFile": True
        }

        # 4. Añadir lógica de Firma Visible (si está marcada)
        if data.get('visibleSign') == 'true':
            if 'image_file' not in files or files['image_file'].filename == '':
                return jsonify({"error": "Firma visible habilitada, pero no se envió imagen."}), 400
            
            image_file = files['image_file']
            image_base64 = base64.b64encode(image_file.read()).decode('utf-8')
            
            pages_text = data.get('pages', '1')
            pages_list = [int(p.strip()) for p in pages_text.split(',') if p.strip().isdigit()]

            payload["visibleSign"] = True
            payload["imageInfo"] = {
                "coordinates": {
                    "lowerLeftX": int(data.get('lowerLeftX', 100)),
                    "lowerLeftY": int(data.get('lowerLeftY', 150)),
                    "upperRightX": int(data.get('upperRightX', 300)),
                    "upperRightY": int(data.get('upperRightY', 230))
                },
                "numPages": pages_list,
                "signFieldName": data.get('signFieldName', 'Firma1'),
                "renderingMode": data.get('renderingMode', 'GRAPHIC_AND_DESCRIPTION'),
                "imageBytes": image_base64,
                "contentSignature": data.get('signatureText', 'Firmado digitalmente')
            }
        else:
            payload["visibleSign"] = False

        # 5. Añadir lógica de Stamp (si está marcada)
        payload["stamp"] = data.get('stamp') == 'true'
        payload["stampInfo"] = {
            "authentication": True, # Hardcodeado de tu app
            "userPassword": True, # Hardcodeado de tu app
            "user": "",
            "password": ""
        }
        if payload["stamp"]:
            stamp_user = data.get('stampUser', '')
            stamp_pass = data.get('stampPass', '')
            if not stamp_user or not stamp_pass:
                return jsonify({"error": "Stamp habilitado, pero faltan usuario o password de Stamp."}), 400
            
            payload["stampInfo"]["user"] = stamp_user
            payload["stampInfo"]["password"] = encrypt_3des(stamp_pass)

        # 6. Añadir lógica de Certitoken (siempre)
        payload["certificateInfo"] = {
            "user": data.get('cert_nuip'),
            "password": encrypted_password,
            "certitoken": True,
            "certitokenInfo": {
                "issuer": "CN=AC SUB 4096 CERTICAMARA, O=CERTICAMARA S.A, OU=NIT 830084433-7, C=CO, ST=DISTRITO CAPITAL, L=BOGOTA, STREET=www.certicamara.com",
                "serial": data.get('cert_serial')
            }
        }
        
        # 7. Llamar al API de Firma (CON CREDENCIALES CORREGIDAS)
        headers = {
            'userId': SIGN_USER_ID,
            'password': SIGN_PASSWORD,
            'Content-Type': SIGN_CONTENT_TYPE
        }
        
        logging.info(f"Enviando payload de firma COMPLETO para serial: {data.get('cert_serial')}")
        response = requests.post(SIGN_URL, headers=headers, json=payload, timeout=120)
        
        if response.status_code != 200:
            logging.error(f"Error del servicio de firma: {response.status_code} - {response.text}")
            return jsonify({"error": "Error del servicio de firma", "details": response.text}), response.status_code

        # 8. Devolver el PDF firmado
        result_json = response.json()
        if 'signedFileBytes' not in result_json:
            logging.error("Respuesta de firma exitosa pero no contiene 'signedFileBytes'")
            return jsonify({"error": "Respuesta de firma no contiene PDF"}), 500

        signed_pdf_bytes = base64.b64decode(result_json['signedFileBytes'])
        
        logging.info("Firma exitosa. Devolviendo archivo PDF.")
        
        return send_file(
            io.BytesIO(signed_pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name='documento_firmado.pdf'
        )

    except Exception as e:
        logging.error(f"Error interno grave en /api/sign-pdf: {str(e)}", exc_info=True)
        return jsonify({"error": f"Error interno del servidor: {str(e)}"}), 500


# --- BLOQUE PARA EJECUTAR EL SERVIDOR ---

# ---
# ¡NUEVO BLOQUE DE SEGURIDAD!
# ---
@app.after_request
def add_security_headers(response):
    """
    Añade cabeceras de seguridad a cada respuesta del servidor.
    Esto soluciona las alertas de OWASP ZAP.
    """
    # Le dice al navegador de dónde puede cargar cosas.
    csp = [
        "default-src 'self'",  # Por defecto, solo confiar en nuestro propio dominio.
        "script-src 'self' https://cdnjs.cloudflare.com", # Permitir scripts de nuestro dominio y de cdnjs (pdf.js)
        "style-src 'self' https://fonts.googleapis.com", # Permitir CSS de nuestro dominio y de Google Fonts
        "font-src 'self' https://fonts.gstatic.com" # Permitir fuentes de nuestro dominio y de Google Fonts
    ]
    response.headers['Content-Security-Policy'] = "; ".join(csp)
    
    # 2. Prevenir Clickjacking (Falta de cabecera Anti-Clickjacking)
    # Impide que la app sea metida en un <iframe> en otro sitio.
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    
    # 3. Prevenir que el navegador "adivine" el tipo de archivo
    # (Soluciona X-Content-Type-Options)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # 4. Otras cabeceras de seguridad recomendadas
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    return response

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)

    app.run(host='0.0.0.0', port=5000, debug=True)
