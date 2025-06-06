import sys
import os
import tempfile
import logging
import threading
import queue
import uuid
import re
import platform
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QLabel, QVBoxLayout,
    QInputDialog, QLineEdit, QMessageBox
)
from PyQt5.QtCore import QTimer
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_der_x509_certificate, ObjectIdentifier
from endesive.pdf import cms
import pkcs11
from pikepdf import Pdf, Dictionary, Array, Name, String
from io import BytesIO
import json

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def auto_detect_pkcs11_lib():
    """Auto-detect PKCS#11 library based on the operating system."""
    system = platform.system()
    common_paths = []
    if system == 'Linux':
        common_paths = [
            '/usr/lib/libykcs11.so',
            '/usr/lib/x86_64-linux-gnu/libpkcs11.so',
            '/usr/lib64/libeTPkcs11.so',
            '/usr/local/lib/libopensc-pkcs11.so',
            '/usr/lib/libsofthsm2.so'
        ]
    elif system == 'Windows':
        common_paths = [
            'C:\\Windows\\System32\\ykcs11.dll',
            'C:\\Windows\\System32\\opensc-pkcs11.dll',
            'C:\\Program Files\\Safenet\\eToken\\PKCS11.dll',
        ]
    elif system == 'Darwin':
        common_paths = [
            '/Library/OpenSC/lib/opensc-pkcs11.so',
            '/usr/local/lib/libykcs11.dylib',
        ]
    for path in common_paths:
        if os.path.isfile(path):
            logging.info(f"Auto-detected PKCS#11 library at: {path}")
            return path
    logging.warning("PKCS#11 library not auto-detected")
    return None

class PKCS11PrivateKey:
    """Wrapper for PKCS#11 private key to provide signing functionality."""
    def __init__(self, priv_key, session):
        self._priv = priv_key
        self._session = session

    def sign(self, data: bytes, pad, algorithm) -> bytes:
        mech = pkcs11.Mechanism.SHA256_RSA_PKCS
        return self._priv.sign(data, mechanism=mech)

class SignPDFApp(QWidget):
    """Main application class for PDF signing with a GUI and HTTP server."""
    def __init__(self):
        super().__init__()
        self.sign_queue = queue.Queue()
        self.sign_results = {}
        self.sign_lock = threading.Lock()
        self.lib_path = auto_detect_pkcs11_lib()
        self.initUI()
        self.start_http_server()
        self.setup_timer()

    def initUI(self):
        """Initialize the GUI."""
        self.setWindowTitle('USB Token PDF Signer')
        self.setGeometry(300, 300, 350, 300)
        layout = QVBoxLayout()
        self.status_label = QLabel('Status: Ready')
        if self.lib_path:
            self.status_label.setText(f'Auto-detected library path:\n{self.lib_path}')
        layout.addWidget(self.status_label)
        self.config_btn = QPushButton('Configure Library Path')
        self.config_btn.clicked.connect(self.configureLibPath)
        layout.addWidget(self.config_btn)
        self.setLayout(layout)

    def configureLibPath(self):
        """Prompt user to configure the PKCS#11 library path."""
        path, ok = QInputDialog.getText(
            self,
            'Enter PKCS#11 Library Path',
            'Full path to your .so/.dll/.dylib:',
            QLineEdit.Normal,
            self.lib_path or ''
        )
        if ok and path:
            if os.path.isfile(path):
                self.lib_path = path
                self.status_label.setText(f'Library path set to:\n{path}')
                logging.info(f"Library path set to: {path}")
            else:
                self.status_label.setText('Invalid path—file not found')
                logging.warning(f"User provided invalid path: {path}")

    def start_http_server(self):
        """Start the HTTP server in a separate thread."""
        thread = threading.Thread(target=self.run_http_server, daemon=True)
        thread.start()

    def run_http_server(self):
        """Run the HTTP server."""
        server = HTTPServer(('localhost', 8000), MyRequestHandler)
        server.app = self
        server.serve_forever()

    def setup_timer(self):
        """Set up a timer to process the signing queue."""
        self.timer = QTimer()
        self.timer.timeout.connect(self.process_sign_queue)
        self.timer.start(100)

    def process_sign_queue(self):
        """Process items in the signing queue."""
        while not self.sign_queue.empty():
            ID, input_path, original_path, pin, event = self.sign_queue.get()
            if not self.lib_path:
                with self.sign_lock:
                    self.sign_results[ID] = ("Library path not configured", None)
                event.set()
                continue
            if not pin:
                with self.sign_lock:
                    self.sign_results[ID] = ("PIN not provided in POST request", None)
                event.set()
                continue
            try:
                result = self.sign_pdf(input_path, self.lib_path, pin, original_path)
                with self.sign_lock:
                    if original_path:
                        self.sign_results[ID] = ("Success", original_path)
                    else:
                        self.sign_results[ID] = ("Success", result)
            except Exception as e:
                logging.exception("Signing error")
                with self.sign_lock:
                    self.sign_results[ID] = (f"Signing failed: {e}", None)
            finally:
                event.set()

    def validate_input_pdf(self, path):
        """Validate the structure of the input PDF."""
        try:
            with Pdf.open(path) as pdf:
                pages = pdf.Root['/Pages']
                assert '/Kids' in pages and pages['/Kids']
                assert '/Count' in pages and pages['/Count'] > 0
            logging.info("Input PDF validation passed")
            return True
        except Exception as e:
            logging.error(f"Validation error: {e}")
            return False

    def sign_pdf(self, input_path, lib_path, pin, original_path=None):
        """Sign the PDF and optionally save to original_path."""
        if not self.validate_input_pdf(input_path):
            raise RuntimeError("Bad PDF structure")
        with open(input_path, 'rb') as f:
            pdf_bytes = f.read()

        lib = pkcs11.lib(lib_path)
        slots = lib.get_slots(token_present=True)
        if not slots:
            raise RuntimeError("No USB token detected.")
        with slots[0].get_token().open(user_pin=pin) as session:
            priv_obj = next(session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
                pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.RSA,
                pkcs11.Attribute.SIGN: True,
                pkcs11.Attribute.ID: b'\x01',
            }), None)
            cert_obj = next(session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.CERTIFICATE,
                pkcs11.Attribute.CERTIFICATE_TYPE: pkcs11.CertificateType.X_509,
                pkcs11.Attribute.ID: b'\x01',
            }), None)
            cert = load_der_x509_certificate(cert_obj[pkcs11.Attribute.VALUE], default_backend())
            key = PKCS11PrivateKey(priv_obj, session)
            attrs = cert.subject.get_attributes_for_oid(ObjectIdentifier('2.5.4.3'))
            signer_name = attrs[0].value if attrs else 'Unknown'
            now = datetime.now(timezone.utc)
            date_str = now.strftime("%d/%m/%Y")

            opts = {
                'signingdate': now.strftime("%Y%m%d%H%M%S+00'00'"),
                'reason': 'Digitally signed',
                'location': 'My Location',
                'contact': 'me@example.com',
            }

            sig = cms.sign(pdf_bytes, opts, key, cert, [], 'sha256')

        with Pdf.open(input_path, allow_overwriting_input=True) as pdf:
            placeholder = b'0' * (len(sig) * 2)
            br = [0, 0, len(pdf_bytes), len(sig)]

            sig_dict = Dictionary(
                Type=Name.Sig, Filter=Name.Adobe_PPKLite,
                SubFilter=Name.adbe_pkcs7_detached,
                ByteRange=Array(br), Contents=String(placeholder),
                Reason=String(opts['reason']), M=String(opts['signingdate']),
                Location=String(opts['location']), ContactInfo=String(opts['contact']),
            )
            sig_ref = pdf.make_indirect(sig_dict)

            page = pdf.pages[0]

            # Prepare visible signature text
            lines = [
                f"Signed by: {signer_name}",
                f"Date: {date_str}"
            ]

            # Estimate box size based on text content with added padding
            char_width = 6  # Rough average character width
            line_height = 14  # Line spacing
            text_width = max(len(line) for line in lines) * char_width + 20
            text_height = len(lines) * line_height + 20  # Increased padding (+10 top, +10 bottom)

            # Create appearance stream (no background box)
            stm = b"".join([
                b"q\n",
                b"1 0 0 1 10 10 cm\n",  # Translate to leave left/bottom padding
                b"BT\n",
                b"/F1 8 Tf\n",  # Font size 8
                f"{line_height} TL\n".encode(),  # Line spacing
                f"10 {text_height - line_height - 10} Td\n".encode()  # Move text down by 10 units
            ] + [
                (f"({line}) Tj\n".encode('latin1') +
                 (b"T*\n" if i < len(lines) - 1 else b""))
                for i, line in enumerate(lines)
            ] + [b"ET\n", b"Q\n"]
            )

            app_stream = pdf.make_stream(stm)
            app_stream.Type = Name.XObject
            app_stream.Subtype = Name.Form
            app_stream.FormType = 1
            app_stream.BBox = Array([0, 0, text_width, text_height])
            app_stream.Resources = Dictionary(
                ProcSet=Array([Name.PDF, Name.Text]),
                Font=Dictionary(F1=Dictionary(
                    Type=Name.Font, Subtype=Name.Type1, BaseFont=Name.Helvetica
                ))
            )
            app_ref = pdf.make_indirect(app_stream)
            ap_ref = pdf.make_indirect(Dictionary(N=app_ref))

            # Position of the visible signature on the page
            x, y = 400, 80  # Adjust as needed

            annot = Dictionary(
                Type=Name.Annot, Subtype=Name.Widget,
                Rect=Array([x, y, x + text_width, y + text_height]),
                F=4, T=String("Signature1"),
                FT=Name.Sig, V=sig_ref, DA=String("/F1 8 Tf 0 g"), AP=ap_ref
            )
            annot_ref = pdf.make_indirect(annot)

            page['/Annots'] = page.get('/Annots', Array())
            page['/Annots'].append(annot_ref)

            dr = Dictionary(Font=Dictionary(
                F1=Dictionary(Type=Name.Font, Subtype=Name.Type1, BaseFont=Name.Helvetica)
            ))

            pdf.Root['/AcroForm'] = pdf.make_indirect(Dictionary(
                SigFlags=3, Fields=Array([annot_ref]), DA=String("/F1 8 Tf 0 g"),
                DR=dr, NeedAppearances=False
            ))

            if original_path:
                pdf.save(original_path, linearize=True)
                if input_path != original_path and os.path.isfile(input_path):
                    os.remove(input_path)
                return original_path
            else:
                output = BytesIO()
                pdf.save(output, linearize=True)
                if os.path.isfile(input_path):
                    os.remove(input_path)
                return output.getvalue()

    def get_certificates(self, pin):
        """Retrieve a list of certificates from the USB token."""
        if not self.lib_path:
            raise RuntimeError("Library path not configured")
        lib = pkcs11.lib(self.lib_path)
        slots = lib.get_slots(token_present=True)
        if not slots:
            raise RuntimeError("No USB token detected")
        with slots[0].get_token().open(user_pin=pin) as session:
            cert_objects = session.get_objects({
                pkcs11.Attribute.CLASS: pkcs11.ObjectClass.CERTIFICATE,
                pkcs11.Attribute.CERTIFICATE_TYPE: pkcs11.CertificateType.X_509,
            })
            certificates = []
            for cert_obj in cert_objects:
                cert_der = cert_obj[pkcs11.Attribute.VALUE]
                cert = load_der_x509_certificate(cert_der, default_backend())
                certificates.append({
                    'serial_number': str(cert.serial_number),  # Convert to string for JSON compatibility
                    'expiration_date': cert.not_valid_after.isoformat(),  # Add expiration date
                    'certifying_authority': cert.issuer.rfc4514_string() 
                })
            return certificates

class MyRequestHandler(BaseHTTPRequestHandler):
    """Handle HTTP requests for PDF signing."""
    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_POST(self):
        """Handle POST requests for signing PDFs or retrieving certificates."""
        if self.path == '/sign':
            # Existing /sign endpoint code remains unchanged
            ct = self.headers.get('Content-Type', '')
            m = re.match(r'multipart/form-data; boundary=(.+)', ct)
            if not m:
                self.send_response(400)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'Invalid content type')
                return
            boundary = m.group(1).encode()
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)
            parts = body.split(b'--' + boundary)
            pdf_data = None
            original_path = None
            pin = None
            for part in parts:
                if b'name="pdf"' in part:
                    _, pdf_data = part.split(b'\r\n\r\n', 1)
                    pdf_data = pdf_data.rstrip(b'\r\n--')
                if b'name="original_path"' in part:
                    _, original_path_data = part.split(b'\r\n\r\n', 1)
                    original_path = original_path_data.rstrip(b'\r\n--').decode('utf-8')
                if b'name="pin"' in part:
                    _, pin_data = part.split(b'\r\n\r\n', 1)
                    pin = pin_data.rstrip(b'\r\n--').decode('utf-8')
            if not pdf_data:
                self.send_response(400)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'No PDF provided')
                return
            input_path = os.path.join(tempfile.gettempdir(), f'pdf_{uuid.uuid4()}.pdf')
            with open(input_path, 'wb') as f:
                f.write(pdf_data)
            ID = str(uuid.uuid4())
            ev = threading.Event()
            self.server.app.sign_queue.put((ID, input_path, original_path, pin, ev))
            ev.wait()
            with self.server.app.sign_lock:
                status, result = self.server.app.sign_results.pop(ID)
            if status == "Success":
                if isinstance(result, str) and os.path.isfile(result):
                    with open(result, 'rb') as f:
                        signed = f.read()
                else:
                    signed = result
                self.send_response(200)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Content-Type', 'application/pdf')
                self.end_headers()
                self.wfile.write(signed)
            else:
                self.send_response(400)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(status.encode())
                if os.path.isfile(input_path):
                    os.remove(input_path)

        elif self.path == '/certificates':
            # New /certificates endpoint
            ct = self.headers.get('Content-Type', '')
            m = re.match(r'multipart/form-data; boundary=(.+)', ct)
            if not m:
                self.send_response(400)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'Invalid content type')
                return
            boundary = m.group(1).encode()
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)
            parts = body.split(b'--' + boundary)
            pin = None
            for part in parts:
                if b'name="pin"' in part:
                    _, pin_data = part.split(b'\r\n\r\n', 1)
                    pin = pin_data.rstrip(b'\r\n--').decode('utf-8')
            if not pin:
                self.send_response(400)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'PIN not provided')
                return
            try:
                certificates = self.server.app.get_certificates(pin)
                self.send_response(200)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(certificates).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(f"Error: {e}".encode())
        else:
            self.send_response(404)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

    def do_GET(self):
        """Handle GET requests for health check."""
        if self.path == '/':
            self.send_response(200)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK')
        else:
            self.send_response(404)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    win = SignPDFApp()
    win.show()
    sys.exit(app.exec_())