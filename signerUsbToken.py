# [Your existing imports...]
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
    QInputDialog, QLineEdit
)
from PyQt5.QtCore import QTimer
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_der_x509_certificate, ObjectIdentifier
from endesive.pdf import cms
import pkcs11
from pikepdf import Pdf, Dictionary, Array, Name, String

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def auto_detect_pkcs11_lib():
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
    def __init__(self, priv_key, session):
        self._priv = priv_key
        self._session = session

    def sign(self, data: bytes, pad, algorithm) -> bytes:
        mech = pkcs11.Mechanism.SHA256_RSA_PKCS
        return self._priv.sign(data, mechanism=mech)

class SignPDFApp(QWidget):
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
        thread = threading.Thread(target=self.run_http_server, daemon=True)
        thread.start()

    def run_http_server(self):
        server = HTTPServer(('localhost', 8000), MyRequestHandler)
        server.app = self
        server.serve_forever()

    def setup_timer(self):
        self.timer = QTimer()
        self.timer.timeout.connect(self.process_sign_queue)
        self.timer.start(100)

    def process_sign_queue(self):
        while not self.sign_queue.empty():
            ID, input_path, event = self.sign_queue.get()
            if not self.lib_path:
                with self.sign_lock:
                    self.sign_results[ID] = "Library path not configured"
                event.set()
                continue

            pin, ok = QInputDialog.getText(
                self, 'Enter PIN', 'USB Token PIN:', QLineEdit.Password
            )
            if not ok or not pin:
                with self.sign_lock:
                    self.sign_results[ID] = "User cancelled"
                event.set()
                continue

            try:
                self.sign_pdf(input_path, self.lib_path, pin)
                with self.sign_lock:
                    self.sign_results[ID] = input_path
            except Exception as e:
                logging.exception("Signing error")
                with self.sign_lock:
                    self.sign_results[ID] = f"Signing failed: {e}"
            finally:
                event.set()

    def validate_input_pdf(self, path):
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

    def sign_pdf(self, path, lib_path, pin):
        if not self.validate_input_pdf(path):
            raise RuntimeError("Bad PDF structure")

        with open(path, 'rb') as f:
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

        with Pdf.open(path) as pdf:
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
            pw, ph = float(page.MediaBox[2]), float(page.MediaBox[3])
            w, h = 250, 150
            x, y = pw - w - 50, 50
            lines = [
                f"Signed by: {signer_name}", f"Date: {date_str}",
                f"Reason: {opts['reason']}", f"Location: {opts['location']}",
                f"Contact: {opts['contact']}"
            ]
            stm = b"".join([
                b"q\n", b"0.9 0.9 0.9 rg\n", b"0 0 %d %d re f\n" % (w, h),
                b"0 0 0 rg\n", b"1 0 0 1 10 10 cm\n", b"BT\n",
                b"/F1 8 Tf\n", b"12 TL\n", b"10 130 Td\n"
            ] + [
                (b"(" + line.encode('latin1') + b") Tj\n" +
                 (b"T*\n" if i < len(lines)-1 else b""))
                for i, line in enumerate(lines)
            ] + [b"ET\n", b"Q\n"]
            )
            app_stream = pdf.make_stream(stm)
            app_stream.Type = Name.XObject
            app_stream.Subtype = Name.Form
            app_stream.FormType = 1
            app_stream.BBox = Array([0, 0, w, h])
            app_stream.Resources = Dictionary(
                ProcSet=Array([Name.PDF, Name.Text]),
                Font=Dictionary(F1=Dictionary(
                    Type=Name.Font, Subtype=Name.Type1, BaseFont=Name.Helvetica
                ))
            )
            app_ref = pdf.make_indirect(app_stream)
            ap_ref = pdf.make_indirect(Dictionary(N=app_ref))
            annot = Dictionary(
                Type=Name.Annot, Subtype=Name.Widget,
                Rect=Array([x, y, x+w, y+h]), F=4, T=String("Signature1"),
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
            pdf.save(path, linearize=True)

class MyRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != '/sign':
            self.send_response(404)
            self.end_headers()
            return
        ct = self.headers.get('Content-Type', '')
        m = re.match(r'multipart/form-data; boundary=(.+)', ct)
        if not m:
            self.send_error(400, "Invalid content type")
            return
        boundary = m.group(1).encode()
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        parts = body.split(b'--' + boundary)
        for part in parts:
            if b'name="pdf"' in part:
                _, data = part.split(b'\r\n\r\n', 1)
                data = data.rstrip(b'\r\n--')
                with open('input.pdf', 'wb') as f:
                    f.write(data)
                ID = str(uuid.uuid4())
                ev = threading.Event()
                self.server.app.sign_queue.put((ID, 'input.pdf', ev))
                ev.wait()
                with self.server.app.sign_lock:
                    res = self.server.app.sign_results.pop(ID)
                if os.path.isfile(res):
                    with open(res, 'rb') as f:
                        signed = f.read()
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/pdf')
                    self.end_headers()
                    self.wfile.write(signed)
                    os.remove(res)
                else:
                    self.send_response(400)
                    self.send_header('Content-Type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(str(res).encode())
                return
        self.send_response(400)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'No PDF provided')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    win = SignPDFApp()
    win.show()
    sys.exit(app.exec_())
