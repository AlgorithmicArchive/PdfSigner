import sys
import warnings
import os
import tempfile
import logging
from datetime import datetime, timezone
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QLabel,
    QFileDialog, QLineEdit, QVBoxLayout, QRadioButton
)
from endesive.pdf import cms
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_der_x509_certificate, ObjectIdentifier
from pikepdf import Pdf, Dictionary, Array, Name, String
import pkcs11

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
try:
    from PyPDF2.errors import PdfReadWarning
except ImportError:
    from PyPDF2.utils import PdfReadWarning

warnings.filterwarnings(
    'ignore',
    message='Xref table not zero-indexed.*',
    category=PdfReadWarning
)

class PKCS11PrivateKey:
    def __init__(self, priv_key, session):
        self._priv = priv_key
        self._session = session  # Keep session reference to prevent closure

    def sign(self, data: bytes, pad, algorithm) -> bytes:
        mech = pkcs11.Mechanism.SHA256_RSA_PKCS
        return self._priv.sign(data, mechanism=mech)

class SignPDFApp(QWidget):
    def __init__(self):
        super().__init__()
        self.pdf_path = None
        self.dsc_path = None
        self.sign_method = 'certificate_file'
        self.initUI()

    def initUI(self):
        self.setWindowTitle('PDF Signer')
        self.setGeometry(300, 300, 350, 350)
        layout = QVBoxLayout()

        self.cert_radio = QRadioButton('Certificate File')
        self.usb_radio = QRadioButton('USB Token')
        self.cert_radio.setChecked(True)
        self.cert_radio.toggled.connect(self.update_ui)
        self.usb_radio.toggled.connect(self.update_ui)
        layout.addWidget(self.cert_radio)
        layout.addWidget(self.usb_radio)

        self.pdf_btn = QPushButton('Select PDF')
        self.pdf_btn.clicked.connect(self.selectPDF)
        layout.addWidget(self.pdf_btn)

        # Certificate File fields
        self.dsc_btn = QPushButton('Select DSC (.p12/.pfx)')
        self.dsc_btn.clicked.connect(self.selectDSC)
        layout.addWidget(self.dsc_btn)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText('DSC Password')
        layout.addWidget(self.password_input)

        # USB Token fields
        self.lib_input = QLineEdit()
        self.lib_input.setPlaceholderText('PKCS#11 Library Path (e.g., /usr/lib/libsofthsm2.so)')
        self.lib_input.setText('/usr/lib/libsofthsm2.so')
        layout.addWidget(self.lib_input)
        self.pin_input = QLineEdit()
        self.pin_input.setEchoMode(QLineEdit.Password)
        self.pin_input.setPlaceholderText('USB Token PIN')
        layout.addWidget(self.pin_input)

        self.sign_btn = QPushButton('Sign PDF')
        self.sign_btn.clicked.connect(self.signPDF)
        layout.addWidget(self.sign_btn)

        self.status_label = QLabel('Status: Ready')
        layout.addWidget(self.status_label)

        self.setLayout(layout)
        self.update_ui()

    def update_ui(self):
        if self.cert_radio.isChecked():
            self.sign_method = 'certificate_file'
            self.dsc_btn.setVisible(True)
            self.password_input.setVisible(True)
            self.lib_input.setVisible(False)
            self.pin_input.setVisible(False)
        elif self.usb_radio.isChecked():
            self.sign_method = 'usb_token'
            self.dsc_btn.setVisible(False)
            self.password_input.setVisible(False)
            self.lib_input.setVisible(True)
            self.pin_input.setVisible(True)

    def selectPDF(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Select PDF', '', 'PDF Files (*.pdf)')
        if path:
            self.pdf_path = path
            self.status_label.setText(f'Selected PDF: {os.path.basename(path)}')

    def selectDSC(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Select DSC', '', 'PKCS#12 Files (*.p12 *.pfx)')
        if path:
            self.dsc_path = path
            self.status_label.setText(f'Selected DSC: {os.path.basename(path)}')

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

    def signPDF(self):
        if not self.pdf_path:
            self.status_label.setText('Select PDF first.')
            return

        if self.sign_method == 'certificate_file':
            if not self.dsc_path or not self.password_input.text().strip():
                self.status_label.setText('Select DSC and enter password.')
                return
        elif self.sign_method == 'usb_token':
            lib_path = self.lib_input.text().strip()
            if not lib_path or not os.path.exists(lib_path) or not self.pin_input.text().strip():
                self.status_label.setText('Enter valid library path and PIN.')
                return

        try:
            if not self.validate_input_pdf(self.pdf_path):
                raise RuntimeError("Bad PDF structure")

            with open(self.pdf_path, 'rb') as f:
                pdf_bytes = f.read()

            if self.sign_method == 'certificate_file':
                with open(self.dsc_path, 'rb') as f:
                    p12 = f.read()
                pw = self.password_input.text().strip()
                key, cert, add_certs = pkcs12.load_key_and_certificates(
                    p12, pw.encode(), default_backend()
                )
            elif self.sign_method == 'usb_token':
                lib_path = self.lib_input.text().strip()
                pin = self.pin_input.text().strip()
                lib = pkcs11.lib(lib_path)
                slots = lib.get_slots(token_present=True)
                if not slots:
                    self.status_label.setText('No USB token detected.')
                    return
                slot = slots[0]
                token = slot.get_token()
                with token.open(user_pin=pin) as session:
                    priv_obj = next(session.get_objects({
                        pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
                        pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.RSA,
                        pkcs11.Attribute.SIGN: True,
                        pkcs11.Attribute.ID: b'\x01',
                    }), None)
                    if not priv_obj:
                        raise RuntimeError("No private key found.")
                    cert_obj = next(session.get_objects({
                        pkcs11.Attribute.CLASS: pkcs11.ObjectClass.CERTIFICATE,
                        pkcs11.Attribute.CERTIFICATE_TYPE: pkcs11.CertificateType.X_509,
                        pkcs11.Attribute.ID: b'\x01',
                    }), None)
                    if not cert_obj:
                        raise RuntimeError("No certificate found.")
                    cert = load_der_x509_certificate(
                        cert_obj[pkcs11.Attribute.VALUE], default_backend()
                    )
                    key = PKCS11PrivateKey(priv_obj, session)
                    add_certs = []
                    # Perform signing while session is still open
                    signer_name = 'Unknown'
                    if cert:
                        attrs = cert.subject.get_attributes_for_oid(ObjectIdentifier('2.5.4.3'))
                        if attrs:
                            signer_name = attrs[0].value
                    logging.debug(f"Signer name: {signer_name}")

                    now = datetime.now(timezone.utc)
                    date_str = now.strftime("%d/%m/%Y")
                    opts = {
                        'signingdate': now.strftime("%Y%m%d%H%M%S+00'00'"),
                        'reason': 'Digitally signed',
                        'location': 'My Location',
                        'contact': 'me@example.com',
                    }
                    sig = cms.sign(pdf_bytes, opts, key, cert, add_certs or [], 'sha256')

            if self.sign_method == 'certificate_file':
                signer_name = 'Unknown'
                if cert:
                    attrs = cert.subject.get_attributes_for_oid(ObjectIdentifier('2.5.4.3'))
                    if attrs:
                        signer_name = attrs[0].value
                logging.debug(f"Signer name: {signer_name}")

                now = datetime.now(timezone.utc)
                date_str = now.strftime("%d/%m/%Y")
                opts = {
                    'signingdate': now.strftime("%Y%m%d%H%M%S+00'00'"),
                    'reason': 'Digitally signed',
                    'location': 'My Location',
                    'contact': 'me@example.com',
                }
                sig = cms.sign(pdf_bytes, opts, key, cert, add_certs or [], 'sha256')

            with Pdf.open(self.pdf_path) as pdf:
                placeholder = b'0' * (len(sig) * 2)
                br = [0, 0, len(pdf_bytes), len(sig)]
                sig_dict = Dictionary(
                    Type=Name.Sig,
                    Filter=Name.Adobe_PPKLite,
                    SubFilter=Name.adbe_pkcs7_detached,
                    ByteRange=Array(br),
                    Contents=String(placeholder),
                    Reason=String(opts['reason']),
                    M=String(opts['signingdate']),
                    Location=String(opts['location']),
                    ContactInfo=String(opts['contact']),
                )
                sig_ref = pdf.make_indirect(sig_dict)

                page = pdf.pages[0]
                media = page.MediaBox
                pw, ph = float(media[2]), float(media[3])
                w, h = 250, 150
                x, y = pw - w - 50, 50

                lines = [
                    f"Signed by: {signer_name}",
                    f"Date: {date_str}",
                    f"Reason: {opts['reason']}",
                    f"Location: {opts['location']}",
                    f"Contact: {opts['contact']}"
                ]
                stm_parts = [
                    b"q\n", b"0.9 0.9 0.9 rg\n",
                    b"0 0 %d %d re f\n" % (w, h), b"0 0 0 rg\n",
                    b"1 0 0 1 10 10 cm\n", b"BT\n",
                    b"/F1 8 Tf\n", b"12 TL\n", b"10 130 Td\n"
                ]
                for i, line in enumerate(lines):
                    stm_parts.append(b"(" + line.encode('latin1') + b") Tj\n")
                    if i < len(lines) - 1:
                        stm_parts.append(b"T*\n")
                stm_parts.extend([b"ET\n", b"Q\n"])
                stm = b''.join(stm_parts)

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

                ap = Dictionary(N=app_ref)
                ap_ref = pdf.make_indirect(ap)

                annot = Dictionary(
                    Type=Name.Annot, Subtype=Name.Widget,
                    Rect=Array([x, y, x + w, y + h]), F=4,
                    T=String("Signature1"), FT=Name.Sig,
                    V=sig_ref, DA=String("/F1 8 Tf 0 g"), AP=ap_ref
                )
                annot_ref = pdf.make_indirect(annot)
                if '/Annots' not in page:
                    page['/Annots'] = pdf.make_indirect(Array([]))
                page['/Annots'].append(annot_ref)

                dr = Dictionary(Font=Dictionary(
                    F1=Dictionary(Type=Name.Font, Subtype=Name.Type1, BaseFont=Name.Helvetica)
                ))
                pdf.Root['/AcroForm'] = pdf.make_indirect(Dictionary(
                    SigFlags=3, Fields=Array([annot_ref]), DA=String("/F1 8 Tf 0 g"),
                    DR=dr, NeedAppearances=False
                ))

                with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmpf:
                    tmp_name = tmpf.name
                    pdf.save(tmp_name, linearize=True)

            with open(tmp_name, 'rb') as f:
                data = f.read()
            final = data.replace(placeholder, sig.hex().encode('ascii'))
            out_path = self.pdf_path.replace('.pdf', '_signed.pdf')
            with open(out_path, 'wb') as f:
                f.write(final)
            os.remove(tmp_name)

            self.status_label.setText(f'Signed PDF saved: {out_path}')

        except Exception as e:
            logging.error("Signing failed:", exc_info=True)
            self.status_label.setText(f'Error: {e}')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    win = SignPDFApp()
    win.show()
    sys.exit(app.exec_())