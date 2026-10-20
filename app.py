import os
import io
import hmac
import hashlib
import json
import math
import secrets
import shutil
import subprocess
import threading
import time
import uuid
from functools import wraps
from urllib.error import HTTPError, URLError
from urllib.request import Request as UrlRequest, urlopen
import win32api
import win32print
import win32con
import qrcode
import pymupdf as fitz
from PIL import Image, ImageChops, ImageEnhance, ImageOps
from flask import Flask, request, render_template, redirect, url_for, jsonify, session, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from urllib.parse import quote
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
os.makedirs(app.instance_path, exist_ok=True)
SECRET_KEY_FILE = os.path.join(app.instance_path, 'flask_secret_key')
secret_key = os.environ.get('FLASK_SECRET_KEY')
if not secret_key:
    if os.path.isfile(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, encoding='utf-8') as secret_file:
            secret_key = secret_file.read().strip()
    else:
        secret_key = secrets.token_urlsafe(48)
        try:
            with open(SECRET_KEY_FILE, 'x', encoding='utf-8') as secret_file:
                secret_file.write(secret_key)
        except FileExistsError:
            with open(SECRET_KEY_FILE, encoding='utf-8') as secret_file:
                secret_key = secret_file.read().strip()
app.secret_key = secret_key
PUBLIC_MODE = os.environ.get('PUBLIC_MODE', '').casefold() in ('1', 'true', 'yes')
PASSWORD_HASH_FILE = os.path.join(app.instance_path, 'admin_password.hash')
if os.path.isfile(PASSWORD_HASH_FILE):
    with open(PASSWORD_HASH_FILE, encoding='utf-8') as password_file:
        configured_password_hash = password_file.read().strip()
else:
    configured_password_hash = os.environ.get('ADMIN_PASSWORD_HASH', '')
app.config.update(
    ADMIN_EMAIL='sakshistudio2026@gmail.com',
    ADMIN_PASSWORD_HASH=configured_password_hash,
    ADMIN_PHONE_NUMBER=os.environ.get('ADMIN_PHONE_NUMBER', '7277244243'),
    WHATSAPP_ACCESS_TOKEN=os.environ.get('WHATSAPP_ACCESS_TOKEN', ''),
    WHATSAPP_PHONE_NUMBER_ID=os.environ.get('WHATSAPP_PHONE_NUMBER_ID', ''),
    WHATSAPP_OTP_TEMPLATE=os.environ.get('WHATSAPP_OTP_TEMPLATE', ''),
    WHATSAPP_TEMPLATE_LANGUAGE=os.environ.get('WHATSAPP_TEMPLATE_LANGUAGE', 'en_US'),
    WHATSAPP_GRAPH_API_VERSION=os.environ.get('WHATSAPP_GRAPH_API_VERSION', 'v22.0'),
    MAX_CONTENT_LENGTH=50 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=PUBLIC_MODE,
    WTF_CSRF_TIME_LIMIT=60 * 60,
)
if PUBLIC_MODE:
    app.config['PREFERRED_URL_SCHEME'] = 'https'
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    if not app.config['ADMIN_PASSWORD_HASH']:
        raise RuntimeError('PUBLIC_MODE requires an admin password configured before startup.')
    if check_password_hash(app.config['ADMIN_PASSWORD_HASH'], 'Admin@12345'):
        raise RuntimeError('Change the temporary admin password before enabling PUBLIC_MODE.')
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=[])

@app.after_request
def add_security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    if PUBLIC_MODE and request.is_secure:
        response.headers.setdefault('Strict-Transport-Security', 'max-age=15552000')
    return response

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

# पेंडिंग प्रिंट रिक्वेस्ट स्टोर करने के लिए (Cash Requests)
pending_requests = []
request_id_counter = 1
PAYMENT_TIMEOUT_SECONDS = 5 * 60
PRINTED_UPLOAD_CLEANUP_DELAY_SECONDS = 60
PAPER_SIZES = {
    'A4': (595.28, 841.89),
    'A5': (419.53, 595.28),
    'Letter': (612, 792),
}
AADHAAR_CARD_SIZE = (85.6 * 72 / 25.4, 54 * 72 / 25.4)
RECOVERY_OTP_LIFETIME_SECONDS = 5 * 60
RECOVERY_OTP_RESEND_SECONDS = 60
RECOVERY_OTP_MAX_ATTEMPTS = 5
recovery_send_times = {}
recovery_challenges = {}
recovery_send_lock = threading.Lock()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_document_images(filepath, first_page_only=False, page_index=0):
    if filepath.lower().endswith('.pdf'):
        with fitz.open(filepath) as document:
            if first_page_only:
                if page_index >= document.page_count:
                    return
                page_numbers = (page_index,)
            else:
                page_numbers = range(document.page_count)
            for page_number in page_numbers:
                pixmap = document[page_number].get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
                yield Image.open(io.BytesIO(pixmap.tobytes('png'))).convert('RGB')
    else:
        with Image.open(filepath) as source:
            yield ImageOps.exif_transpose(source).convert('RGB')

def crop_and_adjust_image(image, crop_mode, margins, lighting_mode, brightness):
    if crop_mode == 'manual':
        top, right, bottom, left = margins
        width, height = image.size
        box = (
            round(width * left / 100),
            round(height * top / 100),
            width - round(width * right / 100),
            height - round(height * bottom / 100),
        )
        if box[2] <= box[0] or box[3] <= box[1]:
            raise ValueError('Crop margins bahut zyada hain.')
        image = image.crop(box)
    else:
        grayscale = ImageOps.grayscale(image)
        foreground = grayscale.point(lambda value: 255 if value < 245 else 0)
        bounds = foreground.getbbox()
        if bounds:
            left, top, right, bottom = bounds
            margin_x = round((right - left) * 0.015)
            margin_y = round((bottom - top) * 0.015)
            image = image.crop((
                max(0, left - margin_x),
                max(0, top - margin_y),
                min(image.width, right + margin_x),
                min(image.height, bottom + margin_y),
            ))

    if lighting_mode == 'auto':
        image = ImageOps.autocontrast(image, cutoff=1)
        image = ImageEnhance.Contrast(image).enhance(1.05)
    else:
        image = ImageEnhance.Brightness(image).enhance(brightness)
    return image

def render_print_pdf(
    front_path,
    paper_size,
    crop_mode,
    margins,
    lighting_mode,
    brightness,
    back_path=None,
    aadhaar_pair=False,
    back_adjustments=None,
    aadhaar_vertical_offset=0,
    aadhaar_horizontal_offset=0,
    id_card_a4=False,
    a4_custom_layout=False,
    a4_layout_x=0,
    a4_layout_y=0,
    a4_layout_width=0,
    a4_layout_height=0,
    image_a4=False,
    image_a4_x=0,
    image_a4_y=0,
    image_a4_width=0,
    image_a4_height=0,
):
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{uuid.uuid4().hex}_print.pdf")
    page_width, page_height = PAPER_SIZES[paper_size]
    output = fitz.open()
    try:
        if aadhaar_pair or id_card_a4:
            if aadhaar_pair and back_path:
                front = next(get_document_images(front_path, first_page_only=True))
                back = next(get_document_images(back_path, first_page_only=True))
            elif aadhaar_pair:
                if not front_path.lower().endswith('.pdf'):
                    raise ValueError('Aadhaar pair ke liye back image ya 2-page PDF chahiye.')
                with fitz.open(front_path) as document:
                    if document.page_count < 2:
                        raise ValueError('Aadhaar PDF mein front/back ke 2 pages hone chahiye.')
                front = next(get_document_images(front_path, first_page_only=True, page_index=0))
                back = next(get_document_images(front_path, first_page_only=True, page_index=1))
            else:
                front = next(get_document_images(front_path, first_page_only=True))

            back_crop_mode, back_margins, back_lighting_mode, back_brightness = back_adjustments or (
                crop_mode,
                margins,
                lighting_mode,
                brightness,
            )
            images = [crop_and_adjust_image(front, crop_mode, margins, lighting_mode, brightness)]
            if aadhaar_pair:
                images.append(crop_and_adjust_image(back, back_crop_mode, back_margins, back_lighting_mode, back_brightness))
            card_width, card_height = AADHAAR_CARD_SIZE
            gap = 8
            if a4_custom_layout:
                layout_width = a4_layout_width
                layout_height = a4_layout_height
                card_width = (layout_width - gap * (len(images) - 1)) / len(images)
                pair_x = a4_layout_x
                card_y = a4_layout_y
            else:
                pair_width = card_width * len(images) + gap * (len(images) - 1)
                pair_x = (page_width - pair_width) / 2 + int(aadhaar_horizontal_offset)
                card_y = (page_height - card_height) / 2 + int(aadhaar_vertical_offset)
                layout_height = card_height
            page = output.new_page(width=page_width, height=page_height)
            for side_index, image in enumerate(images):
                scale = min(card_width / image.width, layout_height / image.height)
                width = image.width * scale
                height = image.height * scale
                card_x = pair_x + side_index * (card_width + gap)
                rect = fitz.Rect(
                    card_x + (card_width - width) / 2,
                    card_y + (layout_height - height) / 2,
                    card_x + (card_width + width) / 2,
                    card_y + (layout_height + height) / 2,
                )
                image_data = io.BytesIO()
                image.save(image_data, format='PNG')
                page.insert_image(rect, stream=image_data.getvalue())
        elif image_a4:
            image = next(get_document_images(front_path, first_page_only=True))
            image = crop_and_adjust_image(image, crop_mode, margins, lighting_mode, brightness)
            page = output.new_page(width=page_width, height=page_height)
            layout_x = a4_layout_x if a4_custom_layout else image_a4_x
            layout_y = a4_layout_y if a4_custom_layout else image_a4_y
            layout_width = a4_layout_width if a4_custom_layout else image_a4_width
            layout_height = a4_layout_height if a4_custom_layout else image_a4_height
            scale = min(layout_width / image.width, layout_height / image.height)
            width = image.width * scale
            height = image.height * scale
            rect = fitz.Rect(
                layout_x + (layout_width - width) / 2,
                layout_y + (layout_height - height) / 2,
                layout_x + (layout_width + width) / 2,
                layout_y + (layout_height + height) / 2,
            )
            image_data = io.BytesIO()
            image.save(image_data, format='PNG')
            page.insert_image(rect, stream=image_data.getvalue())
        else:
            for source in get_document_images(front_path):
                image = crop_and_adjust_image(source, crop_mode, margins, lighting_mode, brightness)
                page = output.new_page(width=page_width, height=page_height)
                scale = min(page_width / image.width, page_height / image.height)
                width = image.width * scale
                height = image.height * scale
                rect = fitz.Rect(
                    (page_width - width) / 2,
                    (page_height - height) / 2,
                    (page_width + width) / 2,
                    (page_height + height) / 2,
                )
                image_data = io.BytesIO()
                image.save(image_data, format='PNG')
                page.insert_image(rect, stream=image_data.getvalue())
        if output.page_count == 0:
            raise ValueError('Document mein print karne layak page nahi mila.')
        output.save(output_path, garbage=4, deflate=True)
        return output_path
    except Exception:
        if os.path.exists(output_path):
            os.remove(output_path)
        raise
    finally:
        output.close()

def get_sumatra_path():
    configured_path = os.environ.get('SUMATRA_PDF_PATH')
    candidates = [
        configured_path,
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'SumatraPDF', 'SumatraPDF.exe'),
        os.path.join(os.environ.get('PROGRAMFILES', ''), 'SumatraPDF', 'SumatraPDF.exe'),
        os.path.join(os.environ.get('PROGRAMFILES(X86)', ''), 'SumatraPDF', 'SumatraPDF.exe'),
        shutil.which('SumatraPDF.exe'),
    ]
    return next((path for path in candidates if path and os.path.isfile(path)), None)

def send_to_printer(filepath, paper_size='A4', duplex=False, copies=1, print_type='Black & White'):
    try:
        sumatra_path = get_sumatra_path()
        if not sumatra_path:
            print('SumatraPDF not found; install it or set SUMATRA_PDF_PATH.')
            return False

        settings = [f'paper={paper_size}', 'fit', f'{copies}x']
        settings.append('color' if print_type == 'Color' else 'monochrome')
        if duplex:
            printer_name = win32print.GetDefaultPrinter()
            printer_handle = win32print.OpenPrinter(printer_name)
            try:
                printer_info = win32print.GetPrinter(printer_handle, 2)
                supports_duplex = win32print.DeviceCapabilities(
                    printer_name,
                    printer_info['pPortName'],
                    win32con.DC_DUPLEX,
                )
            finally:
                win32print.ClosePrinter(printer_handle)
            if not supports_duplex:
                print('Selected printer does not support automatic duplex printing.')
                return False
            settings.append('duplexlong')

        result = subprocess.run(
            [sumatra_path, '-print-to-default', '-silent', '-print-settings', ','.join(settings), filepath],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        )
        if result.returncode != 0:
            print(f"SumatraPDF print failed with exit code {result.returncode}: {result.stderr.strip()}")
            return False
        return True
    except Exception as e:
        print(f"Printing Error: {e}")
        return False

def expire_unpaid_request(req):
    if (
        req.get('payment_mode') == 'upi'
        and req['status'] == 'Awaiting Payment'
        and time.time() >= req['expires_at']
    ):
        req['status'] = 'Expired'
        cleanup_paths = [req['filepath'], *req.get('source_paths', [])]
        if req.get('qr_path'):
            cleanup_paths.append(req['qr_path'])
        for filepath in cleanup_paths:
            schedule_uploaded_file_cleanup(filepath)

def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if session.get('admin_authenticated') is not True:
            return redirect(url_for('admin_login'))
        return view(*args, **kwargs)
    return wrapped_view

def schedule_uploaded_file_cleanup(filepath):
    cleanup_timer = threading.Timer(
        PRINTED_UPLOAD_CLEANUP_DELAY_SECONDS,
        delete_uploaded_file,
        args=(filepath,),
    )
    cleanup_timer.daemon = True
    cleanup_timer.start()

def delete_uploaded_file(filepath):
    try:
        os.remove(filepath)
    except FileNotFoundError:
        pass
    except OSError as error:
        print(f"Could not remove printed upload {filepath}: {error}")

def save_admin_password_hash(password_hash):
    temporary_path = f"{PASSWORD_HASH_FILE}.tmp"
    with open(temporary_path, 'w', encoding='utf-8') as password_file:
        password_file.write(password_hash)
    os.replace(temporary_path, PASSWORD_HASH_FILE)
    app.config['ADMIN_PASSWORD_HASH'] = password_hash

def normalize_phone_number(value):
    digits = ''.join(character for character in value if character.isdigit())
    if len(digits) == 10:
        return f"91{digits}"
    if len(digits) == 12 and digits.startswith('91'):
        return digits
    return ''

def recovery_otp_digest(otp):
    return hmac.new(
        app.secret_key.encode('utf-8'),
        otp.encode('ascii'),
        hashlib.sha256,
    ).hexdigest()

def whatsapp_otp_is_configured():
    return all((
        app.config['WHATSAPP_ACCESS_TOKEN'],
        app.config['WHATSAPP_PHONE_NUMBER_ID'],
        app.config['WHATSAPP_OTP_TEMPLATE'],
    ))

def send_whatsapp_otp(phone_number, otp):
    token = app.config['WHATSAPP_ACCESS_TOKEN']
    phone_number_id = app.config['WHATSAPP_PHONE_NUMBER_ID']
    template_name = app.config['WHATSAPP_OTP_TEMPLATE']
    if not all((token, phone_number_id, template_name)):
        return False

    endpoint = (
        f"https://graph.facebook.com/{app.config['WHATSAPP_GRAPH_API_VERSION']}"
        f"/{phone_number_id}/messages"
    )
    payload = {
        'messaging_product': 'whatsapp',
        'to': phone_number,
        'type': 'template',
        'template': {
            'name': template_name,
            'language': {'code': app.config['WHATSAPP_TEMPLATE_LANGUAGE']},
            'components': [{
                'type': 'body',
                'parameters': [{'type': 'text', 'text': otp}],
            }],
        },
    }
    outbound_request = UrlRequest(
        endpoint,
        data=json.dumps(payload).encode('utf-8'),
        headers={
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        },
        method='POST',
    )
    try:
        with urlopen(outbound_request, timeout=10) as response:
            return 200 <= response.status < 300
    except (HTTPError, URLError, TimeoutError, OSError) as error:
        print(f"WhatsApp OTP delivery failed: {error}")
        return False

# 1. कस्टमर मोबाइल पेज
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/document-preview', methods=['POST'])
@limiter.limit('20 per minute')
def document_preview():
    uploaded_file = request.files.get('file')
    try:
        page_index = int(request.form.get('page', 0))
    except (TypeError, ValueError):
        return "Invalid document page", 400
    if not uploaded_file or not uploaded_file.filename or not allowed_file(uploaded_file.filename):
        return "Unsupported document", 400
    if not uploaded_file.filename.lower().endswith('.pdf'):
        return "Only PDF previews use this route", 400
    try:
        with fitz.open(stream=uploaded_file.read(), filetype='pdf') as document:
            if page_index < 0 or page_index >= document.page_count:
                return "Requested PDF page does not exist", 400
            pixmap = document[page_index].get_pixmap(matrix=fitz.Matrix(1.5, 1.5), alpha=False)
            preview = io.BytesIO(pixmap.tobytes('png'))
        preview.seek(0)
        return send_file(preview, mimetype='image/png', max_age=0)
    except Exception:
        return "PDF preview create nahi ho saki", 400

@app.route('/a4-image-preview', methods=['POST'])
@limiter.limit('20 per minute')
def a4_image_preview():
    uploaded_file = request.files.get('file')
    if not uploaded_file or not uploaded_file.filename or not uploaded_file.filename.lower().endswith(('.jpg', '.jpeg', '.png')):
        return "A4 preview ke liye JPG, JPEG ya PNG image chahiye", 400
    try:
        crop_mode = request.form.get('crop_mode', 'auto')
        lighting_mode = request.form.get('lighting_mode', 'auto')
        margins = tuple(float(request.form.get(f'front_crop_{name}', 0)) for name in ('top', 'right', 'bottom', 'left'))
        brightness = float(request.form.get('brightness', 100)) / 100
        if crop_mode not in ('auto', 'manual') or lighting_mode not in ('auto', 'manual'):
            return "Crop ya lighting setting valid nahi hai", 400
        if any(not math.isfinite(value) or value < 0 or value > 40 for value in margins):
            return "Crop margin 0 se 40 percent ke beech rakhein", 400
        if margins[1] + margins[3] >= 90 or margins[0] + margins[2] >= 90:
            return "Crop margins document ko chhota kar rahe hain", 400
        if not math.isfinite(brightness) or not 0.5 <= brightness <= 1.5:
            return "Brightness 50 se 150 percent ke beech rakhein", 400
        image = ImageOps.exif_transpose(Image.open(uploaded_file)).convert('RGB')
        image = crop_and_adjust_image(image, crop_mode, margins, lighting_mode, brightness)
        preview = io.BytesIO()
        image.save(preview, format='PNG')
        preview.seek(0)
        return send_file(preview, mimetype='image/png', max_age=0)
    except Exception as error:
        print(f"A4 image preview failed: {error}")
        return "A4 image preview nahi ban saki. JPG, JPEG ya PNG file check karein.", 400

# 2. कस्टमर की फाइल अपलोड और पेमेंट चॉइस
@app.route('/upload', methods=['POST'])
@limiter.limit('10 per minute')
def upload_file():
    global request_id_counter
    file = request.files.get('file')
    back_file = request.files.get('back_file')
    payment_mode = request.form.get('payment_mode')  # 'upi' or 'cash'
    print_type = request.form.get('print_type', 'Black & White')
    paper_size = request.form.get('paper_size', 'A4')
    crop_mode = request.form.get('crop_mode', 'auto')
    lighting_mode = request.form.get('lighting_mode', 'auto')
    aadhaar_pair = request.form.get('aadhaar_pair') == 'on'
    id_card_a4 = request.form.get('id_card_a4') == 'on'
    image_a4 = request.form.get('image_a4') == 'on'
    a4_custom_layout = request.form.get('a4_custom_layout') == 'on'
    if sum((aadhaar_pair, id_card_a4, image_a4)) > 1:
        return "Aadhaar pair, ID card, ya image A4 layout mein se ek chunein", 400
    try:
        copies = int(request.form.get('copies', 1))
        margins = tuple(float(request.form.get(f'front_{name}', 0)) for name in ('crop_top', 'crop_right', 'crop_bottom', 'crop_left'))
        back_margins = tuple(float(request.form.get(f'back_{name}', 0)) for name in ('crop_top', 'crop_right', 'crop_bottom', 'crop_left'))
        brightness = float(request.form.get('brightness', 100)) / 100
        back_brightness = float(request.form.get('back_brightness', 100)) / 100
        aadhaar_vertical_offset = int(request.form.get('aadhaar_vertical_offset', 0))
        aadhaar_horizontal_offset = int(request.form.get('aadhaar_horizontal_offset', 0))
        image_a4_x = float(request.form.get('image_a4_x', 0))
        image_a4_y = float(request.form.get('image_a4_y', 0))
        image_a4_width = float(request.form.get('image_a4_width', 0))
        image_a4_height = float(request.form.get('image_a4_height', 0))
        a4_layout_x = float(request.form.get('a4_layout_x', 0))
        a4_layout_y = float(request.form.get('a4_layout_y', 0))
        a4_layout_width = float(request.form.get('a4_layout_width', 0))
        a4_layout_height = float(request.form.get('a4_layout_height', 0))
    except (TypeError, ValueError):
        return "कृपया print settings ki sahi values enter karein", 400
    back_crop_mode = request.form.get('back_crop_mode', crop_mode)
    back_lighting_mode = request.form.get('back_lighting_mode', lighting_mode)
    if aadhaar_pair or id_card_a4 or image_a4:
        paper_size = 'A4'
    if image_a4 and (not file or not file.filename.lower().endswith(('.jpg', '.jpeg', '.png'))):
        return "A4 image layout ke liye JPG, JPEG ya PNG file chunein", 400
    if copies < 1:
        return "कम से कम 1 कॉपी चुनें", 400
    if paper_size not in PAPER_SIZES:
        return "चुना गया paper size valid nahi hai", 400
    if crop_mode not in ('auto', 'manual') or lighting_mode not in ('auto', 'manual'):
        return "चुनी गई crop ya lighting setting valid nahi hai", 400
    if back_crop_mode not in ('auto', 'manual') or back_lighting_mode not in ('auto', 'manual'):
        return "Back-side crop ya lighting setting valid nahi hai", 400
    if any(value < 0 or value > 40 for value in margins):
        return "Crop margin 0 se 40 percent ke beech rakhein", 400
    if any(value < 0 or value > 40 for value in back_margins):
        return "Back-side crop margin 0 se 40 percent ke beech rakhein", 400
    if any(
        horizontal[0] + horizontal[1] >= 90
        for horizontal in ((margins[1], margins[3]), (back_margins[1], back_margins[3]))
    ) or any(
        vertical[0] + vertical[1] >= 90
        for vertical in ((margins[0], margins[2]), (back_margins[0], back_margins[2]))
    ):
        return "Crop margins document ko chhota kar rahe hain", 400
    if not 0.5 <= brightness <= 1.5:
        return "Brightness 50 se 150 percent ke beech rakhein", 400
    if not 0.5 <= back_brightness <= 1.5:
        return "Back-side brightness 50 se 150 percent ke beech rakhein", 400
    card_count = 2 if aadhaar_pair else 1
    layout_width = AADHAAR_CARD_SIZE[0] * card_count + 8 * (card_count - 1)
    max_aadhaar_horizontal_offset = int((PAPER_SIZES['A4'][0] - layout_width) / 2)
    max_aadhaar_vertical_offset = int((PAPER_SIZES['A4'][1] - AADHAAR_CARD_SIZE[1]) / 2)
    if (aadhaar_pair or id_card_a4) and not a4_custom_layout and not -max_aadhaar_vertical_offset <= aadhaar_vertical_offset <= max_aadhaar_vertical_offset:
        return f"Aadhaar vertical position -{max_aadhaar_vertical_offset} se {max_aadhaar_vertical_offset} pt ke beech rakhein", 400
    if (aadhaar_pair or id_card_a4) and not a4_custom_layout and not -max_aadhaar_horizontal_offset <= aadhaar_horizontal_offset <= max_aadhaar_horizontal_offset:
        return f"Card horizontal position -{max_aadhaar_horizontal_offset} se {max_aadhaar_horizontal_offset} pt ke beech rakhein", 400
    layout_geometry = (a4_layout_x, a4_layout_y, a4_layout_width, a4_layout_height)
    if image_a4 and not a4_custom_layout:
        return "Image ko A4 preview mein set karke dobara submit karein", 400
    if a4_custom_layout and (
        not all(math.isfinite(value) for value in layout_geometry)
        or a4_layout_x < 0
        or a4_layout_y < 0
        or a4_layout_width <= 0
        or a4_layout_height <= 0
        or a4_layout_x + a4_layout_width > PAPER_SIZES['A4'][0] + 0.01
        or a4_layout_y + a4_layout_height > PAPER_SIZES['A4'][1] + 0.01
        or (aadhaar_pair and a4_layout_width <= 8)
    ):
        return "A4 preview ke andar image ka size aur jagah set karein", 400
    if payment_mode not in ('upi', 'cash'):
        return "गलत payment option चुना गया है", 400
    price_per_page = 10
    total_amount = price_per_page * copies
    upi_link = (
        "upi://pay?pa=9006606819@okbizaxis"
        f"&pn={quote('Sakshi Digital Studio & Cyber Cafe')}"
        f"&am={total_amount:.2f}&cu=INR"
    )

    if not file or file.filename == '':
        return "कृपया फाइल चुनें", 400

    if not allowed_file(file.filename):
        return "सिर्फ PDF या JPG/PNG फाइल अपलोड करें", 400
    if back_file and back_file.filename and not allowed_file(back_file.filename):
        return "Back side ke liye bhi PDF ya JPG/PNG file chahiye", 400

    source_paths = []
    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{uuid.uuid4().hex}_{filename}")
        file.save(filepath)
        source_paths.append(filepath)

        back_filepath = None
        if aadhaar_pair and back_file and back_file.filename:
            back_filename = secure_filename(back_file.filename)
            back_filepath = os.path.join(
                app.config['UPLOAD_FOLDER'],
                f"{uuid.uuid4().hex}_{back_filename}",
            )
            back_file.save(back_filepath)
            source_paths.append(back_filepath)

        processed_filepath = render_print_pdf(
            filepath,
            paper_size,
            crop_mode,
            margins,
            lighting_mode,
            brightness,
            back_filepath,
            aadhaar_pair,
            (back_crop_mode, back_margins, back_lighting_mode, back_brightness),
            aadhaar_vertical_offset,
            aadhaar_horizontal_offset,
            id_card_a4,
            a4_custom_layout,
            a4_layout_x,
            a4_layout_y,
            a4_layout_width,
            a4_layout_height,
            image_a4,
            image_a4_x,
            image_a4_y,
            image_a4_width,
            image_a4_height,
        )
    except Exception as error:
        for source_path in source_paths:
            delete_uploaded_file(source_path)
        print(f"Document preparation failed: {error}")
        return "File prepare nahi ho saki. File format aur crop settings check karein.", 400

    filename = secure_filename(file.filename)
    if aadhaar_pair:
        back_label = secure_filename(back_file.filename) if back_file and back_file.filename else '2-page PDF'
        filename = f"{filename} + {back_label} (Aadhaar front + back)"
    elif id_card_a4:
        filename = f"{filename} (ID card · single side)"
    print_filepaths = [processed_filepath, *source_paths]
    qr_filename = None
    qr_path = None
    if payment_mode == 'upi':
        qr_filename = f"{uuid.uuid4().hex}_qr.png"
        qr_path = os.path.join(app.static_folder, qr_filename)
        try:
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(upi_link)
            qr.make(fit=True)
            img = qr.make_image(fill='black', back_color='white')
            img.save(qr_path)
        except Exception as error:
            for source_path in print_filepaths:
                delete_uploaded_file(source_path)
            print(f"Payment QR creation failed: {error}")
            return "Payment QR nahi ban saka. Kripya dobara try karein.", 500

    req_data = {
        'id': request_id_counter,
        'filename': filename,
        'filepath': processed_filepath,
        'source_paths': source_paths,
        'print_type': print_type,
        'copies': copies,
        'total_amount': total_amount,
        'paper_size': paper_size,
        'duplex': False,
        'aadhaar_pair': aadhaar_pair,
        'id_card_a4': id_card_a4,
        'image_a4': image_a4,
        'a4_custom_layout': a4_custom_layout,
        'aadhaar_vertical_offset': aadhaar_vertical_offset if aadhaar_pair or id_card_a4 else 0,
        'aadhaar_horizontal_offset': aadhaar_horizontal_offset if aadhaar_pair or id_card_a4 else 0,
        'payment_mode': payment_mode,
        'status': 'Awaiting Payment' if payment_mode == 'upi' else 'Pending',
    }
    if payment_mode == 'upi':
        req_data['expires_at'] = time.time() + PAYMENT_TIMEOUT_SECONDS
        req_data['qr_path'] = qr_path
    pending_requests.append(req_data)
    request_id_counter += 1

    if payment_mode == 'upi':
        return render_template(
            'payment.html',
            total_amount=total_amount,
            qr_filename=qr_filename,
            request_id=req_data['id'],
            expires_at=req_data['expires_at'],
        )
    return render_template(
        'status.html',
        message="कैश रिक्वेस्ट काउंटर पर भेज दी गई है। कृपया काउंटर पर भुगतान करें, फिर प्रिंट निकलेगा।",
    )

@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit('5 per minute')
def admin_login():
    if session.get('admin_authenticated') is True:
        return redirect(url_for('admin'))
    error = None
    success = request.args.get('reset') == '1'
    if request.method == 'POST':
        email = request.form.get('email', '').strip().casefold()
        password = request.form.get('password', '')
        configured_password_hash = app.config['ADMIN_PASSWORD_HASH']
        if not configured_password_hash:
            error = 'Admin password set नहीं है। ऐप शुरू करने से पहले ADMIN_PASSWORD_HASH configure करें।'
        elif (
            hmac.compare_digest(email, app.config['ADMIN_EMAIL'].casefold())
            and check_password_hash(configured_password_hash, password)
        ):
            session.clear()
            session['admin_authenticated'] = True
            return redirect(url_for('admin'))
        else:
            error = 'ईमेल या पासवर्ड सही नहीं है।'
    return render_template(
        'admin_login.html',
        admin_email=app.config['ADMIN_EMAIL'],
        password_configured=bool(app.config['ADMIN_PASSWORD_HASH']),
        error=error,
        success=success,
    )

@app.route('/admin/forgot-password', methods=['GET', 'POST'])
@limiter.limit('2 per minute')
def admin_forgot_password():
    error = None
    otp_configured = whatsapp_otp_is_configured()
    if request.method == 'POST':
        if not otp_configured:
            error = 'WhatsApp OTP service configure nahi hai; OTP send nahi hua.'
        else:
            entered_phone = normalize_phone_number(request.form.get('phone', ''))
            registered_phone = normalize_phone_number(app.config['ADMIN_PHONE_NUMBER'])
            if not entered_phone or not hmac.compare_digest(entered_phone, registered_phone):
                error = 'Number verify nahi ho saka. Registered admin number check karein.'
            else:
                now = time.time()
                with recovery_send_lock:
                    last_sent_at = recovery_send_times.get(entered_phone, 0)
                    if now - last_sent_at < RECOVERY_OTP_RESEND_SECONDS:
                        error = 'Naya OTP bhejne se pehle ek minute intezar karein.'
                    else:
                        recovery_send_times[entered_phone] = now
                        expired_challenges = [
                            challenge_id
                            for challenge_id, challenge in recovery_challenges.items()
                            if now >= challenge['expires_at']
                        ]
                        for challenge_id in expired_challenges:
                            recovery_challenges.pop(challenge_id, None)
                if not error:
                    otp = f"{secrets.randbelow(1_000_000):06d}"
                    if send_whatsapp_otp(entered_phone, otp):
                        challenge_id = secrets.token_urlsafe(24)
                        recovery_challenges[challenge_id] = {
                            'otp_digest': recovery_otp_digest(otp),
                            'expires_at': now + RECOVERY_OTP_LIFETIME_SECONDS,
                            'attempts': 0,
                            'verified_at': None,
                        }
                        session['recovery_challenge_id'] = challenge_id
                        return redirect(url_for('admin_verify_otp'))
                    error = 'WhatsApp OTP deliver nahi ho saka. Service settings check karke dobara try karein.'
    return render_template(
        'admin_recovery.html',
        otp_configured=otp_configured,
        error=error,
    )

@app.route('/admin/verify-otp', methods=['GET', 'POST'])
def admin_verify_otp():
    challenge_id = session.get('recovery_challenge_id')
    challenge = recovery_challenges.get(challenge_id)
    if not challenge or time.time() >= challenge['expires_at']:
        session.pop('recovery_challenge_id', None)
        recovery_challenges.pop(challenge_id, None)
        return redirect(url_for('admin_forgot_password'))

    error = None
    if request.method == 'POST':
        if challenge['attempts'] >= RECOVERY_OTP_MAX_ATTEMPTS:
            recovery_challenges.pop(challenge_id, None)
            session.pop('recovery_challenge_id', None)
            return redirect(url_for('admin_forgot_password'))
        submitted_otp = request.form.get('otp', '').strip()
        if len(submitted_otp) != 6 or not submitted_otp.isdigit() or not hmac.compare_digest(
            recovery_otp_digest(submitted_otp), challenge['otp_digest']
        ):
            challenge['attempts'] += 1
            error = 'OTP sahi nahi hai. Dobara check karein.'
        else:
            challenge['verified_at'] = time.time()
            session['recovery_verified'] = True
            return redirect(url_for('admin_reset_password'))
    return render_template('admin_verify_otp.html', error=error)

@app.route('/admin/reset-password', methods=['GET', 'POST'])
def admin_reset_password():
    challenge_id = session.get('recovery_challenge_id')
    challenge = recovery_challenges.get(challenge_id)
    if (
        not challenge
        or not session.get('recovery_verified')
        or not challenge.get('verified_at')
        or time.time() - challenge['verified_at'] >= RECOVERY_OTP_LIFETIME_SECONDS
    ):
        session.pop('recovery_verified', None)
        return redirect(url_for('admin_forgot_password'))

    error = None
    if request.method == 'POST':
        new_password = request.form.get('password', '')
        confirmation = request.form.get('confirm_password', '')
        if len(new_password) < 10:
            error = 'Password kam se kam 10 characters ka rakhein.'
        elif not hmac.compare_digest(new_password, confirmation):
            error = 'Dono password ek jaise nahi hain.'
        else:
            save_admin_password_hash(generate_password_hash(new_password))
            recovery_challenges.pop(challenge_id, None)
            session.clear()
            return redirect(url_for('admin_login', reset=1))
    return render_template(
        'admin_reset_password.html',
        admin_email=app.config['ADMIN_EMAIL'],
        error=error,
    )

@app.route('/admin/logout', methods=['POST'])
@admin_required
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

# 3. आपका (Admin) कंप्यूटर डैशबोर्ड
@app.route('/admin')
@admin_required
def admin():
    for req in pending_requests:
        expire_unpaid_request(req)
    return render_template('admin.html', requests=pending_requests)

@app.route('/admin/request/<int:req_id>/preview')
@admin_required
def admin_request_preview(req_id):
    req = next((item for item in pending_requests if item['id'] == req_id), None)
    if not req:
        return "Print request nahi mili.", 404
    expire_unpaid_request(req)
    filepath = req.get('filepath')
    if not filepath or not os.path.isfile(filepath):
        return "Is request ki PDF preview ab available nahi hai.", 404
    response = send_file(
        filepath,
        mimetype='application/pdf',
        as_attachment=False,
        download_name=f"print-request-{req_id}.pdf",
        conditional=True,
    )
    response.headers['Cache-Control'] = 'private, no-store'
    return response

@app.route('/payment/<int:req_id>/status')
def payment_status(req_id):
    req = next((item for item in pending_requests if item['id'] == req_id), None)
    if not req:
        return jsonify({'success': False, 'message': 'रिक्वेस्ट नहीं मिली!'}), 404
    expire_unpaid_request(req)
    return jsonify({'status': req['status']})

@app.route('/payment/<int:req_id>/report', methods=['POST'])
def report_payment(req_id):
    req = next((item for item in pending_requests if item['id'] == req_id), None)
    if not req:
        return jsonify({'success': False, 'message': 'रिक्वेस्ट नहीं मिली!'}), 404
    expire_unpaid_request(req)
    if req['status'] == 'Expired':
        return jsonify({'success': False, 'message': 'पेमेंट का समय समाप्त हो गया है।'}), 410
    if req['status'] == 'Awaiting Payment':
        req['status'] = 'Payment Reported'
        req['payment_reported_at'] = time.time()
    return jsonify({'success': True, 'status': req['status']})

# 4. कैश अप्रूव करके प्रिंट देने का रूट (Admin Action)
@app.route('/approve/<int:req_id>', methods=['POST'])
@admin_required
def approve_print(req_id):
    for req in pending_requests:
        expire_unpaid_request(req)
        is_cash_pending = req['payment_mode'] == 'cash' and req['status'] == 'Pending'
        is_upi_verifiable = req['payment_mode'] == 'upi' and req['status'] == 'Payment Reported'
        if req['id'] == req_id and (is_cash_pending or is_upi_verifiable):
            previous_status = req['status']
            req['status'] = 'Printing'
            success = send_to_printer(
                req['filepath'],
                paper_size=req.get('paper_size', 'A4'),
                duplex=req.get('duplex', False),
                copies=req['copies'],
                print_type=req['print_type'],
            )
            if success:
                req['status'] = 'Approved & Printed'
                cleanup_paths = [req['filepath'], *req.get('source_paths', [])]
                if req.get('qr_path'):
                    cleanup_paths.append(req['qr_path'])
                for filepath in cleanup_paths:
                    schedule_uploaded_file_cleanup(filepath)
                return jsonify({'success': True, 'message': 'प्रिंट कमांड भेज दी गई है!'})
            else:
                req['status'] = previous_status
                return jsonify({'success': False, 'message': 'प्रिंटर एरर!'})
    return jsonify({'success': False, 'message': 'रिक्वेस्ट नहीं मिली!'})

if __name__ == '__main__':
    import sys
    if '--set-admin-password' in sys.argv:
        from getpass import getpass

        password = getpass('New admin password (minimum 10 characters): ')
        confirmation = getpass('Confirm new admin password: ')
        if len(password) < 10 or not hmac.compare_digest(password, confirmation):
            print('Password was not changed. Use at least 10 characters and enter both values identically.')
            raise SystemExit(1)
        save_admin_password_hash(generate_password_hash(password))
        print('Admin password hash saved. Start the app normally to use it.')
    elif PUBLIC_MODE:
        from waitress import serve

        serve(app, host='127.0.0.1', port=int(os.environ.get('PORT', '5000')))
    else:
        app.run(host='0.0.0.0', port=5000, debug=False)