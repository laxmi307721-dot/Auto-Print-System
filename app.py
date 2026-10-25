import os
import io
import hmac
import hashlib
import ipaddress
import json
import math
import secrets
import socket
import tempfile
import threading
import time
import uuid
from functools import wraps
from urllib.error import HTTPError, URLError
from urllib.request import Request as UrlRequest, urlopen
import qrcode
import pymupdf as fitz
import redis
from PIL import Image, ImageChops, ImageEnhance, ImageOps
from flask import Flask, request, render_template, redirect, url_for, jsonify, session, send_file, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from urllib.parse import quote, urlencode
from werkzeug.middleware.proxy_fix import ProxyFix
from printing import get_sumatra_path, send_to_printer

IS_VERCEL = bool(os.environ.get('VERCEL'))
app = Flask(__name__, static_folder=None) if IS_VERCEL else Flask(__name__)
SUPABASE_URL = os.environ.get('SUPABASE_URL', '').rstrip('/')
SUPABASE_SERVICE_ROLE_KEY = os.environ.get('SUPABASE_SERVICE_ROLE_KEY', '')
SUPABASE_STORAGE_BUCKET = os.environ.get('SUPABASE_STORAGE_BUCKET', 'print-files')
SUPABASE_ENABLED = bool(SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY)
PUBLIC_MODE = os.environ.get('PUBLIC_MODE', '').casefold() in ('1', 'true', 'yes')
if IS_VERCEL:
    missing_variables = [
        name for name, value in (
            ('FLASK_SECRET_KEY', os.environ.get('FLASK_SECRET_KEY')),
            ('ADMIN_PASSWORD_HASH', os.environ.get('ADMIN_PASSWORD_HASH')),
            ('PRINT_AGENT_TOKEN', os.environ.get('PRINT_AGENT_TOKEN')),
            ('SUPABASE_URL', SUPABASE_URL),
            ('SUPABASE_SERVICE_ROLE_KEY', SUPABASE_SERVICE_ROLE_KEY),
            ('RATELIMIT_STORAGE_URI', os.environ.get('RATELIMIT_STORAGE_URI')),
        ) if not value
    ]
    if missing_variables:
        raise RuntimeError(f"Missing required Vercel environment variables: {', '.join(missing_variables)}")
    if not PUBLIC_MODE:
        raise RuntimeError('Vercel deployment must set PUBLIC_MODE=1.')
    if len(os.environ['PRINT_AGENT_TOKEN']) < 32:
        raise RuntimeError('PRINT_AGENT_TOKEN must contain at least 32 characters.')
    if not SUPABASE_URL.startswith('https://'):
        raise RuntimeError('SUPABASE_URL must use HTTPS.')
    if not os.environ['RATELIMIT_STORAGE_URI'].startswith(('redis://', 'rediss://')):
        raise RuntimeError('RATELIMIT_STORAGE_URI must be a Redis URL.')
    secret_key = os.environ['FLASK_SECRET_KEY']
else:
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
if IS_VERCEL:
    configured_password_hash = os.environ['ADMIN_PASSWORD_HASH']
else:
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
    MAX_CONTENT_LENGTH=(4 * 1024 * 1024 if IS_VERCEL else 50 * 1024 * 1024),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=PUBLIC_MODE,
    WTF_CSRF_TIME_LIMIT=60 * 60,
)
if IS_VERCEL:
    public_static_folder = os.path.join(os.path.dirname(__file__), 'public', 'static')
    app.add_url_rule(
        '/static/<path:filename>',
        endpoint='static',
        view_func=lambda filename: send_from_directory(public_static_folder, filename),
    )
if PUBLIC_MODE:
    app.config['PREFERRED_URL_SCHEME'] = 'https'
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    if not app.config['ADMIN_PASSWORD_HASH']:
        raise RuntimeError('PUBLIC_MODE requires an admin password configured before startup.')
    if check_password_hash(app.config['ADMIN_PASSWORD_HASH'], 'Admin@12345'):
        raise RuntimeError('Change the temporary admin password before enabling PUBLIC_MODE.')
csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=os.environ.get('RATELIMIT_STORAGE_URI', 'memory://'),
)
recovery_redis = (
    redis.Redis.from_url(os.environ['RATELIMIT_STORAGE_URI'], decode_responses=True)
    if IS_VERCEL
    else None
)

@app.after_request
def add_security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    if PUBLIC_MODE and request.is_secure:
        response.headers.setdefault('Strict-Transport-Security', 'max-age=15552000')
    return response

@app.errorhandler(redis.exceptions.RedisError)
def handle_redis_error(error):
    print('Redis service is unavailable for authentication or rate limiting.')
    return 'Authentication service is temporarily unavailable. Please try again later.', 503

UPLOAD_FOLDER = os.path.join(tempfile.gettempdir(), 'auto-print-system') if IS_VERCEL else 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if IS_VERCEL and not SUPABASE_ENABLED:
    raise RuntimeError('Vercel deployment requires Supabase database and storage configuration.')

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

# पेंडिंग प्रिंट रिक्वेस्ट स्टोर करने के लिए (Cash Requests)
pending_requests = []
request_id_counter = 1
pending_requests_lock = threading.Lock()
PAYMENT_TIMEOUT_SECONDS = 5 * 60
MERCHANT_UPI_ID = '9006606819@okbizaxis'
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

def supabase_request(path, method='GET', payload=None, body=None, content_type=None, prefer=None):
    url = f"{SUPABASE_URL}{path}"
    headers = {
        'apikey': SUPABASE_SERVICE_ROLE_KEY,
        'Authorization': f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
    }
    if payload is not None:
        body = json.dumps(payload).encode('utf-8')
        content_type = 'application/json'
    if content_type:
        headers['Content-Type'] = content_type
    if prefer:
        headers['Prefer'] = prefer
    outbound_request = UrlRequest(url, data=body, headers=headers, method=method)
    try:
        with urlopen(outbound_request, timeout=30) as response:
            response_body = response.read()
    except HTTPError as error:
        error_body = error.read().decode('utf-8', errors='replace')
        raise RuntimeError(f"Supabase request failed ({error.code}): {error_body}") from error
    except (URLError, TimeoutError, OSError) as error:
        raise RuntimeError(f"Supabase request failed: {error}") from error
    if not response_body:
        return None
    if content_type == 'application/json' or 'application/json' in response.headers.get('Content-Type', ''):
        return json.loads(response_body.decode('utf-8'))
    return response_body

def supabase_storage_path(key):
    return f"/storage/v1/object/{quote(SUPABASE_STORAGE_BUCKET, safe='')}/{quote(key, safe='/')}"

def upload_job_file(local_path, key, content_type):
    with open(local_path, 'rb') as uploaded_file:
        supabase_request(
            supabase_storage_path(key),
            method='POST',
            body=uploaded_file.read(),
            content_type=content_type,
            prefer='resolution=error',
        )

def download_job_file(key):
    return supabase_request(supabase_storage_path(key), content_type='application/octet-stream')

def signed_job_file_url(key):
    result = supabase_request(
        f"/storage/v1/object/sign/{quote(SUPABASE_STORAGE_BUCKET, safe='')}/{quote(key, safe='/')}",
        method='POST',
        payload={'expiresIn': 900},
    )
    signed_url = result.get('signedURL') if isinstance(result, dict) else None
    if not signed_url:
        raise RuntimeError('Supabase did not return a signed print-file URL.')
    if signed_url.startswith('http://') or signed_url.startswith('https://'):
        return signed_url
    if signed_url.startswith('/storage/v1/'):
        return f"{SUPABASE_URL}{signed_url}"
    return f"{SUPABASE_URL}/storage/v1{signed_url if signed_url.startswith('/') else f'/{signed_url}'}"

def request_to_job(row):
    return {**row['payload'], 'id': row['id'], 'status': row['status']}

def get_all_requests():
    if SUPABASE_ENABLED:
        query = urlencode({'select': 'id,status,payload', 'order': 'id.desc'})
        rows = supabase_request(f"/rest/v1/print_jobs?{query}")
        return [request_to_job(row) for row in rows]
    with pending_requests_lock:
        return list(pending_requests)

def get_request(req_id):
    if SUPABASE_ENABLED:
        query = urlencode({'id': f'eq.{req_id}', 'select': 'id,status,payload'})
        rows = supabase_request(f"/rest/v1/print_jobs?{query}")
        return request_to_job(rows[0]) if rows else None
    with pending_requests_lock:
        return next((item for item in pending_requests if item['id'] == req_id), None)

def create_request(job):
    global request_id_counter
    if SUPABASE_ENABLED:
        payload = {key: value for key, value in job.items() if key not in ('id', 'status')}
        rows = supabase_request(
            '/rest/v1/print_jobs',
            method='POST',
            payload={'status': job['status'], 'payload': payload},
            prefer='return=representation',
        )
        return request_to_job(rows[0])
    with pending_requests_lock:
        job['id'] = request_id_counter
        request_id_counter += 1
        pending_requests.append(job)
    return job

def update_request(job, **changes):
    if SUPABASE_ENABLED:
        payload = {key: value for key, value in job.items() if key not in ('id', 'status')}
        payload.update({key: value for key, value in changes.items() if key != 'status'})
        update_data = {'payload': payload}
        if 'status' in changes:
            update_data['status'] = changes['status']
        filters = {'id': f"eq.{job['id']}"}
        if 'status' in changes:
            filters['status'] = f"eq.{job['status']}"
        query = urlencode(filters)
        updated_rows = supabase_request(
            f"/rest/v1/print_jobs?{query}",
            method='PATCH',
            payload=update_data,
            prefer='return=representation',
        )
        if 'status' in changes and not updated_rows:
            return False
    else:
        with pending_requests_lock:
            stored_job = next((item for item in pending_requests if item['id'] == job['id']), None)
            if not stored_job or ('status' in changes and stored_job['status'] != job['status']):
                return False
            stored_job.update(changes)
            return True
    job.update(changes)
    return True

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_merchant_payment_qr(amount):
    qr = qrcode.QRCode(version=None, box_size=10, border=5)
    qr.add_data('upi://pay?' + urlencode({
        'pa': MERCHANT_UPI_ID,
        'pn': 'Sakshi Digital Studio & Cyber Cafe',
        'am': f'{amount:.2f}',
        'cu': 'INR',
    }))
    qr.make(fit=True)
    image = io.BytesIO()
    qr.make_image(fill_color='black', back_color='white').save(image, format='PNG')
    return image.getvalue()

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

def validate_perspective_points(points):
    if points is None:
        return
    if len(points) != 4 or any(
        len(point) != 2
        or any(not math.isfinite(value) or value < 0 or value > 1 for value in point)
        for point in points
    ):
        raise ValueError('Perspective ke chaaron corners image ke andar hone chahiye.')
    crosses = []
    for index, point in enumerate(points):
        next_point = points[(index + 1) % 4]
        after_next = points[(index + 2) % 4]
        crosses.append(
            (next_point[0] - point[0]) * (after_next[1] - next_point[1])
            - (next_point[1] - point[1]) * (after_next[0] - next_point[0])
        )
    if any(cross <= 0.0001 for cross in crosses):
        raise ValueError('Perspective corners ko clockwise order mein set karein.')
    area = abs(sum(
        point[0] * points[(index + 1) % 4][1] - points[(index + 1) % 4][0] * point[1]
        for index, point in enumerate(points)
    )) / 2
    if area < 0.01:
        raise ValueError('Perspective crop area bahut chhota hai.')

def perspective_correct_image(image, points):
    if points is None:
        return image
    validate_perspective_points(points)
    top_left, top_right, bottom_right, bottom_left = points

    def distance(start, end):
        return math.hypot(
            (end[0] - start[0]) * image.width,
            (end[1] - start[1]) * image.height,
        )

    card_aspect = AADHAAR_CARD_SIZE[0] / AADHAAR_CARD_SIZE[1]
    output_width = max(
        2,
        round(max(
            distance(top_left, top_right),
            distance(bottom_left, bottom_right),
            distance(top_left, bottom_left) * card_aspect,
            distance(top_right, bottom_right) * card_aspect,
        )),
    )
    output_height = max(2, round(output_width / card_aspect))
    quad = tuple(
        coordinate
        for point in (top_left, bottom_left, bottom_right, top_right)
        for coordinate in (point[0] * image.width, point[1] * image.height)
    )
    return image.transform(
        (output_width, output_height),
        Image.Transform.QUAD,
        quad,
        resample=Image.Resampling.BICUBIC,
    )

def get_perspective_points(form, side):
    if form.get(f'{side}_perspective_enabled') != 'on':
        return None
    corners = ('tl', 'tr', 'br', 'bl')
    try:
        points = tuple(
            (
                float(form.get(f'{side}_perspective_{corner}_x', 0)) / 100,
                float(form.get(f'{side}_perspective_{corner}_y', 0)) / 100,
            )
            for corner in corners
        )
    except (TypeError, ValueError) as error:
        raise ValueError('Perspective ke chaaron corners ki position sahi nahi hai.') from error
    validate_perspective_points(points)
    return points

def crop_and_adjust_image(image, crop_mode, margins, lighting_mode, brightness, perspective_points=None):
    image = perspective_correct_image(image, perspective_points)
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

def prepare_print_image(image, rect, print_type):
    if print_type != 'Black & White':
        return image
    max_size = (
        max(1, round(rect.width * 120 / 72)),
        max(1, round(rect.height * 120 / 72)),
    )
    image.thumbnail(max_size, Image.Resampling.LANCZOS)
    return image.convert('L')

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
    print_type='Black & White',
    front_perspective=None,
    back_perspective=None,
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
            images = [crop_and_adjust_image(
                front, crop_mode, margins, lighting_mode, brightness, front_perspective
            )]
            if aadhaar_pair:
                images.append(crop_and_adjust_image(
                    back, back_crop_mode, back_margins, back_lighting_mode, back_brightness,
                    back_perspective,
                ))
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
                card_x = pair_x + side_index * (card_width + gap)
                rect = fitz.Rect(card_x, card_y, card_x + card_width, card_y + layout_height)
                image = ImageOps.fit(
                    image,
                    (
                        max(1, round(rect.width * 120 / 72)),
                        max(1, round(rect.height * 120 / 72)),
                    ),
                    method=Image.Resampling.LANCZOS,
                )
                image = prepare_print_image(image, rect, print_type)
                image_data = io.BytesIO()
                image.save(image_data, format='PNG')
                page.insert_image(rect, stream=image_data.getvalue())
        elif image_a4:
            image = next(get_document_images(front_path, first_page_only=True))
            image = crop_and_adjust_image(
                image, crop_mode, margins, lighting_mode, brightness, front_perspective
            )
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
            image = prepare_print_image(image, rect, print_type)
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
                image = prepare_print_image(image, rect, print_type)
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

def render_print_pdf_batch(filepaths, paper_size, crop_mode, margins, lighting_mode, brightness, print_type='Black & White'):
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{uuid.uuid4().hex}_print.pdf")
    temporary_paths = []
    output = fitz.open()
    try:
        for filepath in filepaths:
            rendered_path = render_print_pdf(
                filepath,
                paper_size,
                crop_mode,
                margins,
                lighting_mode,
                brightness,
                print_type=print_type,
            )
            temporary_paths.append(rendered_path)
            with fitz.open(rendered_path) as rendered_document:
                output.insert_pdf(rendered_document)
        if output.page_count == 0:
            raise ValueError('Documents mein print karne layak page nahi mile.')
        output.save(output_path, garbage=4, deflate=True)
        return output_path
    except Exception:
        if os.path.exists(output_path):
            os.remove(output_path)
        raise
    finally:
        output.close()
        for temporary_path in temporary_paths:
            delete_uploaded_file(temporary_path)

def expire_unpaid_request(req):
    if (
        req.get('payment_mode') == 'upi'
        and req['status'] == 'Awaiting Payment'
        and time.time() >= req['expires_at']
    ):
        if not update_request(req, status='Expired'):
            return
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
    if SUPABASE_ENABLED and not os.path.isfile(filepath):
        delete_uploaded_file(filepath)
        return
    cleanup_timer = threading.Timer(
        PRINTED_UPLOAD_CLEANUP_DELAY_SECONDS,
        delete_uploaded_file,
        args=(filepath,),
    )
    cleanup_timer.daemon = True
    cleanup_timer.start()

def delete_uploaded_file(filepath):
    if SUPABASE_ENABLED and not os.path.isfile(filepath):
        supabase_request(
            f"/storage/v1/object/{quote(SUPABASE_STORAGE_BUCKET, safe='')}",
            method='DELETE',
            payload={'prefixes': [filepath]},
        )
        return
    try:
        os.remove(filepath)
    except FileNotFoundError:
        pass
    except OSError as error:
        print(f"Could not remove printed upload {filepath}: {error}")

def save_admin_password_hash(password_hash):
    if IS_VERCEL:
        recovery_redis.set(
            'auto-print:admin-password-hash',
            json.dumps({
                'base_hash': app.config['ADMIN_PASSWORD_HASH'],
                'password_hash': password_hash,
            }),
        )
        return
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

def get_recovery_challenge(challenge_id):
    if IS_VERCEL:
        challenge_data = recovery_redis.get(f'auto-print:recovery:{challenge_id}')
        return json.loads(challenge_data) if challenge_data else None
    return recovery_challenges.get(challenge_id)

def set_recovery_challenge(challenge_id, challenge):
    if IS_VERCEL:
        remaining = max(1, int(challenge['expires_at'] - time.time()))
        recovery_redis.set(
            f'auto-print:recovery:{challenge_id}',
            json.dumps(challenge),
            ex=remaining,
        )
        return
    recovery_challenges[challenge_id] = challenge

def delete_recovery_challenge(challenge_id):
    if IS_VERCEL:
        recovery_redis.delete(
            f'auto-print:recovery:{challenge_id}',
            f'auto-print:recovery-attempts:{challenge_id}',
        )
        return
    recovery_challenges.pop(challenge_id, None)

def reserve_recovery_send(phone_number, now):
    if IS_VERCEL:
        phone_key = recovery_otp_digest(phone_number)
        return recovery_redis.set(
            f'auto-print:recovery-cooldown:{phone_key}',
            str(now),
            nx=True,
            ex=RECOVERY_OTP_RESEND_SECONDS,
        )
    with recovery_send_lock:
        last_sent_at = recovery_send_times.get(phone_number, 0)
        if now - last_sent_at < RECOVERY_OTP_RESEND_SECONDS:
            return False
        recovery_send_times[phone_number] = now
        expired_challenges = [
            challenge_id
            for challenge_id, challenge in recovery_challenges.items()
            if now >= challenge['expires_at']
        ]
        for challenge_id in expired_challenges:
            recovery_challenges.pop(challenge_id, None)
        return True

def record_recovery_attempt(challenge_id, challenge):
    if IS_VERCEL:
        attempts_key = f'auto-print:recovery-attempts:{challenge_id}'
        attempts = recovery_redis.incr(attempts_key)
        if attempts == 1:
            recovery_redis.expire(attempts_key, RECOVERY_OTP_LIFETIME_SECONDS)
        return attempts
    challenge['attempts'] += 1
    return challenge['attempts']

def get_admin_password_hash():
    if IS_VERCEL:
        stored_hash = recovery_redis.get('auto-print:admin-password-hash')
        if stored_hash:
            override = json.loads(stored_hash)
            if override.get('base_hash') == os.environ['ADMIN_PASSWORD_HASH']:
                return override['password_hash']
    return app.config['ADMIN_PASSWORD_HASH']

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
    return render_template(
        'index.html',
        max_upload_size_mb=app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024),
    )

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
    if not uploaded_file or not uploaded_file.filename or not uploaded_file.filename.lower().endswith(('.jpg', '.jpeg', '.png', '.pdf')):
        return "A4 preview ke liye JPG, JPEG, PNG ya PDF file chahiye", 400
    try:
        side = request.form.get('side', 'front')
        if side not in ('front', 'back'):
            return "Preview side valid nahi hai", 400
        crop_mode = request.form.get(f'{side}_crop_mode', request.form.get('crop_mode', 'auto'))
        lighting_mode = request.form.get(f'{side}_lighting_mode', request.form.get('lighting_mode', 'auto'))
        margins = tuple(float(request.form.get(f'{side}_crop_{name}', 0)) for name in ('top', 'right', 'bottom', 'left'))
        brightness = float(request.form.get(f'{side}_brightness', request.form.get('brightness', 100))) / 100
        page_index = int(request.form.get('page', 0))
        fit_card = request.form.get('fit_card') == 'on'
        if crop_mode not in ('auto', 'manual') or lighting_mode not in ('auto', 'manual'):
            return "Crop ya lighting setting valid nahi hai", 400
        if page_index < 0:
            return "Requested PDF page does not exist", 400
        if any(not math.isfinite(value) or value < 0 or value >= 90 for value in margins):
            return "Crop margin 0 se 90 percent se kam rakhein", 400
        if margins[1] + margins[3] >= 90 or margins[0] + margins[2] >= 90:
            return "Crop margins document ko chhota kar rahe hain", 400
        if not math.isfinite(brightness) or not 0.5 <= brightness <= 1.5:
            return "Brightness 50 se 150 percent ke beech rakhein", 400
        try:
            perspective_points = get_perspective_points(request.form, side)
        except ValueError as error:
            return str(error), 400
        if uploaded_file.filename.lower().endswith('.pdf'):
            with fitz.open(stream=uploaded_file.read(), filetype='pdf') as document:
                if page_index >= document.page_count:
                    return "Requested PDF page does not exist", 400
                pixmap = document[page_index].get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
                image = Image.open(io.BytesIO(pixmap.tobytes('png'))).convert('RGB')
        else:
            image = ImageOps.exif_transpose(Image.open(uploaded_file)).convert('RGB')
        image = crop_and_adjust_image(
            image, crop_mode, margins, lighting_mode, brightness, perspective_points
        )
        if fit_card:
            image = ImageOps.fit(
                image,
                (
                    max(1, round(AADHAAR_CARD_SIZE[0] * 120 / 72)),
                    max(1, round(AADHAAR_CARD_SIZE[1] * 120 / 72)),
                ),
                method=Image.Resampling.LANCZOS,
            )
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
    uploaded_files = request.files.getlist('files')
    if not uploaded_files:
        uploaded_files = request.files.getlist('file')
    uploaded_files = [uploaded_file for uploaded_file in uploaded_files if uploaded_file and uploaded_file.filename]
    aadhaar_pair = request.form.get('aadhaar_pair') == 'on'
    same_image_back = request.form.get('same_image_back') == 'on'
    separate_images_back = request.form.get('separate_images_back') == 'on'
    back_file = request.files.get('back_file')
    if not uploaded_files:
        return "कृपया फाइल चुनें", 400
    if separate_images_back:
        if (
            not aadhaar_pair
            or same_image_back
            or len(uploaded_files) != 2
            or any(not uploaded_file.filename.lower().endswith(('.jpg', '.jpeg', '.png')) for uploaded_file in uploaded_files)
            or (back_file and back_file.filename)
        ):
            return "Aadhaar front/back ke liye Aadhaar pair chunein aur theek 2 JPG ya PNG images ek saath upload karein", 400
        back_file = uploaded_files[1]
        uploaded_files = uploaded_files[:1]
    if len(uploaded_files) > 10:
        return "एक order mein adhiktam 10 files upload karein", 400
    file = uploaded_files[0]
    payment_mode = request.form.get('payment_mode')  # 'upi' or 'cash'
    print_type = request.form.get('print_type', 'Black & White')
    paper_size = request.form.get('paper_size', 'A4')
    crop_mode = request.form.get('crop_mode', 'auto')
    lighting_mode = request.form.get('lighting_mode', 'auto')
    id_card_a4 = request.form.get('id_card_a4') == 'on'
    image_a4 = request.form.get('image_a4') == 'on'
    a4_custom_layout = request.form.get('a4_custom_layout') == 'on'
    if len(uploaded_files) > 1 and (aadhaar_pair or id_card_a4 or image_a4 or a4_custom_layout):
        return "Aadhaar pair, ID card aur A4 custom layout ek hi document ke liye hain", 400
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
    try:
        front_perspective = get_perspective_points(request.form, 'front')
        back_perspective = get_perspective_points(request.form, 'back')
    except ValueError as error:
        return str(error), 400
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
    if any(value < 0 or value >= 90 for value in margins):
        return "Crop margin 0 se 90 percent se kam rakhein", 400
    if any(value < 0 or value >= 90 for value in back_margins):
        return "Back-side crop margin 0 se 90 percent se kam rakhein", 400
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
    billable_file_count = len(uploaded_files) + int(
        bool(aadhaar_pair and back_file and back_file.filename)
    )
    price_per_file = 10
    total_amount = price_per_file * billable_file_count * copies

    if any(not allowed_file(uploaded_file.filename) for uploaded_file in uploaded_files):
        return "सिर्फ PDF या JPG/PNG फाइल अपलोड करें", 400
    if back_file and back_file.filename and not allowed_file(back_file.filename):
        return "Back side ke liye bhi PDF ya JPG/PNG file chahiye", 400
    if same_image_back and (
        not aadhaar_pair
        or not file.filename.lower().endswith(('.jpg', '.jpeg', '.png'))
        or (back_file and back_file.filename)
    ):
        return "Same photo front/back option ke liye Aadhaar pair mein ek JPG ya PNG photo chunein", 400

    source_paths = []
    document_paths = []
    preparation_error = None
    try:
        for uploaded_file in uploaded_files:
            safe_filename = secure_filename(uploaded_file.filename)
            if not safe_filename:
                raise ValueError('Filename valid nahi hai.')
            document_path = os.path.join(
                app.config['UPLOAD_FOLDER'],
                f"{uuid.uuid4().hex}_{safe_filename}",
            )
            uploaded_file.save(document_path)
            source_paths.append(document_path)
            document_paths.append(document_path)

        back_filepath = None
        if aadhaar_pair and same_image_back:
            back_filepath = document_paths[0]
        elif aadhaar_pair and back_file and back_file.filename:
            back_filename = secure_filename(back_file.filename)
            back_filepath = os.path.join(
                app.config['UPLOAD_FOLDER'],
                f"{uuid.uuid4().hex}_{back_filename}",
            )
            back_file.save(back_filepath)
            source_paths.append(back_filepath)

        if len(document_paths) > 1:
            processed_filepath = render_print_pdf_batch(
                document_paths,
                paper_size,
                crop_mode,
                margins,
                lighting_mode,
                brightness,
                print_type,
            )
        else:
            processed_filepath = render_print_pdf(
                document_paths[0],
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
                print_type,
                front_perspective,
                back_perspective,
            )
    except Exception as error:
        preparation_error = str(error)
    if preparation_error is not None:
        for source_path in source_paths:
            delete_uploaded_file(source_path)
        print(f"Document preparation failed: {preparation_error}")
        return "File prepare nahi ho saki. File format aur crop settings check karein.", 400

    filename = secure_filename(file.filename)
    if len(uploaded_files) > 1:
        filename = f"{filename} + {len(uploaded_files) - 1} aur files"
    elif aadhaar_pair:
        back_label = (
            'same photo'
            if same_image_back
            else secure_filename(back_file.filename) if back_file and back_file.filename else '2-page PDF'
        )
        filename = f"{filename} + {back_label} (Aadhaar front + back)"
    elif id_card_a4:
        filename = f"{filename} (ID card · single side)"
    print_filepaths = [processed_filepath, *source_paths]
    qr_filename = None
    qr_path = None
    if payment_mode == 'upi':
        qr_filename = f"{uuid.uuid4().hex}_qr.png"
        qr_directory = UPLOAD_FOLDER if IS_VERCEL else app.static_folder
        qr_path = os.path.join(qr_directory, qr_filename)
        try:
            with open(qr_path, 'wb') as qr_file:
                qr_file.write(create_merchant_payment_qr(total_amount))
        except Exception as error:
            for source_path in print_filepaths:
                delete_uploaded_file(source_path)
            if os.path.isfile(qr_path):
                delete_uploaded_file(qr_path)
            print(f"Payment QR creation failed: {error}")
            return "Payment QR nahi ban saka. Kripya dobara try karein.", 500

    req_data = {
        'filename': filename,
        'filepath': processed_filepath,
        'source_paths': source_paths,
        'print_type': print_type,
        'copies': copies,
        'document_count': billable_file_count,
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
    if SUPABASE_ENABLED:
        uploaded_keys = []
        try:
            path_map = {}
            for local_path in [*print_filepaths, *([qr_path] if qr_path else [])]:
                storage_key = f"{uuid.uuid4().hex}_{os.path.basename(local_path)}"
                content_type = 'image/png' if local_path == qr_path else 'application/pdf' if local_path == processed_filepath or local_path.lower().endswith('.pdf') else 'image/jpeg'
                upload_job_file(local_path, storage_key, content_type)
                uploaded_keys.append(storage_key)
                path_map[local_path] = storage_key
            req_data['filepath'] = path_map[processed_filepath]
            req_data['source_paths'] = [path_map[path] for path in source_paths]
            if qr_path:
                req_data['qr_path'] = path_map[qr_path]
        except (OSError, RuntimeError) as error:
            for storage_key in uploaded_keys:
                delete_uploaded_file(storage_key)
            for local_path in [*print_filepaths, *([qr_path] if qr_path else [])]:
                delete_uploaded_file(local_path)
            print(f"Supabase file upload failed: {error}")
            return "फाइल सुरक्षित नहीं हो सकी। कृपया कुछ देर बाद दोबारा कोशिश करें।", 503
        for local_path in [*print_filepaths, *([qr_path] if qr_path else [])]:
            delete_uploaded_file(local_path)

    try:
        req_data = create_request(req_data)
    except RuntimeError as error:
        print(f"Print request storage failed: {error}")
        for filepath in [req_data['filepath'], *req_data.get('source_paths', [])]:
            schedule_uploaded_file_cleanup(filepath)
        if req_data.get('qr_path'):
            schedule_uploaded_file_cleanup(req_data['qr_path'])
        return "Print request सुरक्षित नहीं हो सकी। कृपया दोबारा कोशिश करें।", 503

    if payment_mode == 'upi':
        return render_template(
            'payment.html',
            total_amount=total_amount,
            document_count=billable_file_count,
            copies=copies,
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
        configured_password_hash = get_admin_password_hash()
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
                if not reserve_recovery_send(entered_phone, now):
                    error = 'Naya OTP bhejne se pehle ek minute intezar karein.'
                if not error:
                    otp = f"{secrets.randbelow(1_000_000):06d}"
                    if send_whatsapp_otp(entered_phone, otp):
                        challenge_id = secrets.token_urlsafe(24)
                        set_recovery_challenge(challenge_id, {
                            'otp_digest': recovery_otp_digest(otp),
                            'expires_at': now + RECOVERY_OTP_LIFETIME_SECONDS,
                            'attempts': 0,
                            'verified_at': None,
                        })
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
    challenge = get_recovery_challenge(challenge_id) if challenge_id else None
    if not challenge or time.time() >= challenge['expires_at']:
        session.pop('recovery_challenge_id', None)
        if challenge_id:
            delete_recovery_challenge(challenge_id)
        return redirect(url_for('admin_forgot_password'))

    error = None
    if request.method == 'POST':
        if challenge.get('attempts', 0) >= RECOVERY_OTP_MAX_ATTEMPTS:
            delete_recovery_challenge(challenge_id)
            session.pop('recovery_challenge_id', None)
            return redirect(url_for('admin_forgot_password'))
        submitted_otp = request.form.get('otp', '').strip()
        if len(submitted_otp) != 6 or not submitted_otp.isdigit() or not hmac.compare_digest(
            recovery_otp_digest(submitted_otp), challenge['otp_digest']
        ):
            attempts = record_recovery_attempt(challenge_id, challenge)
            if attempts >= RECOVERY_OTP_MAX_ATTEMPTS:
                delete_recovery_challenge(challenge_id)
                session.pop('recovery_challenge_id', None)
                return redirect(url_for('admin_forgot_password'))
            if not IS_VERCEL:
                set_recovery_challenge(challenge_id, challenge)
            error = 'OTP sahi nahi hai. Dobara check karein.'
        else:
            challenge['verified_at'] = time.time()
            set_recovery_challenge(challenge_id, challenge)
            session['recovery_verified'] = True
            return redirect(url_for('admin_reset_password'))
    return render_template('admin_verify_otp.html', error=error)

@app.route('/admin/reset-password', methods=['GET', 'POST'])
def admin_reset_password():
    challenge_id = session.get('recovery_challenge_id')
    challenge = get_recovery_challenge(challenge_id) if challenge_id else None
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
        elif PUBLIC_MODE and hmac.compare_digest(new_password, 'Admin@12345'):
            error = 'Temporary admin password use na karein.'
        else:
            save_admin_password_hash(generate_password_hash(new_password))
            delete_recovery_challenge(challenge_id)
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
    requests = get_all_requests()
    for req in requests:
        expire_unpaid_request(req)
    return render_template('admin.html', requests=requests)

@app.route('/admin/request/<int:req_id>/preview')
@admin_required
def admin_request_preview(req_id):
    req = get_request(req_id)
    if not req:
        return "Print request nahi mili.", 404
    expire_unpaid_request(req)
    filepath = req.get('filepath')
    if not filepath:
        return "Is request ki PDF preview ab available nahi hai.", 404
    if SUPABASE_ENABLED:
        response = send_file(
            io.BytesIO(download_job_file(filepath)),
            mimetype='application/pdf',
            as_attachment=False,
            download_name=f"print-request-{req_id}.pdf",
            conditional=True,
        )
    else:
        if not os.path.isfile(filepath):
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

@app.route('/payment/<int:req_id>/qr')
def payment_qr(req_id):
    req = get_request(req_id)
    if not req:
        return "Payment QR nahi mili.", 404
    expire_unpaid_request(req)
    if req.get('payment_mode') != 'upi' or req['status'] == 'Expired':
        return "Payment QR nahi mili.", 404
    response = send_file(
        io.BytesIO(create_merchant_payment_qr(req['total_amount'])),
        mimetype='image/png',
        max_age=0,
    )
    response.headers['Cache-Control'] = 'private, no-store'
    return response

@app.route('/payment/<int:req_id>/status')
def payment_status(req_id):
    req = get_request(req_id)
    if not req:
        return jsonify({'success': False, 'message': 'रिक्वेस्ट नहीं मिली!'}), 404
    expire_unpaid_request(req)
    return jsonify({'status': req['status']})

def print_agent_is_local():
    if IS_VERCEL:
        token = os.environ['PRINT_AGENT_TOKEN']
        authorization = request.headers.get('Authorization', '')
        return hmac.compare_digest(authorization, f'Bearer {token}')
    return request.remote_addr in ('127.0.0.1', '::1')

@app.route('/get_next_job')
def get_next_job():
    if not print_agent_is_local():
        return jsonify({'success': False, 'message': 'यह endpoint केवल local print agent के लिए है।'}), 403

    now = time.time()
    job = next((
        item for item in get_all_requests()
        if item['status'] == 'Printing'
        or (
            item['status'] == 'Agent Printing'
            and now - (item.get('agent_claimed_at') or 0) >= 900
        )
    ), None)
    if not job:
        return jsonify(None)
    if job['status'] == 'Agent Printing':
        if not update_request(job, status='Printing', agent_claimed_at=None):
            return jsonify(None)
    if not update_request(job, status='Agent Printing', agent_claimed_at=now):
        return jsonify(None)
    if SUPABASE_ENABLED:
        try:
            file_url = signed_job_file_url(job['filepath'])
        except RuntimeError:
            update_request(job, status='Printing', agent_claimed_at=None)
            raise
        return jsonify({'id': job['id'], 'file_url': file_url})
    return jsonify({
        'id': job['id'],
        'file_path': os.path.abspath(job['filepath']),
        'paper_size': job.get('paper_size', 'A4'),
        'duplex': job.get('duplex', False),
        'copies': job.get('copies', 1),
        'print_type': job.get('print_type', 'Black & White'),
    })

@app.route('/update_job_status', methods=['POST'])
@csrf.exempt
def update_job_status():
    if not print_agent_is_local():
        return jsonify({'success': False, 'message': 'यह endpoint केवल local print agent के लिए है।'}), 403

    data = request.get_json(silent=True)
    if (
        not isinstance(data, dict)
        or type(data.get('job_id')) is not int
        or data.get('status') not in ('Printed', 'Retry')
    ):
        return jsonify({'success': False, 'message': 'Job ID या status मान्य नहीं है।'}), 400

    job = get_request(data['job_id'])
    if not job:
        return jsonify({'success': False, 'message': 'Print request नहीं मिली।'}), 404
    if job['status'] != 'Agent Printing':
        return jsonify({'success': False, 'message': 'यह request print के लिए उपलब्ध नहीं है।'}), 409

    new_status = 'Approved & Printed' if data['status'] == 'Printed' else 'Printing'
    updates = {'status': new_status}
    if new_status == 'Printing':
        updates['agent_claimed_at'] = None
    if not update_request(job, **updates):
        return jsonify({'success': False, 'message': 'इस job का status पहले ही बदल चुका है।'}), 409

    if new_status == 'Approved & Printed':
        cleanup_paths = [job['filepath'], *job.get('source_paths', [])]
        if job.get('qr_path'):
            cleanup_paths.append(job['qr_path'])
        for filepath in cleanup_paths:
            delete_uploaded_file(filepath)

    return jsonify({'success': True, 'status': new_status})

@app.route('/payment/<int:req_id>/report', methods=['POST'])
def report_payment(req_id):
    req = get_request(req_id)
    if not req:
        return jsonify({'success': False, 'message': 'रिक्वेस्ट नहीं मिली!'}), 404
    expire_unpaid_request(req)
    if req['status'] == 'Expired':
        return jsonify({'success': False, 'message': 'पेमेंट का समय समाप्त हो गया है।'}), 410
    if req['status'] == 'Awaiting Payment':
        if not update_request(req, status='Payment Reported', payment_reported_at=time.time()):
            return jsonify({'success': False, 'message': 'पेमेंट की request पहले ही update हो चुकी है।'}), 409
    return jsonify({'success': True, 'status': req['status']})

# 4. कैश अप्रूव करके प्रिंट देने का रूट (Admin Action)
@app.route('/approve/<int:req_id>', methods=['POST'])
@admin_required
def approve_print(req_id):
    req = get_request(req_id)
    if req:
        expire_unpaid_request(req)
        is_cash_pending = req['payment_mode'] == 'cash' and req['status'] == 'Pending'
        is_upi_verifiable = req['payment_mode'] == 'upi' and req['status'] == 'Payment Reported'
        if is_cash_pending or is_upi_verifiable:
            if not update_request(req, status='Printing'):
                return jsonify({'success': False, 'message': 'रिक्वेस्ट पहले ही process हो रही है।'}), 409
            return jsonify({'success': True, 'message': 'प्रिंट रिक्वेस्ट agent queue में भेज दी गई है!'})
    return jsonify({'success': False, 'message': 'रिक्वेस्ट नहीं मिली!'})

@app.route('/cancel/<int:req_id>', methods=['POST'])
@admin_required
def cancel_print(req_id):
    req = get_request(req_id)
    if not req:
        return jsonify({'success': False, 'message': 'रिक्वेस्ट नहीं मिली!'}), 404
    if req['status'] not in ('Pending', 'Awaiting Payment', 'Payment Reported', 'Printing'):
        return jsonify({
            'success': False,
            'message': 'यह request cancel नहीं हो सकती; हो सकता है agent ने इसे पहले ही print के लिए ले लिया हो।',
        }), 409
    if not update_request(req, status='Cancelled', agent_claimed_at=None):
        return jsonify({
            'success': False,
            'message': 'Request उसी समय process हो गई। Status refresh करके जाँचें।',
        }), 409
    cleanup_paths = [req['filepath'], *req.get('source_paths', [])]
    if req.get('qr_path'):
        cleanup_paths.append(req['qr_path'])
    for filepath in cleanup_paths:
        schedule_uploaded_file_cleanup(filepath)
    return jsonify({'success': True, 'message': 'Print request cancel कर दी गई है।'})

def print_lan_urls(port):
    try:
        interfaces = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError as error:
        print(f"Could not detect LAN IP addresses: {error}")
        return
    addresses = set()
    for interface in interfaces:
        address = ipaddress.ip_address(interface[4][0])
        if address.is_private and not address.is_loopback and not address.is_link_local:
            addresses.add(str(address))
    if addresses:
        for address in sorted(addresses):
            print(f"Open on a phone connected to the same Wi-Fi: http://{address}:{port}")
    else:
        print("LAN IP address not detected. Check the computer's Wi-Fi connection.")
    print("If the page does not open, allow this app through Windows Firewall on Private networks.")

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

        port = int(os.environ.get('PORT', '5000'))
        if not IS_VERCEL:
            print_lan_urls(port)
        serve(app, host='127.0.0.1' if IS_VERCEL else '0.0.0.0', port=port)
    else:
        port = 5000
        print_lan_urls(port)
        app.run(host='0.0.0.0', port=port, debug=False)