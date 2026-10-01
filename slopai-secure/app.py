import functools
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
import click
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import SecurityError
from werkzeug.security import check_password_hash, generate_password_hash
from catalog import CATEGORIES, PARTS, PRESETS, resolve, compatibility, price
from security import LOOPBACK_HOSTS, has_controls, local_secret, private_database, private_directory, same_origin


def create_app(test_config=None, *, instance_path=None):
    app = Flask(__name__, instance_relative_config=True, instance_path=instance_path)
    mode = os.environ.get('APP_ENV', 'local')
    app.config.update(APP_ENV=mode, SECRET_KEY=os.environ.get('SECRET_KEY'),
                      DATABASE=str(Path(app.instance_path) / 'slopai.sqlite3'),
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
                      SESSION_COOKIE_SECURE=mode == 'production' or os.getenv('COOKIE_SECURE') == '1',
                      PERMANENT_SESSION_LIFETIME=timedelta(days=7), MAX_CONTENT_LENGTH=32 * 1024)
    app.config.update(
        TRUSTED_HOSTS=[h.strip() for h in os.getenv('TRUSTED_HOSTS', 'localhost,127.0.0.1,[::1]').split(',') if
                       h.strip()],
        MAX_FORM_MEMORY_SIZE=32 * 1024, MAX_FORM_PARTS=40,
        SESSION_REFRESH_EACH_REQUEST=False,
    )
    if test_config:
        app.config.update(test_config)

    mode = app.config['APP_ENV']
    if mode not in ('local', 'production'):
        raise RuntimeError('APP_ENV должен быть local или production.')
    if not app.config['TRUSTED_HOSTS']:
        raise RuntimeError('TRUSTED_HOSTS не должен быть пустым.')
    if mode == 'production':
        if not app.config['SECRET_KEY']:
            raise RuntimeError('В production требуется новый случайный SECRET_KEY из окружения.')
        if (not app.config['SESSION_COOKIE_SECURE'] or os.getenv('COOKIE_SECURE') == '0'
                or app.config['DEBUG']):
            raise RuntimeError('В production обязательны Secure-cookie и отключённый DEBUG.')
        app.config['SESSION_COOKIE_NAME'] = '__Host-session'
        app.config['SESSION_COOKIE_DOMAIN'] = None
        app.config['SESSION_COOKIE_PATH'] = '/'
    elif any(host not in LOOPBACK_HOSTS for host in app.config['TRUSTED_HOSTS']):
        raise RuntimeError('Для сетевого размещения задайте APP_ENV=production и HTTPS.')

    # Test configuration is applied before touching any real instance or key.
    if not app.config.get('TESTING') or not app.config['SECRET_KEY']:
        directory = private_directory(app.instance_path)
        if not app.config['SECRET_KEY']:
            app.config['SECRET_KEY'] = local_secret(directory)
    if len(app.config['SECRET_KEY']) < 32 and not app.config.get('TESTING'):
        raise RuntimeError('SECRET_KEY должен содержать не менее 32 символов.')
    private_database(app.config['DATABASE'])
    dummy_hash = generate_password_hash(secrets.token_hex(32))

    def db():
        if 'db' not in g:
            g.db = sqlite3.connect(app.config['DATABASE'], timeout=15)
            g.db.row_factory = sqlite3.Row
            g.db.execute('PRAGMA foreign_keys = ON')
        return g.db

    @app.teardown_appcontext
    def close_db(error=None):
        connection = g.pop('db', None)
        if connection:
            connection.close()

    @app.cli.command('revoke-sessions')
    def revoke_sessions():
        """Revoke every login after a suspected leak; retain accounts and orders."""
        db().execute('DELETE FROM auth_sessions')
        db().commit()
        click.echo('Все активные сеансы отозваны.')

    with app.app_context():
        db().executescript('''
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), items TEXT NOT NULL, total INTEGER NOT NULL, phone TEXT NOT NULL, address TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Заявка принята', token TEXT UNIQUE NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS attempts (scope TEXT NOT NULL, stamp REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS attempts_scope ON attempts(scope, stamp);
        CREATE INDEX IF NOT EXISTS attempts_expiry ON attempts(stamp);
        CREATE TABLE IF NOT EXISTS auth_sessions (
            token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS auth_expiry ON auth_sessions(expires_at);
        CREATE TABLE IF NOT EXISTS order_receipts (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id));
        INSERT OR IGNORE INTO order_receipts(token, user_id) SELECT token, user_id FROM orders;
        CREATE INDEX IF NOT EXISTS orders_owner ON orders(user_id, id);
        CREATE TABLE IF NOT EXISTS order_sequence (singleton INTEGER PRIMARY KEY CHECK(singleton=1), last_id INTEGER NOT NULL);
        INSERT OR IGNORE INTO order_sequence(singleton,last_id) SELECT 1,COALESCE(MAX(id),0) FROM orders;
        UPDATE order_sequence SET last_id=MAX(last_id, (SELECT COALESCE(MAX(id),0) FROM orders)) WHERE singleton=1;

        ''')
        db().commit()

    def establish_session(user_id):
        cart = session.get('cart', [])
        if session.get('sid'):
            db().execute('DELETE FROM auth_sessions WHERE token_hash=?',
                         (hashlib.sha256(session['sid'].encode()).hexdigest(),))
        sid = secrets.token_urlsafe(32)
        now = time.time()
        db().execute('DELETE FROM auth_sessions WHERE expires_at < ?', (now,))
        db().execute('INSERT INTO auth_sessions(token_hash,user_id,expires_at) VALUES(?,?,?)',
                     (hashlib.sha256(sid.encode()).hexdigest(), user_id, now + 7 * 86400))
        db().commit()
        session.clear()
        session.update(sid=sid, cart=cart, csrf=secrets.token_hex(32))
        session.permanent = True

    @app.before_request
    def prepare():
        g.user = None
        # Preserve Host rejection before other guards try to render URLs.
        if isinstance(request.routing_exception, SecurityError):
            raise request.routing_exception
        if app.config['APP_ENV'] == 'production' and not request.is_secure:
            abort(400)
        if app.config['APP_ENV'] == 'local' and request.remote_addr not in ('127.0.0.1', '::1'):
            abort(403)
        session.setdefault('csrf', secrets.token_hex(32))
        if session.get('sid'):
            g.user = db().execute(
                'SELECT u.id,u.name,u.email FROM auth_sessions s JOIN users u ON u.id=s.user_id '
                'WHERE s.token_hash=? AND s.expires_at>?',
                (hashlib.sha256(session['sid'].encode()).hexdigest(), time.time())
            ).fetchone()
            if not g.user:
                session.pop('sid', None)
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            origin = request.headers.get('Origin')
            if origin is not None and not same_origin(origin, request.host_url):
                abort(403)
            # Reject non-ASCII/malformed tokens before constant-time comparison.
            token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token', '')
            if not re.fullmatch(r'[a-f0-9]{64}', token) or not secrets.compare_digest(session['csrf'], token):
                abort(400, description='Форма устарела. Обновите страницу и попробуйте ещё раз.')
            if request.headers.get('Sec-Fetch-Site') == 'cross-site':
                abort(403)

    @app.after_request
    def headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        response.headers[
            'Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
        if request.endpoint != 'static':
            response.headers['Cache-Control'] = 'no-store'
        return response

    @app.template_filter('rub')
    def rub(value):
        return f'{value:,.0f}'.replace(',', ' ') + ' ₽'

    @app.context_processor
    def context():
        return dict(user=getattr(g, 'user', None), csrf_token=session.get('csrf', ''),
                    cart_count=len(session.get('cart', [])), categories=CATEGORIES)

    def login_required(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            if not g.user:
                flash('Войдите в аккаунт, чтобы продолжить.', 'info')
                return redirect(url_for('login', next=request.path))
            return fn(*args, **kwargs)

        return wrapped

    def rate_limit(action='auth', identity=''):
        # Atomic counters across all Waitress threads; no user strings in SQL.
        now = time.time()
        ip = request.remote_addr or 'local'
        limits = [(f'{action}:ip:{ip}', 15 if action == 'auth' else 30)]
        if identity:
            limits.append((f'{action}:identity:{identity}', 15))
        secret = app.config['SECRET_KEY']
        if isinstance(secret, str):
            secret = secret.encode()
        scopes = [(hmac.new(secret, label.encode(), hashlib.sha256).hexdigest(), count)
                  for label, count in limits]
        connection = db()
        connection.execute('BEGIN IMMEDIATE')
        blocked = False
        try:
            connection.execute('DELETE FROM attempts WHERE stamp < ?', (now - 900,))
            for scope, limit in scopes:
                count = connection.execute(
                    'SELECT COUNT(*) FROM attempts WHERE scope=? AND stamp>?', (scope, now - 900)
                ).fetchone()[0]
                if count >= limit:
                    blocked = True
                    break
            if not blocked:
                connection.executemany('INSERT INTO attempts(scope,stamp) VALUES(?,?)',
                                       [(scope, now) for scope, _ in scopes])
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        if blocked:
            abort(429, description='Слишком много попыток. Попробуйте через 15 минут.')

    def safe_next():
        target = request.args.get('next', '')
        return target if target in ('/cart', '/checkout', '/account') else url_for('account')

    @app.route('/')
    def index():
        query = request.args.get('q', '').strip()[:80]
        purpose = request.args.get('purpose', '')
        sorting = request.args.get('sort', 'popular')
        cards = [dict(preset=p, parts=resolve(p), total=price(resolve(p))) for p in PRESETS]
        if query:
            cards = [c for c in cards if query.casefold() in (
                    c['preset']['name'] + ' ' + c['preset']['category'] + ' ' +
                    ' '.join(part['name'] for part in c['parts'].values())
            ).casefold()]
        if purpose in ('1080p', '1440p', '4K'):
            cards = [c for c in cards if c['preset']['label'] == purpose]
        if sorting in ('price_asc', 'price_desc'):
            cards.sort(key=lambda c: c['total'], reverse=sorting == 'price_desc')
        return render_template('index.html', title='Компьютеры под твои задачи', cards=cards,
                               query=query, purpose=purpose, sorting=sorting)

    @app.get('/computer/<preset_id>')
    def computer(preset_id):
        preset = next((p for p in PRESETS if p['id'] == preset_id), None)
        if not preset:
            abort(404)
        parts = resolve(preset)
        return render_template('computer.html', title='SlopAI ' + preset['name'],
                               preset=preset, parts=parts, total=price(parts))

    @app.get('/help')
    def help_page():
        return render_template('help.html', title='О сборке, доставке и гарантии')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if g.user:
            return redirect(url_for('account'))
        if request.method == 'POST':
            rate_limit(identity=request.form.get('email', '').strip().lower()[:254])
            name = request.form.get('name', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            if not 2 <= len(name) <= 60 or has_controls(name):
                flash('Имя должно содержать от 2 до 60 символов.', 'error')
            elif len(email) > 254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
                flash('Укажите корректный email.', 'error')
            elif not 12 <= len(password) <= 128:
                flash('Пароль должен содержать от 12 до 128 символов.', 'error')
            elif password != request.form.get('confirm'):
                flash('Пароли не совпадают.', 'error')
            else:
                try:
                    cursor = db().execute('INSERT INTO users(name,email,password_hash) VALUES(?,?,?)',
                                          (name, email, generate_password_hash(password)))
                    db().commit()
                    establish_session(cursor.lastrowid)
                    flash('Аккаунт создан. Добро пожаловать в SlopAI!', 'success')
                    return redirect(safe_next())
                except sqlite3.IntegrityError:
                    db().rollback()
                    flash('Не удалось создать аккаунт с этими данными. Проверьте email или попробуйте войти.', 'error')
        return render_template('auth.html', mode='register', title='Регистрация')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if g.user:
            return redirect(url_for('account'))
        if request.method == 'POST':
            rate_limit(identity=request.form.get('email', '').strip().lower()[:254])
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            row = db().execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            valid = check_password_hash(row['password_hash'] if row else dummy_hash, password[:128])
            if row and 1 <= len(password) <= 128 and len(email) <= 254 and valid:
                establish_session(row['id'])
                return redirect(safe_next())
            flash('Неверный email или пароль.', 'error')
        return render_template('auth.html', mode='login', title='Вход')

    @app.post('/logout')
    def logout():
        if session.get('sid'):
            db().execute('DELETE FROM auth_sessions WHERE token_hash=?',
                         (hashlib.sha256(session['sid'].encode()).hexdigest(),))
            db().commit()
        session.clear()
        return redirect(url_for('index'))

    @app.route('/configure')
    def configure():
        preset = next((p for p in PRESETS if p['id'] == request.args.get('preset')), PRESETS[1])
        return render_template('configure.html', title='Конфигуратор ПК', parts=PARTS, selected=preset)

    @app.post('/api/quote')
    def quote():
        try:
            parts = resolve(request.form)
        except ValueError as e:
            return jsonify(error=str(e)), 400
        errors, watts = compatibility(parts)
        return jsonify(total=price(parts), errors=errors, watts=watts, parts={k: v['name'] for k, v in parts.items()})

    def cart_items():
        result = []
        for selection in session.get('cart', []):
            try:
                parts = resolve(selection)
            except (ValueError, AttributeError):
                session['cart'] = []
                session.pop('checkout_token', None)
                flash('Каталог изменился. Соберите компьютер заново.', 'info')
                return []
            result.append(dict(selection=selection, parts=parts, total=price(parts)))
        return result

    @app.post('/cart/add')
    def add_cart():
        try:
            parts = resolve(request.form)
        except ValueError as e:
            abort(400, description=str(e))
        errors, _ = compatibility(parts)
        if errors:
            flash(' '.join(errors), 'error')
            return redirect(url_for('configure'))
        cart = session.get('cart', [])
        if len(cart) >= 5:
            flash('В корзине может быть не более 5 компьютеров.', 'error')
        else:
            cart.append({k: v['id'] for k, v in parts.items()})
            session['cart'] = cart
            session.pop('checkout_token', None)
            flash('Сборка добавлена в корзину.', 'success')
        return redirect(url_for('cart'))

    @app.route('/cart')
    def cart():
        items = cart_items()
        return render_template('cart.html', title='Корзина', items=items, total=sum(i['total'] for i in items))

    @app.post('/cart/remove/<int:index>')
    def remove_cart(index):
        cart = session.get('cart', [])
        if 0 <= index < len(cart):
            cart.pop(index)
            session['cart'] = cart
            session.pop('checkout_token', None)
        return redirect(url_for('cart'))

    @app.route('/checkout', methods=['GET', 'POST'])
    @login_required
    def checkout():
        items = cart_items()
        if not items:
            return redirect(url_for('cart'))
        session.setdefault('checkout_token', secrets.token_hex(24))
        total = sum(i['total'] for i in items)
        if request.method == 'POST':
            rate_limit('checkout', str(g.user['id']))
            phone = request.form.get('phone', '').strip()
            address = request.form.get('address', '').strip()
            if (not re.fullmatch(r'\+?[0-9 ()-]{10,30}', phone)
                    or not 10 <= len(re.sub(r'[^0-9]', '', phone)) <= 15):
                flash('Введите номер телефона с кодом страны.', 'error')
            elif not 10 <= len(address) <= 300 or has_controls(address):
                flash('Укажите город и адрес (от 10 до 300 символов).', 'error')
            elif request.form.get('checkout_token') != session['checkout_token']:
                abort(400, description='Заказ уже изменён. Обновите страницу.')
            else:
                for item in items:
                    if compatibility(item['parts'])[0]:
                        abort(400, description='В сборке есть несовместимые комплектующие.')
                snapshot = [dict(parts={k: dict(name=v['name'], price=v['price']) for k, v in item['parts'].items()},
                                 total=item['total']) for item in items]
                connection = db()
                connection.execute('BEGIN IMMEDIATE')
                try:
                    receipt = connection.execute(
                        'INSERT OR IGNORE INTO order_receipts(token,user_id) VALUES(?,?)',
                        (session['checkout_token'], g.user['id'])
                    )
                    if receipt.rowcount:
                        connection.execute('UPDATE order_sequence SET last_id=last_id+1 WHERE singleton=1')
                        new_id = connection.execute('SELECT last_id FROM order_sequence WHERE singleton=1').fetchone()[
                            0]
                        connection.execute(
                            'INSERT INTO orders(id,user_id,items,total,phone,address,token) VALUES(?,?,?,?,?,?,?)',
                            (new_id, g.user['id'], json.dumps(snapshot, ensure_ascii=False), total,
                             phone, address, session['checkout_token'])
                        )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
                session['cart'] = []
                session.pop('checkout_token', None)
                flash('Заявка сохранена. Её состав доступен в личном кабинете. Оплата не списывалась.', 'success')
                return redirect(url_for('account'))
        return render_template('checkout.html', title='Оформление заявки', items=items, total=total)

    @app.route('/account')
    @login_required
    def account():
        rows = db().execute('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC', (g.user['id'],)).fetchall()
        orders = [dict(row, items=json.loads(row['items'])) for row in rows]
        return render_template('account.html', title='Личный кабинет', orders=orders)

    @app.route('/orders/<int:order_id>/delete', methods=['GET', 'POST'])
    @login_required
    def delete_order(order_id):
        if order_id > 9223372036854775807:
            abort(404)
        order = db().execute('SELECT id,total,created_at FROM orders WHERE id=? AND user_id=?',
                             (order_id, g.user['id'])).fetchone()
        if order is None:
            abort(404)
        if request.method == 'POST':
            rate_limit('delete-order', str(g.user['id']))
            if request.form.get('confirm') != 'delete':
                abort(400, description='Подтвердите удаление заказа.')
            # Owner check is repeated in DELETE itself, not only in the interface.
            db().execute('DELETE FROM orders WHERE id=? AND user_id=?', (order_id, g.user['id']))
            db().commit()
            flash('Заказ удалён вместе с его составом и контактными данными.', 'success')
            return redirect(url_for('account'))
        return render_template('delete_order.html', title='Удаление заказа', order=order)

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(413)
    @app.errorhandler(429)
    @app.errorhandler(500)
    def error(e):
        if isinstance(e, SecurityError):
            # Host rejection happens before Flask can build internal URLs.
            return app.response_class('Bad Request: untrusted host.', status=400, mimetype='text/plain')
        descriptions = {
            400: 'Некорректный запрос или устаревшая форма. Обновите страницу.',
            403: 'Действие недоступно. Откройте форму на сайте и попробуйте ещё раз.',
            404: 'Страница или заказ не найдены.',
            405: 'Этот способ обращения к странице не поддерживается.',
            413: 'Слишком большой запрос. Сократите введённые данные.',
            429: 'Слишком много попыток. Попробуйте через 15 минут.',
            500: 'Не удалось выполнить действие. Попробуйте позже.'
        }
        message = descriptions.get(e.code, descriptions[500])
        if request.path.startswith('/api/'):
            response = jsonify(error=message)
        else:
            response = app.make_response(render_template(
                'error.html', title='Что-то пошло не так',
                error=SimpleNamespace(code=e.code, description=message)))
        response.status_code = e.code
        if e.code == 429:
            response.headers['Retry-After'] = '900'
        return response

    return app


if __name__ == '__main__':
    from waitress import serve

    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', 5000))
    app = create_app()
    if app.config['APP_ENV'] == 'local' and host not in ('127.0.0.1', '::1', 'localhost'):
        raise RuntimeError('Локальный режим разрешает только loopback HOST.')
    print(f'SlopAI: http://{host}:{port} — остановить: Ctrl+C', flush=True)
    serve(app, host=host, port=port, max_request_body_size=32 * 1024)
