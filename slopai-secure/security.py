"""Storage and configuration helpers; never ship runtime secrets with source."""
import os
import secrets
import stat
import tempfile
from pathlib import Path
from urllib.parse import urlsplit


LOOPBACK_HOSTS = ('localhost', '127.0.0.1', '[::1]')


def private_directory(path):
    path = Path(path)
    if path.is_symlink():
        raise RuntimeError('Каталог instance не должен быть символической ссылкой.')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == 'posix':
        path.chmod(0o700)
    return path


def local_secret(directory):
    """Publish a complete key atomically, including concurrent first starts."""
    key_path = directory / 'secret.key'
    fd, temporary = tempfile.mkstemp(prefix='.secret-', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='ascii') as stream:
            stream.write(secrets.token_hex(32))
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, key_path)
        except FileExistsError:
            pass
    finally:
        Path(temporary).unlink(missing_ok=True)
    if key_path.is_symlink() or not key_path.is_file():
        raise RuntimeError('Ожидался обычный файл ключа.')
    if os.name == 'posix':
        key_path.chmod(0o600)
    return key_path.read_text(encoding='ascii').strip()


def private_database(path):
    path = Path(path)
    if path.is_symlink():
        raise RuntimeError('База данных не должна быть символической ссылкой.')
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RuntimeError('Ожидался обычный файл базы данных.')
        if os.name == 'posix':
            os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def same_origin(origin, expected):
    def normalized(value):
        parsed = urlsplit(value)
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
            return None
        return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80)
    try:
        actual = normalized(origin)
        return actual is not None and actual == normalized(expected)
    except ValueError:
        return False


def has_controls(value):
    return any(ord(char) < 32 or ord(char) == 127 for char in value)
