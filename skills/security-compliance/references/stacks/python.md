# Python (Django / Flask / FastAPI)

Detección: `pyproject.toml`, `requirements.txt`, `setup.py`, `Pipfile`. Lockfile: `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements.txt` con `==`.

- **Autorización:** Django `permission_required`/`LoginRequiredMixin`/DRF `permission_classes` y `DEFAULT_PERMISSION_CLASSES` globales; FastAPI `Depends(...)` a nivel de router/aplicación; Flask `before_request`.
- **Inyección:** `cursor.execute(f"…")`, `.raw()`/`.extra()` con interpolación, `subprocess(..., shell=True)`, `eval/exec`, `yaml.load` sin `SafeLoader`, `pickle.loads`.
- **Config:** `DEBUG=True`, `ALLOWED_HOSTS=['*']`, `SECRET_KEY` embebida, `verify=False` en `requests`, CSRF desactivado (`@csrf_exempt`).
- **Cripto:** `hashlib.md5/sha1` para contraseñas, `random` en lugar de `secrets` para tokens.
- **Plantillas:** `|safe`, `mark_safe`, `autoescape off`.
