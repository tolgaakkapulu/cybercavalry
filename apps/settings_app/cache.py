from django.core.cache import cache


class SettingsCache:
    """Cached access to platform settings."""
    TTL = 60  # seconds

    @classmethod
    def get(cls, key, default=None):
        cache_key = f'cybercavalry_setting_{key}'
        # Cache backend may be unavailable (e.g. DatabaseCache table not yet
        # created). Never let that bubble up — fall back to the DB instead.
        try:
            val = cache.get(cache_key)
        except Exception:
            val = None
        if val is None:
            from .models import Setting
            try:
                s = Setting.objects.get(key=key)
                val = s.typed_value()
                try:
                    cache.set(cache_key, val, cls.TTL)
                except Exception:
                    pass  # cache write best-effort
            except Setting.DoesNotExist:
                return default
            except Exception:
                return default
        return val

    @classmethod
    def invalidate(cls, key):
        cache.delete(f'cybercavalry_setting_{key}')

    @classmethod
    def invalidate_all(cls):
        """Invalidate all setting caches (called on bulk settings save)."""
        from .models import Setting
        for s in Setting.objects.values_list('key', flat=True):
            cls.invalidate(s)
