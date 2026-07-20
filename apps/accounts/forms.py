import re
from django import forms
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from .models import Role


def validate_password_policy(password):
    """
    Returns an error message string if the password fails the configured
    policy, or None if the password is acceptable.
    Policy values are read from SettingsCache (security.password_* keys)
    with sensible hard-coded defaults as fallback.
    """
    try:
        from apps.settings_app.cache import SettingsCache
        min_length        = int(SettingsCache.get('security.password_min_length', 8) or 8)
        req_uppercase     = SettingsCache.get('security.password_require_uppercase', True)
        req_lowercase     = SettingsCache.get('security.password_require_lowercase', True)
        req_digits        = SettingsCache.get('security.password_require_digits', True)
        req_symbols       = SettingsCache.get('security.password_require_symbols', True)
    except Exception:
        min_length, req_uppercase, req_lowercase, req_digits, req_symbols = 8, True, True, True, True

    if len(password) < min_length:
        return f"Password must be at least {min_length} characters."
    if req_digits and not re.search(r'[0-9]', password):
        return "Password must contain at least one digit (0–9)."
    if req_lowercase and not re.search(r'[a-z]', password):
        return "Password must contain at least one lowercase letter."
    if req_uppercase and not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter."
    if req_symbols and not re.search(r'[^a-zA-Z0-9]', password):
        return "Password must contain at least one symbol (e.g. !@#$%)."
    return None


class LoginForm(forms.Form):
    username = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'Username', 'autofocus': True})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-input', 'placeholder': 'Password'})
    )
    remember_me = forms.BooleanField(required=False, widget=forms.CheckboxInput(attrs={'class': 'form-checkbox'}))

    def __init__(self, request=None, *args, **kwargs):
        self.request = request
        self.user_cache = None
        super().__init__(*args, **kwargs)

    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        if username and password:
            self.user_cache = authenticate(self.request, username=username, password=password)
            if self.user_cache is None:
                raise forms.ValidationError("Invalid username or password.")
            if not self.user_cache.is_active:
                raise forms.ValidationError("Invalid username or password.")
        return self.cleaned_data

    def get_user(self):
        return self.user_cache


class UserCreateForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-input'}))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-input'}))
    role = forms.ModelChoiceField(
        queryset=Role.objects.all(),
        widget=forms.Select(attrs={'class': 'form-select'}),
        required=False
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-input'}),
            'email': forms.EmailInput(attrs={'class': 'form-input'}),
            'first_name': forms.TextInput(attrs={'class': 'form-input'}),
            'last_name': forms.TextInput(attrs={'class': 'form-input'}),
        }

    def clean_username(self):
        username = self.cleaned_data.get('username', '').strip()
        if User.objects.filter(username__iexact=username).exists():
            raise forms.ValidationError(
                f"A user with the username '{username}' already exists. Please choose a different username."
            )
        return username

    def clean(self):
        cleaned_data = super().clean()
        p1 = cleaned_data.get('password')
        p2 = cleaned_data.get('confirm_password')
        if p1:
            error = validate_password_policy(p1)
            if error:
                raise forms.ValidationError(error)
        if p1 and p2 and p1 != p2:
            raise forms.ValidationError("Passwords do not match.")
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password'])
        if commit:
            user.save()
            if self.cleaned_data.get('role'):
                profile = user.profile
                profile.role = self.cleaned_data['role']
                profile.save()
        return user


class UserRoleForm(forms.Form):
    role = forms.ModelChoiceField(
        queryset=Role.objects.all(),
        widget=forms.Select(attrs={'class': 'form-select'}),
        required=False,
        empty_label="— No Role —"
    )
