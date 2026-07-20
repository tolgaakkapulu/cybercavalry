from django import forms
from .models import BlacklistEntry, BlacklistGroup
from .utils import normalize_cidr, is_valid_ip_or_cidr


class BlacklistEntryForm(forms.ModelForm):
    ip_input = forms.CharField(
        label="IP Address or CIDR",
        help_text="E.g., 192.168.1.1, 10.0.0.0/24, or 203.0.113.0/32",
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': '192.168.1.1 or 10.0.0.0/24'})
    )

    class Meta:
        model = BlacklistEntry
        fields = ['group', 'reason']
        widgets = {
            'group': forms.Select(attrs={'class': 'form-select'}),
            'reason': forms.Textarea(attrs={'class': 'form-input', 'rows': 3, 'placeholder': 'Optional reason...'}),
        }

    def clean_ip_input(self):
        value = self.cleaned_data['ip_input']
        if not is_valid_ip_or_cidr(value):
            raise forms.ValidationError(f"'{value}' is not a valid IP address or CIDR notation.")
        cidr, ip, prefix = normalize_cidr(value)
        self.cleaned_data['_cidr'] = cidr
        self.cleaned_data['_ip'] = ip
        self.cleaned_data['_prefix'] = prefix
        return value

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.cidr = self.cleaned_data['_cidr']
        instance.ip_address = self.cleaned_data['_ip']
        instance.prefix_length = self.cleaned_data['_prefix']
        instance.set_expiry_from_group()
        if commit:
            instance.save()
        return instance


class BulkBlacklistForm(forms.Form):
    ip_list = forms.CharField(
        label="IP Addresses / CIDRs",
        help_text="One IP or CIDR per line. Max 500 entries.",
        widget=forms.Textarea(attrs={
            'class': 'form-input font-mono',
            'rows': 10,
            'placeholder': '192.168.1.1\n10.0.0.0/24\n203.0.113.5'
        })
    )
    group = forms.ModelChoiceField(
        queryset=BlacklistGroup.objects.all(),
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    reason = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'Optional reason for all entries'})
    )

    def clean_ip_list(self):
        raw = self.cleaned_data['ip_list']
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        if len(lines) > 500:
            raise forms.ValidationError("Maximum 500 entries per bulk import.")
        valid = []
        invalid = []
        for line in lines:
            if not is_valid_ip_or_cidr(line):
                invalid.append(line)
            else:
                valid.append(line)
        if invalid:
            raise forms.ValidationError(f"Invalid entries: {', '.join(invalid[:10])}")
        return valid
