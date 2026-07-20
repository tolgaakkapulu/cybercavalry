"""
CYBERCavalry PDF Report Generator
Requires: pip install reportlab>=4.2 svglib
"""
import html as _html
import io
import logging
import os
from datetime import timedelta

_logger = logging.getLogger(__name__)

from django.utils import timezone
from reportlab.lib.pagesizes import A4, landscape as rl_landscape
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame, NextPageTemplate,
    SimpleDocTemplate, Table, TableStyle, Paragraph,
    Spacer, HRFlowable, KeepTogether, PageBreak,
)
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.charts.linecharts import HorizontalLineChart

try:
    from svglib.svglib import svg2rlg
    from reportlab.graphics import renderPDF as _renderPDF
    _SVG_OK = True
except ImportError:
    _SVG_OK = False

# ── Logo path ──────────────────────────────────────────────────────────────
_LOGO_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    'static', 'img', 'logo.svg',
)


# ── Palette ────────────────────────────────────────────────────────────────
class _C:
    HDR_BG      = HexColor('#0D1117')
    HDR_ACCENT  = HexColor('#1F7EC4')
    # Brand suffix colour — applied wherever general.platform_name_suffix is
    # drawn (cover name). General report chrome keeps HDR_ACCENT (blue).
    BRAND_SUFFIX = HexColor('#ee5356')
    HDR_TEXT    = HexColor('#E6EDF3')
    HDR_MUTED   = HexColor('#8B949E')
    COL_HDR_BG  = HexColor('#21262D')
    COL_HDR_TXT = HexColor('#E6EDF3')
    ROW_ODD     = HexColor('#FFFFFF')
    ROW_EVEN    = HexColor('#F6F8FA')
    BORDER      = HexColor('#D0D7DE')
    TEXT        = HexColor('#1F2328')
    TEXT_MUTED  = HexColor('#57606A')

    SUCCESS_BG = HexColor('#DAFBE1'); SUCCESS_FG = HexColor('#1A7F37')
    DANGER_BG  = HexColor('#FFEBE9'); DANGER_FG  = HexColor('#CF222E')
    WARNING_BG = HexColor('#FFF8C5'); WARNING_FG = HexColor('#9A6700')
    INFO_BG    = HexColor('#DDF4FF'); INFO_FG    = HexColor('#0969DA')
    PURPLE_BG  = HexColor('#FBEFFF'); PURPLE_FG  = HexColor('#8250DF')
    PINK_BG    = HexColor('#FFEFF7'); PINK_FG    = HexColor('#C83C8C')
    AMBER_BG   = HexColor('#FFF3CD'); AMBER_FG   = HexColor('#9A6700')
    MUTED_BG   = HexColor('#EAEEF2'); MUTED_FG   = HexColor('#57606A')

    # Cover-specific
    COVER_SURFACE = HexColor('#1C2330')
    COVER_BORDER  = HexColor('#30363D')


# ── Platform names / email ─────────────────────────────────────────────────
def _get_platform_names():
    try:
        from apps.settings_app.cache import SettingsCache
        primary = SettingsCache.get('general.platform_name', 'CYBER') or 'CYBER'
        suffix  = SettingsCache.get('general.platform_name_suffix', 'Cavalry') or 'Cavalry'
    except Exception:
        primary, suffix = 'CYBER', 'Cavalry'
    return primary, suffix


def _brand_name():
    """Configured platform name (primary + suffix) for report headers/footers.
    Delegates to the central branding helper for a single source of truth."""
    try:
        from apps.settings_app.branding import platform_name
        return platform_name()
    except Exception:
        primary, suffix = _get_platform_names()
        return f'{primary}{suffix}'


def _draw_login_mark(canvas, page_w, bottom_y, max_w=90, max_h=26):
    """Centre-draw the uploaded login/sidebar mark above the cover footer.

    Pulls `general.brand_login` via uploaded_login_path() — when no image is
    uploaded, draws nothing (the cover keeps its original layout). Supports
    both SVG and raster uploads; raster preserves alpha for transparent logos.
    Returns True iff a mark was drawn.
    """
    try:
        from apps.settings_app.branding import uploaded_login_path
        p = uploaded_login_path()
    except Exception:
        p = None
    if not p:
        return False

    is_svg = p.lower().endswith('.svg')
    if is_svg and _SVG_OK:
        try:
            drawing = svg2rlg(p)
            if drawing and drawing.width and drawing.height:
                scale = min(max_w / drawing.width, max_h / drawing.height)
                drawing.width  *= scale
                drawing.height *= scale
                drawing.transform = (scale, 0, 0, scale, 0, 0)
                x = (page_w - drawing.width) / 2
                _renderPDF.draw(drawing, canvas, x, bottom_y)
                return True
        except Exception as exc:
            _logger.warning("PDF login-mark SVG render failed for %s: %s", p, exc)
    elif not is_svg:
        try:
            from reportlab.lib.utils import ImageReader
            img = ImageReader(p)
            iw, ih = img.getSize()
            if iw and ih:
                scale = min(max_w / iw, max_h / ih)
                dw, dh = iw * scale, ih * scale
                x = (page_w - dw) / 2
                canvas.drawImage(img, x, bottom_y, width=dw, height=dh,
                                 preserveAspectRatio=True, mask='auto')
                return True
        except Exception:
            pass
    return False


def _refresh_brand_suffix():
    """Resolve `general.brand_color` and update `_C.BRAND_SUFFIX` for this render.

    Called at the entry of every `generate_*` PDF function so report covers,
    headers and accents track whatever colour the admin picked in
    Settings → General. Falls back to the legacy purple on missing/invalid hex.
    """
    val = '#ee5356'
    try:
        from apps.settings_app.cache import SettingsCache
        import re as _re
        raw = (SettingsCache.get('general.brand_color', '#ee5356') or '#ee5356').strip()
        if _re.match(r'^#[0-9a-fA-F]{6}$', raw):
            val = raw
    except Exception:
        pass
    _C.BRAND_SUFFIX = HexColor(val)


def _get_platform_email():
    try:
        from apps.settings_app.cache import SettingsCache
        return SettingsCache.get('general.platform_email', '') or ''
    except Exception:
        return ''


# ── Small helpers ──────────────────────────────────────────────────────────
def _fmt(dt):
    if not dt:
        return '—'
    return timezone.localtime(dt).strftime('%Y-%m-%d %H:%M')


def _trunc(s, n=50):
    if not s:
        return '—'
    out = s if len(s) <= n else s[:n - 1] + '…'
    # ReportLab Paragraph parses an XML-like mini-markup; user-controlled free
    # text (reason, username) must be escaped or a '<', '&' etc. corrupts the
    # render or raises during doc.build() (report DoS / markup injection).
    return _html.escape(out)


def _added_by_display(user):
    """Return 'username (Full Name)' if full name exists, else just username."""
    if not user:
        return '—'
    username = user.username
    full_name = user.get_full_name()
    if full_name:
        return f'{username} ({full_name})'
    return username


def _source_col(src):
    return {
        'api':    (_C.INFO_BG,    _C.INFO_FG),
        'import': (_C.AMBER_BG,   _C.AMBER_FG),
        'manual': (_C.SUCCESS_BG, _C.SUCCESS_FG),
    }.get(src, (_C.MUTED_BG, _C.MUTED_FG))


def _group_col(name):
    return {
        '30d': (_C.PURPLE_BG, _C.PURPLE_FG),
        '24h': (_C.PINK_BG,   _C.PINK_FG),
    }.get(name, (_C.AMBER_BG, _C.AMBER_FG))


def _hash_type_col(ht):
    return {
        'md5':    (_C.INFO_BG,    _C.INFO_FG),
        'sha1':   (_C.AMBER_BG,   _C.AMBER_FG),
        'sha256': (_C.PURPLE_BG,  _C.PURPLE_FG),
        'sha512': (_C.PINK_BG,    _C.PINK_FG),
    }.get(ht, (_C.MUTED_BG, _C.MUTED_FG))


def _status_col(is_active, is_expired=False):
    if is_expired:
        return _C.WARNING_BG, _C.WARNING_FG
    return (_C.SUCCESS_BG, _C.SUCCESS_FG) if is_active else (_C.DANGER_BG, _C.DANGER_FG)


def _score_col(score, thr_high, thr_low):
    if score is None:
        return None, None
    if score >= thr_high:
        return _C.DANGER_BG, _C.DANGER_FG
    if score >= thr_low:
        return _C.WARNING_BG, _C.WARNING_FG
    return _C.SUCCESS_BG, _C.SUCCESS_FG


# ── Paragraph styles ───────────────────────────────────────────────────────
def _ps(name, **kw):
    defaults = dict(fontName='Helvetica', fontSize=8, textColor=_C.TEXT, leading=10)
    defaults.update(kw)
    return ParagraphStyle(name, **defaults)


_ST = {
    'cell':    _ps('cell', fontSize=7.5, leading=9),
    'cell_c':  _ps('cell_c', fontSize=7.5, leading=9, alignment=TA_CENTER),
    'cell_bold': _ps('cell_bold', fontSize=7.5, fontName='Helvetica-Bold', leading=9),
    'hdr':     _ps('hdr', fontSize=8, fontName='Helvetica-Bold',
                   textColor=_C.COL_HDR_TXT, alignment=TA_CENTER),
    'sect':    _ps('sect', fontSize=11, fontName='Helvetica-Bold', textColor=_C.TEXT),
    'sub':     _ps('sub', fontSize=8.5, textColor=_C.TEXT_MUTED),
    'stat_n':  _ps('stat_n', fontSize=22, fontName='Helvetica-Bold',
                   textColor=_C.TEXT, alignment=TA_CENTER, leading=26),
    'stat_l':  _ps('stat_l', fontSize=8, textColor=_C.TEXT_MUTED,
                   alignment=TA_CENTER, leading=10),
    'top_hdr': _ps('top_hdr', fontSize=7.5, fontName='Helvetica-Bold',
                   textColor=_C.COL_HDR_TXT, alignment=TA_CENTER),
    'top_cell':_ps('top_cell', fontSize=7.5, leading=9),
    'top_c':   _ps('top_cell_c', fontSize=7.5, leading=9, alignment=TA_CENTER),
}


# ── Base table style ───────────────────────────────────────────────────────
_BASE_TBL = [
    ('BACKGROUND',   (0, 0), (-1,  0),  _C.COL_HDR_BG),
    ('TEXTCOLOR',    (0, 0), (-1,  0),  _C.COL_HDR_TXT),
    ('FONTNAME',     (0, 0), (-1,  0),  'Helvetica-Bold'),
    ('FONTSIZE',     (0, 0), (-1,  0),  8),
    ('ALIGN',        (0, 0), (-1,  0),  'CENTER'),
    ('VALIGN',       (0, 0), (-1, -1),  'MIDDLE'),
    ('TOPPADDING',   (0, 0), (-1, -1),  3),
    ('BOTTOMPADDING',(0, 0), (-1, -1),  3),
    ('LEFTPADDING',  (0, 0), (-1, -1),  4),
    ('RIGHTPADDING', (0, 0), (-1, -1),  4),
    ('GRID',         (0, 0), (-1, -1),  0.3, _C.BORDER),
    ('ROWBACKGROUNDS',(0, 1),(-1, -1), [_C.ROW_ODD, _C.ROW_EVEN]),
    ('FONTNAME',     (0, 1), (-1, -1),  'Helvetica'),
    ('FONTSIZE',     (0, 1), (-1, -1),  7.5),
    ('ALIGN',        (0, 1), (-1, -1),  'CENTER'),
]


# ── Cover logo resolution ──────────────────────────────────────────────────
def _resolve_cover_logo():
    """(path, is_svg) for the cover logo, with PNG preference for reliability.

    Order:
      1. Admin upload (Settings → General).
      2. Bundled PNG `static/img/logo.png` if it exists — svglib cannot render
         all SVG features (e.g. radial gradients + clipPath); a co-located PNG
         lets the PDF cover show the logo even when SVG rendering would blank.
      3. Bundled SVG `static/img/logo.svg` as a last resort.
    """
    try:
        from apps.settings_app.branding import uploaded_logo_path
        p = uploaded_logo_path()
        if p:
            return p, p.lower().endswith('.svg')
    except Exception:
        pass
    png_path = os.path.join(os.path.dirname(_LOGO_PATH), 'logo.png')
    if os.path.exists(png_path):
        return png_path, False
    return _LOGO_PATH, True


# ── Cover page canvas callback ─────────────────────────────────────────────
def _cover_fn(report_name, report_type_label, generated_at, generated_by, filters_text):
    """Returns an onPage callback that draws the full cover page design."""
    primary, suffix = _get_platform_names()
    logo_path, logo_is_svg = _resolve_cover_logo()

    def _draw(canvas, doc):
        canvas.saveState()
        W, H = A4  # Cover is always portrait A4

        # ── Full dark background ──────────────────────────────────────────
        canvas.setFillColor(_C.HDR_BG)
        canvas.rect(0, 0, W, H, fill=1, stroke=0)

        # ── Top accent bar ────────────────────────────────────────────────
        canvas.setFillColor(_C.BRAND_SUFFIX)
        canvas.rect(0, H - 6, W, 6, fill=1, stroke=0)

        # ── Bottom accent bar ─────────────────────────────────────────────
        canvas.rect(0, 0, W, 4, fill=1, stroke=0)

        # ── Logo (uploaded brand logo if set, else bundled SVG) ───────────
        logo_bottom = H * 0.715  # bottom edge of logo
        logo_size   = 76         # points
        if logo_is_svg and _SVG_OK and os.path.exists(logo_path):
            try:
                drawing = svg2rlg(logo_path)
                if drawing and drawing.width and drawing.height:
                    scale = logo_size / max(drawing.width, drawing.height)
                    drawing.width  *= scale
                    drawing.height *= scale
                    drawing.transform = (scale, 0, 0, scale, 0, 0)
                    logo_x = (W - drawing.width) / 2
                    _renderPDF.draw(drawing, canvas, logo_x, logo_bottom)
                else:
                    _logger.warning("PDF cover: svg2rlg returned empty drawing for %s "
                                    "(unsupported SVG features?); add static/img/logo.png "
                                    "for a reliable fallback.", logo_path)
            except Exception as exc:
                _logger.warning("PDF cover SVG render failed for %s: %s", logo_path, exc)
        elif not logo_is_svg and os.path.exists(logo_path):
            # Raster logo (PNG/JPG/…) — drawn via ImageReader, transparency preserved.
            try:
                from reportlab.lib.utils import ImageReader
                img = ImageReader(logo_path)
                iw, ih = img.getSize()
                if iw and ih:
                    scale = logo_size / max(iw, ih)
                    dw, dh = iw * scale, ih * scale
                    logo_x = (W - dw) / 2
                    canvas.drawImage(img, logo_x, logo_bottom, width=dw, height=dh,
                                     preserveAspectRatio=True, mask='auto')
            except Exception:
                pass

        # ── Platform name ─────────────────────────────────────────────────
        name_y = logo_bottom - 28  # gap between logo and name
        p_w = canvas.stringWidth(primary, 'Helvetica-Bold', 28)
        s_w = canvas.stringWidth(suffix,  'Helvetica-Bold', 28)
        gap  = 5
        total_w = p_w + gap + s_w
        name_x  = (W - total_w) / 2

        canvas.setFont('Helvetica-Bold', 28)
        canvas.setFillColor(_C.HDR_TEXT)
        canvas.drawString(name_x, name_y, primary)
        canvas.setFillColor(_C.BRAND_SUFFIX)
        canvas.drawString(name_x + p_w + gap, name_y, suffix)

        # ── Tagline ───────────────────────────────────────────────────────
        canvas.setFont('Helvetica', 10)
        canvas.setFillColor(_C.HDR_MUTED)
        canvas.drawCentredString(W / 2, name_y - 20, 'Blacklist Management Platform')

        # ── Divider ───────────────────────────────────────────────────────
        div_y = name_y - 44
        canvas.setStrokeColor(_C.BRAND_SUFFIX)
        canvas.setLineWidth(0.8)
        canvas.line(W * 0.18, div_y, W * 0.82, div_y)

        # ── Report type label ─────────────────────────────────────────────
        canvas.setFont('Helvetica-Bold', 8.5)
        canvas.setFillColor(_C.BRAND_SUFFIX)
        canvas.drawCentredString(W / 2, div_y - 20, report_type_label.upper())

        # ── Report name ───────────────────────────────────────────────────
        canvas.setFont('Helvetica-Bold', 20)
        canvas.setFillColor(_C.HDR_TEXT)
        canvas.drawCentredString(W / 2, div_y - 48, report_name)

        # ── Metadata card ─────────────────────────────────────────────────
        card_margin = W * 0.10
        card_x = card_margin
        card_w = W - 2 * card_margin
        card_h = 102
        card_y = div_y - 48 - 38  # below report name
        card_y -= card_h           # card bottom

        canvas.setFillColor(_C.COVER_SURFACE)
        canvas.setStrokeColor(_C.COVER_BORDER)
        canvas.setLineWidth(0.5)
        canvas.roundRect(card_x, card_y, card_w, card_h, radius=6, fill=1, stroke=1)

        # Vertical divider inside card
        mid_x = card_x + card_w * 0.5
        canvas.setStrokeColor(_C.COVER_BORDER)
        canvas.setLineWidth(0.4)
        canvas.line(mid_x, card_y + 12, mid_x, card_y + card_h - 12)

        pad = 18
        row1_y = card_y + card_h - 24
        row2_y = row1_y - 18
        row3_y = row2_y - 20
        row4_y = row3_y - 16

        # Left column: Generated By
        canvas.setFont('Helvetica-Bold', 7)
        canvas.setFillColor(_C.HDR_MUTED)
        canvas.drawString(card_x + pad, row1_y, 'GENERATED BY')
        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(_C.HDR_TEXT)
        canvas.drawString(card_x + pad, row2_y, str(generated_by))

        # Right column: Generated At
        canvas.setFont('Helvetica-Bold', 7)
        canvas.setFillColor(_C.HDR_MUTED)
        canvas.drawString(mid_x + pad, row1_y, 'GENERATED AT')
        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(_C.HDR_TEXT)
        canvas.drawString(mid_x + pad, row2_y, str(generated_at))

        # Full-width row: Filters
        canvas.setStrokeColor(_C.COVER_BORDER)
        canvas.setLineWidth(0.4)
        canvas.line(card_x + 12, row3_y + 10, card_x + card_w - 12, row3_y + 10)

        canvas.setFont('Helvetica-Bold', 7)
        canvas.setFillColor(_C.HDR_MUTED)
        canvas.drawString(card_x + pad, row3_y, 'APPLIED FILTERS')
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(_C.HDR_TEXT)
        # Truncate filter text if very long
        ft = str(filters_text)
        max_filter_w = card_w - 2 * pad
        while canvas.stringWidth(ft, 'Helvetica', 8) > max_filter_w and len(ft) > 4:
            ft = ft[:-4] + '…'
        canvas.drawString(card_x + pad, row4_y, ft)

        # ── Optional admin-uploaded login/sidebar mark ────────────────────
        # Centered just above the confidentiality line; quietly skipped when
        # no image is uploaded in Settings → General → Login & Sidebar Image.
        _draw_login_mark(canvas, W, bottom_y=28)

        # ── Confidential footer ───────────────────────────────────────────
        contact_email = _get_platform_email()
        canvas.setFont('Helvetica-Bold', 7)
        canvas.setFillColor(_C.HDR_MUTED)
        canvas.drawCentredString(W / 2, 16, 'CONFIDENTIAL — FOR AUTHORIZED USE ONLY')
        if contact_email:
            canvas.setFont('Helvetica', 7)
            canvas.drawCentredString(W / 2, 7, contact_email)

        canvas.restoreState()

    return _draw


# ── Brand-name two-tone draw helpers (primary in HDR_TEXT, suffix in BRAND_SUFFIX)
def _draw_brand_left(canvas, x, y, font_size):
    """Draw '<primary><suffix>' starting at x, returns total drawn width."""
    primary, suffix = _get_platform_names()
    canvas.setFont('Helvetica-Bold', font_size)
    p_w = canvas.stringWidth(primary, 'Helvetica-Bold', font_size)
    s_w = canvas.stringWidth(suffix,  'Helvetica-Bold', font_size)
    canvas.setFillColor(_C.HDR_TEXT)
    canvas.drawString(x, y, primary)
    canvas.setFillColor(_C.BRAND_SUFFIX)
    canvas.drawString(x + p_w, y, suffix)
    return p_w + s_w


def _draw_brand_right(canvas, x_right, y, font_size):
    """Draw '<primary><suffix>' right-aligned at x_right."""
    primary, suffix = _get_platform_names()
    canvas.setFont('Helvetica-Bold', font_size)
    s_w = canvas.stringWidth(suffix, 'Helvetica-Bold', font_size)
    canvas.setFillColor(_C.BRAND_SUFFIX)
    canvas.drawRightString(x_right, y, suffix)
    canvas.setFillColor(_C.HDR_TEXT)
    canvas.drawRightString(x_right - s_w, y, primary)


# ── Page canvas (header + footer on every content page) ───────────────────
def _page_fn(title, subtitle, generated_at, generated_by, total_count, filters_text):
    def _draw(canvas, doc):
        canvas.saveState()
        W, H = canvas._pagesize  # use actual canvas size — doc.pagesize stays portrait

        # Dark header bar
        canvas.setFillColor(_C.HDR_BG)
        canvas.rect(0, H - 52, W, 52, fill=1, stroke=0)
        # Accent stripe (left edge)
        canvas.setFillColor(_C.BRAND_SUFFIX)
        canvas.rect(0, H - 52, 4, 52, fill=1, stroke=0)

        # Left: title + subtitle (split the brand prefix if present so the
        # suffix carries the brand colour).
        brand = _brand_name()
        canvas.setFont('Helvetica-Bold', 13)
        if title.startswith(brand):
            width = _draw_brand_left(canvas, 14, H - 22, 13)
            canvas.setFillColor(_C.HDR_TEXT)
            canvas.drawString(14 + width, H - 22, title[len(brand):])
        else:
            canvas.setFillColor(_C.HDR_TEXT)
            canvas.drawString(14, H - 22, title)
        canvas.setFillColor(_C.HDR_MUTED)
        canvas.setFont('Helvetica', 7.5)
        canvas.drawString(14, H - 34, subtitle)
        canvas.drawString(14, H - 45, filters_text)

        # Right: brand (primary normal + suffix purple) + meta
        _draw_brand_right(canvas, W - 14, H - 18, 9)
        canvas.setFillColor(_C.HDR_MUTED)
        canvas.setFont('Helvetica', 7)
        canvas.drawRightString(W - 14, H - 29, f'Generated: {generated_at}')
        canvas.drawRightString(W - 14, H - 39, f'By: {generated_by}')

        # Footer line + page number
        contact_email = _get_platform_email()
        canvas.setStrokeColor(_C.BORDER)
        canvas.setLineWidth(0.4)
        canvas.line(14, 18, W - 14, 18)
        canvas.setFillColor(_C.TEXT_MUTED)
        canvas.setFont('Helvetica', 6.5)
        footer_left = f'CONFIDENTIAL — {brand} Platform Report'
        if contact_email:
            footer_left += f'  |  {contact_email}'
        canvas.drawString(14, 7, footer_left)
        canvas.drawRightString(W - 14, 7, f'Page {doc.page - 1}')  # -1 to exclude cover

        canvas.restoreState()
    return _draw


# ── Document builder (cover + content pages) ──────────────────────────────
def _build_doc(buf, content_pagesize, content_margins, cover_cb, content_cb):
    """
    Returns (BaseDocTemplate, story_prefix) where story_prefix must be
    prepended to the data flowables before calling doc.build().
    """
    lm, rm, tm, bm = content_margins

    # Cover page template — portrait A4, minimal frame (flowables go to data pages)
    cW, cH = A4
    cover_frame = Frame(
        0, 0, cW, cH,
        leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0,
        id='cover_frame',
    )
    cover_tmpl = PageTemplate(
        id='Cover', frames=[cover_frame],
        onPage=cover_cb, pagesize=A4,
    )

    # Content page template
    pW, pH = content_pagesize
    content_frame = Frame(
        lm, bm, pW - lm - rm, pH - tm - bm,
        id='content_frame',
    )
    content_tmpl = PageTemplate(
        id='Content', frames=[content_frame],
        onPage=content_cb, pagesize=content_pagesize,
    )

    doc = BaseDocTemplate(buf, pagesize=A4)
    doc.addPageTemplates([cover_tmpl, content_tmpl])

    # Switch to Content after the cover page
    story_prefix = [NextPageTemplate('Content'), PageBreak()]
    return doc, story_prefix


# ── Stat box (executive report) ────────────────────────────────────────────
def _stat_box(value, label, bg=None, fg=None):
    bg = bg or HexColor('#F6F8FA')
    fg = fg or _C.TEXT
    vs = ParagraphStyle('sv', fontName='Helvetica-Bold', fontSize=22,
                        textColor=fg, alignment=TA_CENTER, leading=26)
    ls = ParagraphStyle('sl', fontName='Helvetica', fontSize=8,
                        textColor=_C.TEXT_MUTED, alignment=TA_CENTER, leading=11)
    tbl = Table(
        [[Paragraph(str(value), vs)], [Paragraph(label, ls)]],
        style=TableStyle([
            ('BACKGROUND',   (0, 0), (-1, -1), bg),
            ('BOX',          (0, 0), (-1, -1), 0.5, _C.BORDER),
            ('TOPPADDING',   (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING',(0, 0), (-1, -1), 8),
            ('LEFTPADDING',  (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('ALIGN',        (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN',       (0, 0), (-1, -1), 'MIDDLE'),
        ]),
    )
    return tbl


def _stat_row(boxes, col_w):
    tbl = Table(
        [boxes],
        colWidths=[col_w] * len(boxes),
        style=TableStyle([
            ('LEFTPADDING',  (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING',   (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING',(0, 0), (-1, -1), 0),
        ]),
    )
    tbl.hAlign = 'LEFT'
    return tbl


# ── Mini breakdown table (executive) ──────────────────────────────────────
def _breakdown_table(rows, col_widths, title_=None):
    """rows: list of (label, count, pct_str, bg, fg)"""
    elems = []
    if title_:
        elems.append(Spacer(1, 6))
        elems.append(Paragraph(title_, _ST['sect']))
        elems.append(Spacer(1, 4))

    hdr_row = [
        Paragraph('Category', _ST['top_hdr']),
        Paragraph('Count', _ST['top_hdr']),
        Paragraph('%', _ST['top_hdr']),
    ]
    data = [hdr_row]
    style_cmds = list(_BASE_TBL)

    for i, (label, count, pct, bg, fg) in enumerate(rows, start=1):
        data.append([
            Paragraph(label, _ST['top_cell']),
            Paragraph(str(count), _ST['top_c']),
            Paragraph(pct, _ST['top_c']),
        ])
        if bg:
            style_cmds += [
                ('BACKGROUND', (0, i), (0, i), bg),
                ('TEXTCOLOR',  (0, i), (0, i), fg),
            ]

    tbl = Table(data, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle(style_cmds))
    tbl.hAlign = 'LEFT'
    elems.append(tbl)
    return elems


# ── Filters summary text ───────────────────────────────────────────────────
def _filter_line(f):
    parts = []
    preset = f.get('date_preset', '')
    if preset == 'today':
        parts.append('Date: Today')
    elif preset == '7d':
        parts.append('Date: Last 7 days')
    elif preset == '30d':
        parts.append('Date: Last 30 days')
    elif preset == 'custom':
        df = f.get('date_from', '')
        dt = f.get('date_to', '')
        if df or dt:
            parts.append(f"Date: {df or '...'} → {dt or '...'}")
    else:
        parts.append('Date: All time')

    status = f.get('status', 'all')
    parts.append(f'Status: {status.capitalize()}')

    return '  |  '.join(parts) if parts else 'No filters'


# ══════════════════════════════════════════════════════════════════════════
#  BLACKLIST
# ══════════════════════════════════════════════════════════════════════════

def generate_blacklist_executive(queryset, filters, generated_by, score_30d=80, score_24h=10):
    """Return PDF bytes for IP Blacklist report (landscape, all columns, sorted by added_at desc)."""
    from collections import Counter
    _refresh_brand_suffix()
    buf = io.BytesIO()
    now = timezone.now()
    entries = list(queryset.select_related('group', 'added_by').order_by('-added_at'))
    total = len(entries)
    generated_at = timezone.localtime(now).strftime('%Y-%m-%d %H:%M')
    filters_text = _filter_line(filters)

    # ── Stats ─────────────────────────────────────────────────────────────
    active_ct   = sum(1 for e in entries if e.is_active
                      and not (e.expires_at and e.expires_at < now))
    expired_ct  = sum(1 for e in entries if e.is_active
                      and e.expires_at and e.expires_at < now)
    inactive_ct = sum(1 for e in entries if not e.is_active)
    by_source   = Counter(e.source for e in entries)
    by_group    = Counter(
        (e.group.name if e.group else '', e.group.label if e.group else 'Other')
        for e in entries
    )
    by_user     = Counter(_added_by_display(e.added_by) for e in entries)

    # Column widths (mm) — landscape A4 usable = 14+269+14 = 297 mm
    col_w = [12, 34, 18, 14, 40, 20, 27, 32, 26, 26, 20]  # sum = 269 mm
    col_w_pts = [w * mm for w in col_w]
    pw = sum(col_w) * mm
    headers = ['#', 'IP', 'Group', 'Source', 'Reason',
               'Abuse\nIPDB', 'Abuse\nChecked', 'Added By', 'Added At', 'Expires', 'Status']

    content_pagesize = rl_landscape(A4)
    lm = rm = 14 * mm
    tm = 22 * mm
    bm = 22 * mm

    cover_cb = _cover_fn(
        report_name='IP Blacklist Report',
        report_type_label='Report',
        generated_at=generated_at,
        generated_by=generated_by,
        filters_text=filters_text,
    )
    content_cb = _page_fn(
        title='IP Blacklist Report',
        subtitle=f'Generated: {generated_at}',
        generated_at=generated_at,
        generated_by=generated_by,
        total_count=total,
        filters_text=filters_text,
    )

    doc, prefix = _build_doc(buf, content_pagesize, (lm, rm, tm, bm), cover_cb, content_cb)
    elems = list(prefix)

    # ── Statistics section ────────────────────────────────────────────────
    _sf = filters.get('status', 'all')
    _stat_boxes = [_stat_box(total, 'Total Entries')]
    if _sf != 'inactive':
        _stat_boxes.append(_stat_box(active_ct,   'Active',   _C.SUCCESS_BG, _C.SUCCESS_FG))
        _stat_boxes.append(_stat_box(expired_ct,  'Expired',  _C.WARNING_BG, _C.WARNING_FG))
    if _sf != 'active':
        _stat_boxes.append(_stat_box(inactive_ct, 'Inactive', _C.DANGER_BG,  _C.DANGER_FG))
    elems.append(_stat_row(_stat_boxes, pw / len(_stat_boxes)))
    elems.append(Spacer(1, 10))

    src_map = {'api': 'API', 'manual': 'Manual', 'import': 'Import'}
    if by_source:
        rows = [(src_map.get(s, s.capitalize()), c,
                 f'{c / total * 100:.1f}%' if total else '0%',
                 *_source_col(s))
                for s, c in sorted(by_source.items(), key=lambda x: -x[1])]
        elems += _breakdown_table(rows, [pw * 0.5, pw * 0.25, pw * 0.25], 'Breakdown by Source')

    if by_group:
        rows = [(lbl, c, f'{c / total * 100:.1f}%' if total else '0%',
                 *_group_col(name))
                for (name, lbl), c in sorted(by_group.items(), key=lambda x: -x[1])]
        elems += _breakdown_table(rows, [pw * 0.5, pw * 0.25, pw * 0.25], 'Breakdown by Group')

    if by_user:
        rows = [(_trunc(u, 40), c, f'{c / total * 100:.1f}%' if total else '0%',
                 _C.PURPLE_BG, _C.PURPLE_FG)
                for u, c in sorted(by_user.items(), key=lambda x: -x[1])[:15]]
        elems += _breakdown_table(rows, [pw * 0.5, pw * 0.25, pw * 0.25], 'Breakdown by User')

    elems.append(Spacer(1, 14))

    # ── Data table ────────────────────────────────────────────────────────
    data = [[Paragraph(h, _ST['hdr']) for h in headers]]
    style_cmds = list(_BASE_TBL)

    for idx, e in enumerate(entries, start=1):
        expired = bool(e.expires_at and e.expires_at < now)
        g_name  = e.group.name if e.group else ''
        g_label = e.group.label if e.group else '—'
        g_bg, g_fg   = _group_col(g_name)
        s_bg, s_fg   = _source_col(e.source)
        score_str    = str(e.abuse_confidence_score) if e.abuse_confidence_score is not None else '—'
        sc_bg, sc_fg = _score_col(e.abuse_confidence_score, score_30d, score_24h)
        if not e.is_active:
            st_str, st_bg, st_fg = 'Inactive', _C.DANGER_BG,  _C.DANGER_FG
        elif expired:
            st_str, st_bg, st_fg = 'Expired',  _C.WARNING_BG, _C.WARNING_FG
        else:
            st_str, st_bg, st_fg = 'Active',   _C.SUCCESS_BG, _C.SUCCESS_FG

        added_by   = _added_by_display(e.added_by)
        expires    = _fmt(e.expires_at) if e.expires_at else 'Never'
        ip_display = e.ip_address if e.prefix_length == 32 else e.cidr

        data.append([
            Paragraph(str(idx),                  _ST['cell_c']),
            Paragraph(ip_display or '—',         _ST['cell_c']),
            Paragraph(g_label,                   _ST['cell_c']),
            Paragraph(e.get_source_display(),    _ST['cell_c']),
            Paragraph(_trunc(e.reason, 45),      _ST['cell_c']),
            Paragraph(score_str,                 _ST['cell_c']),
            Paragraph(_fmt(e.abuse_checked_at),  _ST['cell_c']),
            Paragraph(_trunc(added_by, 28),      _ST['cell_c']),
            Paragraph(_fmt(e.added_at),          _ST['cell_c']),
            Paragraph(expires,                   _ST['cell_c']),
            Paragraph(st_str,                    _ST['cell_c']),
        ])
        r = idx
        style_cmds += [('BACKGROUND', (2,  r), (2,  r), g_bg),  ('TEXTCOLOR', (2,  r), (2,  r), g_fg)]
        style_cmds += [('BACKGROUND', (3,  r), (3,  r), s_bg),  ('TEXTCOLOR', (3,  r), (3,  r), s_fg)]
        if sc_bg:
            style_cmds += [('BACKGROUND', (5, r), (5, r), sc_bg), ('TEXTCOLOR', (5, r), (5, r), sc_fg)]
        style_cmds += [('BACKGROUND', (10, r), (10, r), st_bg), ('TEXTCOLOR', (10, r), (10, r), st_fg)]

    table = Table(data, colWidths=col_w_pts, repeatRows=1)
    table.setStyle(TableStyle(style_cmds))
    table.hAlign = 'LEFT'
    elems.append(table)
    doc.build(elems)
    return buf.getvalue()


# ══════════════════════════════════════════════════════════════════════════
#  WHITELIST
# ══════════════════════════════════════════════════════════════════════════

def generate_whitelist_executive(queryset, filters, generated_by):
    """Return PDF bytes for IP Whitelist report (landscape, all columns, sorted by added_at desc)."""
    from collections import Counter
    _refresh_brand_suffix()
    buf = io.BytesIO()
    now = timezone.now()
    entries = list(queryset.select_related('added_by').order_by('-added_at'))
    total = len(entries)
    generated_at = timezone.localtime(now).strftime('%Y-%m-%d %H:%M')
    filters_text = _filter_line(filters)

    # ── Stats ─────────────────────────────────────────────────────────────
    active_ct   = sum(1 for e in entries if e.is_active)
    inactive_ct = total - active_ct
    by_source   = Counter(e.source for e in entries)
    by_prefix   = Counter(e.prefix_length for e in entries)
    by_user     = Counter(_added_by_display(e.added_by) for e in entries)

    # Columns: #, CIDR, Prefix, Status, Source, Reason, Added By, Added At
    # Landscape A4 usable = 14+269+14 = 297 mm
    col_w = [12, 54, 16, 20, 16, 74, 51, 26]  # sum = 269 mm
    col_w_pts = [w * mm for w in col_w]
    pw = sum(col_w) * mm
    headers = ['#', 'CIDR', 'Prefix', 'Status', 'Source', 'Reason', 'Added By', 'Added At']

    content_pagesize = rl_landscape(A4)
    lm = rm = 14 * mm
    tm = 22 * mm
    bm = 22 * mm

    cover_cb = _cover_fn(
        report_name='IP Whitelist Report',
        report_type_label='Report',
        generated_at=generated_at,
        generated_by=generated_by,
        filters_text=filters_text,
    )
    content_cb = _page_fn(
        title='IP Whitelist Report',
        subtitle=f'Generated: {generated_at}',
        generated_at=generated_at,
        generated_by=generated_by,
        total_count=total,
        filters_text=filters_text,
    )

    doc, prefix = _build_doc(buf, content_pagesize, (lm, rm, tm, bm), cover_cb, content_cb)
    elems = list(prefix)

    # ── Statistics section ────────────────────────────────────────────────
    _sf = filters.get('status', 'all')
    _stat_boxes = [_stat_box(total, 'Total Entries')]
    if _sf != 'inactive':
        _stat_boxes.append(_stat_box(active_ct,   'Active',   _C.SUCCESS_BG, _C.SUCCESS_FG))
    if _sf != 'active':
        _stat_boxes.append(_stat_box(inactive_ct, 'Inactive', _C.DANGER_BG,  _C.DANGER_FG))
    elems.append(_stat_row(_stat_boxes, pw / len(_stat_boxes)))
    elems.append(Spacer(1, 10))

    src_map = {'manual': 'Manual', 'import': 'Import'}
    if by_source:
        rows = [(src_map.get(s, s.capitalize()), c,
                 f'{c / total * 100:.1f}%' if total else '0%',
                 *_source_col(s))
                for s, c in sorted(by_source.items(), key=lambda x: -x[1])]
        elems += _breakdown_table(rows, [pw * 0.5, pw * 0.25, pw * 0.25], 'Breakdown by Source')

    if by_prefix:
        rows = [(f'/{p}', c, f'{c / total * 100:.1f}%' if total else '0%',
                 _C.INFO_BG, _C.INFO_FG)
                for p, c in sorted(by_prefix.items(), key=lambda x: x[0])[:10]]
        elems += _breakdown_table(rows, [pw * 0.5, pw * 0.25, pw * 0.25], 'Breakdown by Prefix Length')

    if by_user:
        rows = [(_trunc(u, 40), c, f'{c / total * 100:.1f}%' if total else '0%',
                 _C.PURPLE_BG, _C.PURPLE_FG)
                for u, c in sorted(by_user.items(), key=lambda x: -x[1])[:15]]
        elems += _breakdown_table(rows, [pw * 0.5, pw * 0.25, pw * 0.25], 'Breakdown by User')

    elems.append(Spacer(1, 14))

    # ── Data table ────────────────────────────────────────────────────────
    data = [[Paragraph(h, _ST['hdr']) for h in headers]]
    style_cmds = list(_BASE_TBL)

    for idx, e in enumerate(entries, start=1):
        s_bg, s_fg = _source_col(e.source)
        st_str, st_bg, st_fg = (
            ('Active',   _C.SUCCESS_BG, _C.SUCCESS_FG) if e.is_active
            else ('Inactive', _C.DANGER_BG,  _C.DANGER_FG)
        )
        added_by = _added_by_display(e.added_by)

        data.append([
            Paragraph(str(idx),                   _ST['cell_c']),
            Paragraph(e.cidr or '—',              _ST['cell_c']),
            Paragraph(f'/{e.prefix_length}',      _ST['cell_c']),
            Paragraph(st_str,                     _ST['cell_c']),
            Paragraph(e.get_source_display(),     _ST['cell_c']),
            Paragraph(_trunc(e.reason, 70),       _ST['cell_c']),
            Paragraph(_trunc(added_by, 38),       _ST['cell_c']),
            Paragraph(_fmt(e.added_at),           _ST['cell_c']),
        ])
        r = idx
        style_cmds += [('BACKGROUND', (3, r), (3, r), st_bg), ('TEXTCOLOR', (3, r), (3, r), st_fg)]
        style_cmds += [('BACKGROUND', (4, r), (4, r), s_bg),  ('TEXTCOLOR', (4, r), (4, r), s_fg)]

    table = Table(data, colWidths=col_w_pts, repeatRows=1)
    table.setStyle(TableStyle(style_cmds))
    table.hAlign = 'LEFT'
    elems.append(table)
    doc.build(elems)
    return buf.getvalue()


# ══════════════════════════════════════════════════════════════════════════
#  HASH BLACKLIST
# ══════════════════════════════════════════════════════════════════════════

def generate_hashlist_executive(queryset, filters, generated_by, vt_threshold=5):
    """Return PDF bytes for Hash Blacklist report (landscape, all columns, sorted by added_at desc)."""
    from collections import Counter
    _refresh_brand_suffix()
    buf = io.BytesIO()
    now = timezone.now()
    entries = list(queryset.select_related('added_by').order_by('-added_at'))
    total = len(entries)
    generated_at = timezone.localtime(now).strftime('%Y-%m-%d %H:%M')
    filters_text = _filter_line(filters)

    # ── Stats ─────────────────────────────────────────────────────────────
    active_ct   = sum(1 for e in entries if e.is_active)
    inactive_ct = total - active_ct
    vt_checked  = sum(1 for e in entries if e.vt_checked_at)
    vt_detected = sum(1 for e in entries
                      if e.vt_checked_at and e.vt_malicious is not None
                      and e.vt_malicious >= vt_threshold)
    by_type   = Counter(e.hash_type for e in entries)
    by_source = Counter(e.source for e in entries)
    by_user   = Counter(_added_by_display(e.added_by) for e in entries)

    # Columns: #, Hash Value, Type, Source, Reason, VT Score, VT Checked, Added By, Added At
    # Landscape A4 usable = 14+269+14 = 297 mm
    col_w = [12, 60, 16, 14, 52, 20, 32, 37, 26]  # sum = 269 mm
    col_w_pts = [w * mm for w in col_w]
    pw = sum(col_w) * mm
    headers = ['#', 'Hash Value', 'Type', 'Source', 'Reason', 'VirusTotal\nScore', 'VirusTotal\nChecked', 'Added By', 'Added At']

    content_pagesize = rl_landscape(A4)
    lm = rm = 14 * mm
    tm = 22 * mm
    bm = 22 * mm

    cover_cb = _cover_fn(
        report_name='Hash Blacklist Report',
        report_type_label='Report',
        generated_at=generated_at,
        generated_by=generated_by,
        filters_text=filters_text,
    )
    content_cb = _page_fn(
        title='Hash Blacklist Report',
        subtitle=f'Generated: {generated_at}',
        generated_at=generated_at,
        generated_by=generated_by,
        total_count=total,
        filters_text=filters_text,
    )

    doc, prefix = _build_doc(buf, content_pagesize, (lm, rm, tm, bm), cover_cb, content_cb)
    elems = list(prefix)

    # ── Statistics section ────────────────────────────────────────────────
    _sf = filters.get('status', 'all')
    _stat_boxes = [_stat_box(total, 'Total Hashes')]
    if _sf != 'inactive':
        _stat_boxes.append(_stat_box(active_ct,   'Active',   _C.SUCCESS_BG, _C.SUCCESS_FG))
    if _sf != 'active':
        _stat_boxes.append(_stat_box(inactive_ct, 'Inactive', _C.DANGER_BG,  _C.DANGER_FG))
    _stat_boxes += [
        _stat_box(vt_checked,  'VirusTotal Checked',      _C.INFO_BG,    _C.INFO_FG),
        _stat_box(vt_detected, f'VirusTotal Detected (≥{vt_threshold})', _C.WARNING_BG, _C.WARNING_FG),
    ]
    elems.append(_stat_row(_stat_boxes, pw / len(_stat_boxes)))
    elems.append(Spacer(1, 10))

    type_map = {'md5': 'MD5', 'sha1': 'SHA1', 'sha256': 'SHA256',
                'sha512': 'SHA512', 'unknown': 'Unknown'}
    if by_type:
        rows = [(type_map.get(t, t.upper()), c,
                 f'{c / total * 100:.1f}%' if total else '0%',
                 *_hash_type_col(t))
                for t, c in sorted(by_type.items(), key=lambda x: -x[1])]
        elems += _breakdown_table(rows, [pw * 0.5, pw * 0.25, pw * 0.25], 'Breakdown by Hash Type')

    src_map = {'api': 'API', 'manual': 'Manual', 'import': 'Import'}
    if by_source:
        rows = [(src_map.get(s, s.capitalize()), c,
                 f'{c / total * 100:.1f}%' if total else '0%',
                 *_source_col(s))
                for s, c in sorted(by_source.items(), key=lambda x: -x[1])]
        elems += _breakdown_table(rows, [pw * 0.5, pw * 0.25, pw * 0.25], 'Breakdown by Source')

    if by_user:
        rows = [(_trunc(u, 40), c, f'{c / total * 100:.1f}%' if total else '0%',
                 _C.PURPLE_BG, _C.PURPLE_FG)
                for u, c in sorted(by_user.items(), key=lambda x: -x[1])[:15]]
        elems += _breakdown_table(rows, [pw * 0.5, pw * 0.25, pw * 0.25], 'Breakdown by User')

    elems.append(Spacer(1, 14))

    # ── Data table ────────────────────────────────────────────────────────
    data = [[Paragraph(h, _ST['hdr']) for h in headers]]
    style_cmds = list(_BASE_TBL)

    for idx, e in enumerate(entries, start=1):
        ht_bg, ht_fg = _hash_type_col(e.hash_type)
        s_bg, s_fg   = _source_col(e.source)
        if e.vt_malicious is not None and e.vt_total is not None:
            vt_str = f'{e.vt_malicious}/{e.vt_total}'
            vt_bg  = _C.DANGER_BG  if e.vt_malicious >= vt_threshold else _C.SUCCESS_BG
            vt_fg  = _C.DANGER_FG  if e.vt_malicious >= vt_threshold else _C.SUCCESS_FG
        else:
            vt_str, vt_bg, vt_fg = '—', None, None
        added_by = _added_by_display(e.added_by)

        data.append([
            Paragraph(str(idx),                          _ST['cell_c']),
            Paragraph(_trunc(e.hash_value.upper(), 60),  _ST['cell_c']),
            Paragraph(e.hash_type.upper(),               _ST['cell_c']),
            Paragraph(e.get_source_display(),            _ST['cell_c']),
            Paragraph(_trunc(e.reason, 60),              _ST['cell_c']),
            Paragraph(vt_str,                            _ST['cell_c']),
            Paragraph(_fmt(e.vt_checked_at),             _ST['cell_c']),
            Paragraph(_trunc(added_by, 32),              _ST['cell_c']),
            Paragraph(_fmt(e.added_at),                  _ST['cell_c']),
        ])
        r = idx
        style_cmds += [('BACKGROUND', (2, r), (2, r), ht_bg), ('TEXTCOLOR', (2, r), (2, r), ht_fg)]
        style_cmds += [('BACKGROUND', (3, r), (3, r), s_bg),  ('TEXTCOLOR', (3, r), (3, r), s_fg)]
        if vt_bg:
            style_cmds += [('BACKGROUND', (5, r), (5, r), vt_bg), ('TEXTCOLOR', (5, r), (5, r), vt_fg)]

    table = Table(data, colWidths=col_w_pts, repeatRows=1)
    table.setStyle(TableStyle(style_cmds))
    table.hAlign = 'LEFT'
    elems.append(table)
    doc.build(elems)
    return buf.getvalue()


# ════════════════════════════════════════════════════════════════════════════
#  DASHBOARD
# ════════════════════════════════════════════════════════════════════════════

_PIE_CAP = ParagraphStyle('pie_cap', fontName='Helvetica-Bold', fontSize=8.5,
                          textColor=_C.TEXT, alignment=TA_CENTER, leading=11)


def _legend_label(label, count, maxlen=18):
    s = str(label)
    if len(s) > maxlen:
        s = s[:maxlen - 1] + '…'
    return f'{s} ({count})'


def _pie_drawing(dist, w, h):
    """Pie chart on the left with a colour legend on the right (offline, ReportLab)."""
    d = Drawing(w, h)
    labels, data, colors = dist['labels'], dist['data'], dist['colors']
    psize = min(h - 12, 104)
    pie = Pie()
    pie.x = 2
    pie.y = (h - psize) / 2
    pie.width = pie.height = psize
    pie.data = data
    pie.labels = None
    pie.slices.strokeColor = HexColor('#FFFFFF')
    pie.slices.strokeWidth = 0.75
    for i in range(len(data)):
        pie.slices[i].fillColor = HexColor(colors[i])
    d.add(pie)

    leg = Legend()
    leg.x = pie.x + psize + 10
    leg.y = h - 4
    leg.boxAnchor = 'nw'
    leg.fontName = 'Helvetica'
    leg.fontSize = 7
    leg.dxTextSpace = 5
    leg.deltay = 10.5
    leg.dx = 6
    leg.dy = 6
    leg.columnMaximum = 12
    # Legend ordered by value, highest → lowest (each swatch keeps its slice colour).
    ordered = sorted(zip(colors, labels, data), key=lambda t: t[2], reverse=True)
    leg.colorNamePairs = [
        (HexColor(c), _legend_label(lbl, v)) for c, lbl, v in ordered
    ]
    d.add(leg)
    return d


def _timeline_drawing(timeline, w, h):
    """Two-line daily timeline (IP + hash additions) with a small manual legend."""
    d = Drawing(w, h)
    ip, hsh, names = timeline['ip'], timeline['hash'], timeline['labels']

    # Thin out the x-axis labels so they never overlap — keep about MAX_TICKS
    # spread evenly across the window (first and last always visible).
    MAX_TICKS = 12
    n = len(names)
    if n > MAX_TICKS:
        stride = (n + MAX_TICKS - 1) // MAX_TICKS   # ceil(n / MAX_TICKS)
        sparse = [''] * n
        for i in range(0, n, stride):
            sparse[i] = names[i]
        sparse[-1] = names[-1]                       # always show the latest
        display_names = sparse
    else:
        display_names = list(names)

    lc = HorizontalLineChart()
    lc.x = 30
    lc.y = 18
    lc.width = w - 42
    lc.height = h - 44
    lc.data = [ip, hsh]
    lc.categoryAxis.categoryNames = display_names
    lc.categoryAxis.labels.fontName = 'Helvetica'
    lc.categoryAxis.labels.fontSize = 6
    lc.categoryAxis.labels.dy = -2
    lc.valueAxis.valueMin = 0
    lc.valueAxis.valueMax = max(ip + hsh + [1])
    lc.valueAxis.labels.fontName = 'Helvetica'
    lc.valueAxis.labels.fontSize = 6
    lc.lines[0].strokeColor = HexColor('#d3737a')
    lc.lines[1].strokeColor = HexColor('#6c9bd2')
    lc.lines[0].strokeWidth = 1.5
    lc.lines[1].strokeWidth = 1.5
    d.add(lc)

    # Manual legend (top-left) — two series.
    ly = h - 9
    d.add(Rect(30, ly, 8, 8, fillColor=HexColor('#d3737a'), strokeColor=None))
    d.add(String(42, ly + 1, 'IP Blacklist', fontName='Helvetica', fontSize=7, fillColor=_C.TEXT))
    d.add(Rect(120, ly, 8, 8, fillColor=HexColor('#6c9bd2'), strokeColor=None))
    d.add(String(132, ly + 1, 'Hash Blacklist', fontName='Helvetica', fontSize=7, fillColor=_C.TEXT))
    return d


_TIMELINE_PRESET_LABELS = {
    1: 'Last 24 hours', 7: 'Last 7 days', 30: 'Last 30 days',
    90: 'Last 90 days', 180: 'Last 6 months', 365: 'Last 12 months',
}
_TIMELINE_BUCKET_LABELS = {
    'minute': 'Minutely', 'hour': 'Hourly', 'day': 'Daily', 'month': 'Monthly',
}


def _timeline_window_label(days, bucket, minutes=None):
    """Human label for the timeline window, e.g. 'Last 30 days · Daily'.

    The minute bucket uses the `minutes` argument instead of `days` so the
    label shows the minute window (e.g. 'Last 60 minutes · Minutely') and
    mirrors what the user actually picked on the dashboard.
    """
    if not bucket:
        return ''
    bucket_lbl = _TIMELINE_BUCKET_LABELS.get(bucket, bucket.title())
    if bucket == 'minute':
        try:
            m = int(minutes) if minutes else 60
        except (TypeError, ValueError):
            m = 60
        return f"Last {m} minutes · {bucket_lbl}"
    if not days:
        return bucket_lbl
    try:
        d = int(days)
    except (TypeError, ValueError):
        return bucket_lbl
    range_lbl = _TIMELINE_PRESET_LABELS.get(d, f'Last {d} days')
    return f"{range_lbl} · {bucket_lbl}"


def generate_dashboard_snapshot(stats, groups, recent_blacklist, recent_whitelist,
                                recent_hashlist, generated_by, charts=None, timeline=None):
    """
    Portrait A4 dashboard PDF.
    stats           : dict  — keys: hashlist_total, blacklist_total, blacklist_30d,
                              blacklist_24h, whitelist_total, api_reports, users_total
    groups          : annotated BlacklistGroup queryset (active_count annotation)
    recent_blacklist: queryset[:10] — select_related('group', 'added_by')
    recent_whitelist: queryset[:10] — select_related('added_by')
    recent_hashlist : queryset[:10] — select_related('added_by')
    generated_by    : str
    """
    _refresh_brand_suffix()
    buf = io.BytesIO()
    generated_at = timezone.localtime(timezone.now()).strftime('%Y-%m-%d %H:%M:%S')

    lm = rm = 20 * mm
    bm = 20 * mm
    tm = 22 * mm

    pw = A4[0] - lm - rm  # ≈170 mm usable width

    snapshot_label = f'Overview generated at: {generated_at}'

    cover_cb = _cover_fn(
        report_name='Platform Overview',
        report_type_label='Report',
        generated_at=generated_at,
        generated_by=generated_by,
        filters_text=snapshot_label,
    )
    page_cb = _page_fn(
        title=f'{_brand_name()} — Dashboard',
        subtitle='Platform overview  |  Active entries across all lists',
        generated_at=generated_at,
        generated_by=generated_by,
        total_count='—',
        filters_text=snapshot_label,
    )

    doc, story_prefix = _build_doc(
        buf,
        content_pagesize=A4,
        content_margins=(lm, rm, tm, bm),
        cover_cb=cover_cb,
        content_cb=page_cb,
    )

    elems = list(story_prefix)

    # ── Section 1: Platform Statistics ──────────────────────────────────────
    _sect_c = ParagraphStyle('sect_c', parent=_ST['sect'], alignment=TA_CENTER)
    elems.append(Paragraph('Platform Statistics', _sect_c))
    elems.append(Spacer(1, 6))

    box_w = pw / 3
    row1 = [
        _stat_box(stats.get('hashlist_total', 0), 'Hash Blacklist\n(Active)',
                  _C.DANGER_BG, _C.DANGER_FG),
        _stat_box(stats.get('blacklist_30d', 0), '30d IP Blacklist\n(Active)',
                  _C.PURPLE_BG, _C.PURPLE_FG),
        _stat_box(stats.get('blacklist_24h', 0), '24h IP Blacklist\n(Active)',
                  _C.PINK_BG, _C.PINK_FG),
    ]
    elems.append(_stat_row(row1, box_w))
    elems.append(Spacer(1, 6))

    row2 = [
        _stat_box(stats.get('whitelist_total', 0), 'IP Whitelist\n(Active)',
                  _C.SUCCESS_BG, _C.SUCCESS_FG),
        _stat_box(stats.get('api_reports', 0), 'API Requests\n(Last 24h)',
                  _C.INFO_BG, _C.INFO_FG),
        _stat_box(stats.get('users_total', 0), 'Active Users',
                  _C.MUTED_BG, _C.MUTED_FG),
    ]
    elems.append(_stat_row(row2, box_w))
    elems.append(Spacer(1, 14))

    # ── Section 1b: Blacklist Timeline (mirrors the dashboard selection) ─────
    if timeline and timeline.get('labels'):
        elems.append(Paragraph('Blacklist Timeline', _sect_c))
        _range_label = _timeline_window_label(
            timeline.get('days'), timeline.get('bucket'), timeline.get('minutes'),
        )
        if _range_label:
            _sub_c = ParagraphStyle('tl_sub', parent=_ST['sub'], alignment=TA_CENTER)
            elems.append(Paragraph(_range_label, _sub_c))
        elems.append(Spacer(1, 6))
        elems.append(_timeline_drawing(timeline, pw, 150))
        elems.append(Spacer(1, 14))

    # ── Section 1c: Analytics distributions (pie charts) ─────────────────────
    if charts:
        elems.append(Paragraph('Analytics', _sect_c))
        elems.append(Spacer(1, 6))
        cw = pw / 2
        ch = 122

        def _pie_cell(title, key):
            dist = charts.get(key)
            cell = [Paragraph(title, _PIE_CAP), Spacer(1, 2)]
            if dist and dist.get('total'):
                cell.append(_pie_drawing(dist, cw - 12, ch))
            else:
                cell.append(Spacer(1, ch / 2))
                cell.append(Paragraph('No data yet.', _ST['sub']))
            return cell

        pie_rows = [
            [_pie_cell('IP Score', 'ipscore'), _pie_cell('IP Top Countries', 'ipcountry')],
            [_pie_cell('Hash Score', 'hashscore'), _pie_cell('Hash Top Threat Labels', 'hashthreat')],
        ]
        pie_tbl = Table(pie_rows, colWidths=[cw, cw])
        pie_tbl.setStyle(TableStyle([
            ('VALIGN',       (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING',  (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING',   (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING',(0, 0), (-1, -1), 6),
        ]))
        pie_tbl.hAlign = 'LEFT'
        elems.append(pie_tbl)
        elems.append(Spacer(1, 14))

    # ── Section 2: Blacklist Groups ──────────────────────────────────────────
    total_bl = stats.get('blacklist_total', 0) or 1
    group_rows = []
    for g in groups:
        cnt = g.active_count
        pct = f'{cnt / total_bl * 100:.1f}%'
        bg, fg = _group_col(g.name)
        group_rows.append((g.label or g.name, cnt, pct, bg, fg))

    if group_rows:
        gw = [pw * 0.60, pw * 0.20, pw * 0.20]
        # Keep the heading with its table so it never sits orphaned at a page
        # bottom — if they don't fit together, both move to the next page.
        elems.append(KeepTogether(_breakdown_table(group_rows, gw, title_='Blacklist Groups')))
        elems.append(Spacer(1, 14))

    # ── Section 3: Recent Hash Blacklist ─────────────────────────────────────
    elems.append(Paragraph('Recent Hash Blacklist', _ST['sect']))
    elems.append(Spacer(1, 4))

    # col widths sum to 170 mm
    hl_col_w = [w * mm for w in [10, 80, 20, 20, 40]]
    hl_data = [[
        Paragraph('#',        _ST['hdr']),
        Paragraph('Hash',     _ST['hdr']),
        Paragraph('Type',     _ST['hdr']),
        Paragraph('Source',   _ST['hdr']),
        Paragraph('Added At', _ST['hdr']),
    ]]
    hl_style = list(_BASE_TBL)

    for idx, e in enumerate(recent_hashlist, start=1):
        ht_bg, ht_fg = _hash_type_col(e.hash_type)
        s_bg,  s_fg  = _source_col(e.source)
        hl_data.append([
            Paragraph(str(idx),                         _ST['cell_c']),
            Paragraph(_trunc(e.hash_value.upper(), 60), _ST['cell_c']),
            Paragraph(e.hash_type.upper(),              _ST['cell_c']),
            Paragraph(e.get_source_display(),           _ST['cell_c']),
            Paragraph(_fmt(e.added_at),                 _ST['cell_c']),
        ])
        hl_style += [('BACKGROUND', (2, idx), (2, idx), ht_bg),
                     ('TEXTCOLOR',  (2, idx), (2, idx), ht_fg)]
        hl_style += [('BACKGROUND', (3, idx), (3, idx), s_bg),
                     ('TEXTCOLOR',  (3, idx), (3, idx), s_fg)]

    hl_tbl = Table(hl_data, colWidths=hl_col_w, repeatRows=1)
    hl_tbl.setStyle(TableStyle(hl_style))
    hl_tbl.hAlign = 'LEFT'
    elems.append(hl_tbl)
    elems.append(Spacer(1, 14))

    # ── Section 4: Recent IP Blacklist ───────────────────────────────────────
    elems.append(Paragraph('Recent IP Blacklist', _ST['sect']))
    elems.append(Spacer(1, 4))

    # col widths sum to 170 mm
    bl_col_w = [w * mm for w in [10, 58, 30, 22, 50]]
    bl_data = [[
        Paragraph('#',        _ST['hdr']),
        Paragraph('IP',       _ST['hdr']),
        Paragraph('Group',    _ST['hdr']),
        Paragraph('Source',   _ST['hdr']),
        Paragraph('Added At', _ST['hdr']),
    ]]
    bl_style = list(_BASE_TBL)

    for idx, e in enumerate(recent_blacklist, start=1):
        g_bg, g_fg = _group_col(e.group.name)
        s_bg, s_fg = _source_col(e.source)
        ip_display = e.ip_address if e.prefix_length == 32 else e.cidr
        bl_data.append([
            Paragraph(str(idx),                    _ST['cell_c']),
            Paragraph(ip_display,                  _ST['cell_c']),
            Paragraph(e.group.label or e.group.name, _ST['cell_c']),
            Paragraph(e.get_source_display(),      _ST['cell_c']),
            Paragraph(_fmt(e.added_at),            _ST['cell_c']),
        ])
        bl_style += [('BACKGROUND', (2, idx), (2, idx), g_bg),
                     ('TEXTCOLOR',  (2, idx), (2, idx), g_fg)]
        bl_style += [('BACKGROUND', (3, idx), (3, idx), s_bg),
                     ('TEXTCOLOR',  (3, idx), (3, idx), s_fg)]

    bl_tbl = Table(bl_data, colWidths=bl_col_w, repeatRows=1)
    bl_tbl.setStyle(TableStyle(bl_style))
    bl_tbl.hAlign = 'LEFT'
    elems.append(bl_tbl)
    elems.append(Spacer(1, 14))

    # ── Section 5: Recent IP Whitelist ───────────────────────────────────────
    elems.append(Paragraph('Recent IP Whitelist', _ST['sect']))
    elems.append(Spacer(1, 4))

    # col widths sum to 170 mm
    wl_col_w = [w * mm for w in [10, 72, 18, 22, 48]]
    wl_data = [[
        Paragraph('#',        _ST['hdr']),
        Paragraph('CIDR',     _ST['hdr']),
        Paragraph('Prefix',   _ST['hdr']),
        Paragraph('Source',   _ST['hdr']),
        Paragraph('Added At', _ST['hdr']),
    ]]
    wl_style = list(_BASE_TBL)

    for idx, e in enumerate(recent_whitelist, start=1):
        s_bg, s_fg = _source_col(e.source)
        wl_data.append([
            Paragraph(str(idx),               _ST['cell_c']),
            Paragraph(e.cidr,                 _ST['cell_c']),
            Paragraph(f'/{e.prefix_length}',  _ST['cell_c']),
            Paragraph(e.get_source_display(), _ST['cell_c']),
            Paragraph(_fmt(e.added_at),       _ST['cell_c']),
        ])
        wl_style += [('BACKGROUND', (3, idx), (3, idx), s_bg),
                     ('TEXTCOLOR',  (3, idx), (3, idx), s_fg)]

    wl_tbl = Table(wl_data, colWidths=wl_col_w, repeatRows=1)
    wl_tbl.setStyle(TableStyle(wl_style))
    wl_tbl.hAlign = 'LEFT'
    elems.append(wl_tbl)

    doc.build(elems)
    return buf.getvalue()


# ════════════════════════════════════════════════════════════════════════════
#  API REFERENCE
# ════════════════════════════════════════════════════════════════════════════

def _api_page_fn(generated_at, generated_by):
    """Canvas callback for API Reference content pages."""
    def _draw(canvas, doc):
        canvas.saveState()
        W, H = canvas._pagesize  # use actual canvas size — doc.pagesize stays portrait
        canvas.setFillColor(_C.HDR_BG)
        canvas.rect(0, H - 52, W, 52, fill=1, stroke=0)
        canvas.setFillColor(_C.BRAND_SUFFIX)
        canvas.rect(0, H - 52, 4, 52, fill=1, stroke=0)
        brand = _brand_name()   # used in the footer below
        # Left title: '<primary><suffix> — API Reference' — brand split-coloured
        canvas.setFont('Helvetica-Bold', 13)
        width = _draw_brand_left(canvas, 14, H - 22, 13)
        canvas.setFillColor(_C.HDR_TEXT)
        canvas.drawString(14 + width, H - 22, ' — API Reference')
        canvas.setFillColor(_C.HDR_MUTED)
        canvas.setFont('Helvetica', 7.5)
        canvas.drawString(14, H - 34, 'REST API Documentation  |  Base URL: https://<host>:8443/api/v1')
        # Right brand (split-coloured)
        _draw_brand_right(canvas, W - 14, H - 18, 9)
        canvas.setFillColor(_C.HDR_MUTED)
        canvas.setFont('Helvetica', 7)
        canvas.drawRightString(W - 14, H - 29, f'Generated: {generated_at}')
        canvas.drawRightString(W - 14, H - 40, f'By: {generated_by}')
        api_contact_email = _get_platform_email()
        canvas.setStrokeColor(_C.BORDER)
        canvas.setLineWidth(0.4)
        canvas.line(14, 18, W - 14, 18)
        canvas.setFillColor(_C.TEXT_MUTED)
        canvas.setFont('Helvetica', 6.5)
        api_footer_left = f'CONFIDENTIAL — {brand} API Documentation'
        if api_contact_email:
            api_footer_left += f'  |  {api_contact_email}'
        canvas.drawString(14, 7, api_footer_left)
        canvas.drawRightString(W - 14, 7, f'Page {doc.page - 1}')
        canvas.restoreState()
    return _draw


def generate_api_reference(generated_by):
    """Return PDF bytes for the API Reference documentation report."""
    _refresh_brand_suffix()
    buf = io.BytesIO()
    now = timezone.now()
    generated_at = timezone.localtime(now).strftime('%Y-%m-%d %H:%M')

    lm = rm = 20 * mm
    tm = 22 * mm
    bm = 22 * mm
    pw = A4[0] - lm - rm

    cover_cb = _cover_fn(
        report_name='API Reference',
        report_type_label='Documentation',
        generated_at=generated_at,
        generated_by=generated_by,
        filters_text='All Endpoints',
    )
    content_cb = _api_page_fn(generated_at=generated_at, generated_by=generated_by)

    doc, prefix = _build_doc(buf, A4, (lm, rm, tm, bm), cover_cb, content_cb)
    elems = list(prefix)

    from apps.accounts.api_docs import get_endpoints
    ENDPOINTS = get_endpoints()

    def _ps2(name, **kw):
        base = dict(fontName='Helvetica', fontSize=8.5, textColor=_C.TEXT, leading=13)
        base.update(kw)
        return ParagraphStyle(name, **base)

    body_st  = _ps2('api_body')
    slbl_st  = _ps2('api_slbl', fontName='Helvetica-Bold', fontSize=7,
                    textColor=_C.TEXT_MUTED, leading=9, spaceBefore=8, spaceAfter=3)
    code_st  = _ps2('api_code', fontName='Courier', fontSize=7.5, textColor=_C.TEXT, leading=12)
    mono_lbl = _ps2('api_mono_lbl', fontName='Courier', fontSize=7.5, textColor=_C.INFO_FG, leading=11)
    tbl_txt  = _ps2('api_tbl_txt', fontSize=8, textColor=_C.TEXT, leading=11)

    def _sec(label):
        return Paragraph(label.upper(), slbl_st)

    def _method_row(method, path, description):
        m_colors = {'GET': (_C.SUCCESS_BG, _C.SUCCESS_FG), 'POST': (_C.WARNING_BG, _C.WARNING_FG)}
        bg, fg = m_colors.get(method, (_C.MUTED_BG, _C.MUTED_FG))
        m_st = _ps2('m_st', fontName='Helvetica-Bold', fontSize=9, textColor=fg,
                    alignment=TA_CENTER, leading=12)
        p_st = _ps2('p_st', fontName='Courier-Bold', fontSize=9.5, textColor=_C.TEXT, leading=12)
        d_st = _ps2('d_st', fontSize=8.5, textColor=_C.TEXT_MUTED, leading=12)
        return Table(
            [[Paragraph(method, m_st), Paragraph(_html.escape(path), p_st), Paragraph(description, d_st)]],
            colWidths=[18 * mm, 103 * mm, pw - 18 * mm - 103 * mm],
            style=TableStyle([
                ('BACKGROUND',    (0, 0), (0, 0),  bg),
                ('BACKGROUND',    (1, 0), (-1, 0), HexColor('#F0F6FF')),
                ('BOX',           (0, 0), (-1, 0), 0.6, _C.HDR_ACCENT),
                ('INNERGRID',     (0, 0), (-1, 0), 0.4, _C.BORDER),
                ('VALIGN',        (0, 0), (-1, 0), 'MIDDLE'),
                ('TOPPADDING',    (0, 0), (-1, 0), 6),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('LEFTPADDING',   (0, 0), (-1, 0), 8),
                ('RIGHTPADDING',  (0, 0), (-1, 0), 8),
                ('ALIGN',         (0, 0), (0, 0),  'CENTER'),
            ]),
        )

    def _code_block(lines):
        """Lines starting with # are rendered in the muted colour."""
        parts = []
        for ln in lines:
            if not ln or not ln.strip():
                parts.append('&nbsp;')
            elif ln.lstrip().startswith('#'):
                parts.append(f'<font color="#57606A">{_html.escape(ln)}</font>')
            else:
                parts.append(_html.escape(ln))
        p = Paragraph('<br/>'.join(parts), code_st)
        t = Table([[p]], colWidths=[pw])
        t.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), HexColor('#F6F8FA')),
            ('BOX',           (0, 0), (-1, -1), 0.4, _C.BORDER),
            ('LEFTPADDING',   (0, 0), (-1, -1), 10),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 10),
            ('TOPPADDING',    (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        return t

    def _params_tbl(rows, col_name='Parameter'):
        data = [[Paragraph(col_name, _ST['top_hdr']), Paragraph('Description', _ST['top_hdr'])]]
        s = list(_BASE_TBL) + [('ALIGN', (0, 0), (-1, -1), 'LEFT'), ('LEFTPADDING', (0, 0), (-1, -1), 6)]
        for row in rows:
            lbl = row['label'] if isinstance(row, dict) else row[0]
            dsc = row['desc']  if isinstance(row, dict) else row[1]
            data.append([Paragraph(_html.escape(lbl), mono_lbl), Paragraph(dsc, tbl_txt)])
        t = Table(data, colWidths=[pw * 0.32, pw * 0.68], repeatRows=1)
        t.setStyle(TableStyle(s))
        return t

    # ── Base URL kutusu ──────────────────────────────────────────────────
    bu_lbl = _ps2('bu_l', fontName='Helvetica-Bold', fontSize=8, textColor=_C.HDR_MUTED)
    bu_val = _ps2('bu_v', fontName='Courier-Bold', fontSize=9, textColor=_C.HDR_TEXT)
    elems.append(Table(
        [[Paragraph('BASE URL', bu_lbl), Paragraph('https://&lt;host&gt;:8443/api/v1', bu_val)]],
        colWidths=[pw * 0.22, pw * 0.78],
        style=TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), _C.HDR_BG),
            ('BOX',           (0, 0), (-1, -1), 0.6, _C.HDR_ACCENT),
            ('LEFTPADDING',   (0, 0), (-1, -1), 12),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 12),
            ('TOPPADDING',    (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ]),
    ))
    elems.append(Spacer(1, 14))

    # ── api_docs.ENDPOINTS'ten dinamik render ────────────────────────────
    for ep_idx, ep in enumerate(ENDPOINTS):
        elems.append(_method_row(ep['method'], ep['path'], ep['description']))
        elems.append(Spacer(1, 5))
        elems.append(_sec('Authentication'))
        elems.append(Paragraph(ep['auth_pdf'], body_st))
        if ep['auth'] == 'token':
            elems.append(Spacer(1, 3))
            elems.append(_code_block([
                'Authorization: Token <api_user-token>',
                'X-Username: <api_user-username>',
            ]))
        elems.append(Spacer(1, 4))

        for sec in ep['sections']:
            if sec['type'] == 'code':
                elems.append(_sec(sec['label']))
                elems.append(_code_block(sec['lines']))
                elems.append(Spacer(1, 4))
            elif sec['type'] == 'params':
                elems.append(_sec(sec['label']))
                elems.append(_params_tbl(sec['rows'], col_name=sec['col_name']))
                elems.append(Spacer(1, 4))

        if ep_idx < len(ENDPOINTS) - 1:
            elems.append(Spacer(1, 14))

    doc.build(elems)
    return buf.getvalue()
