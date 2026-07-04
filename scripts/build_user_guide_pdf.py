from __future__ import annotations

import argparse
from datetime import date
from pathlib import Path


GITHUB_REPO = "https://github.com/Amtonsi/ib-audit-workstation"
GITHUB_README = f"{GITHUB_REPO}#readme"
GITHUB_RELEASES = f"{GITHUB_REPO}/releases"
GITHUB_ISSUES = f"{GITHUB_REPO}/issues"
GITHUB_ACTIONS = f"{GITHUB_REPO}/actions"

SOURCE_LINKS = [
    ("CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
    ("NVD Data Feeds", "https://nvd.nist.gov/vuln/data-feeds"),
    ("NVD Vulnerabilities API", "https://nvd.nist.gov/developers/vulnerabilities"),
    ("ФСТЭК БДУ", "https://bdu.fstec.ru/vul"),
]


def _font_path(*names: str) -> Path | None:
    for name in names:
        candidate = Path("C:/Windows/Fonts") / name
        if candidate.exists():
            return candidate
    return None


def build_pdf(output_path: str | Path) -> Path:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.units import mm
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.pdfgen import canvas
    except ImportError as exc:
        raise SystemExit(
            "reportlab is required to build the PDF guide. "
            "Install it with: python -m pip install reportlab"
        ) from exc

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    regular_font = "Helvetica"
    bold_font = "Helvetica-Bold"
    regular_path = _font_path("segoeui.ttf", "arial.ttf", "calibri.ttf")
    bold_path = _font_path("segoeuib.ttf", "arialbd.ttf", "calibrib.ttf")
    if regular_path is not None:
        pdfmetrics.registerFont(TTFont("GuideRegular", str(regular_path)))
        regular_font = "GuideRegular"
    if bold_path is not None:
        pdfmetrics.registerFont(TTFont("GuideBold", str(bold_path)))
        bold_font = "GuideBold"
    elif regular_path is not None:
        bold_font = regular_font

    page_width, page_height = landscape(A4)
    margin = 22 * mm
    c = canvas.Canvas(str(output), pagesize=landscape(A4))
    c.setTitle("IB Audit Workstation - подробная инструкция")
    c.setAuthor("Абдрахманов Амаль Даулетович")
    c.setSubject("Логика работы, запуск, GitHub, пакетная HTML-проверка")

    ink = colors.HexColor("#172126")
    muted = colors.HexColor("#64748B")
    canvas_bg = colors.HexColor("#F3F6F8")
    panel = colors.white
    line = colors.HexColor("#DCE3E7")
    teal = colors.HexColor("#0F766E")
    teal_dark = colors.HexColor("#115E59")
    blue = colors.HexColor("#2563EB")
    violet = colors.HexColor("#6D4AFF")
    amber = colors.HexColor("#B45309")
    red = colors.HexColor("#B91C1C")
    green = colors.HexColor("#15803D")
    light_teal = colors.HexColor("#DDF7F3")
    light_blue = colors.HexColor("#E8F0FF")
    light_violet = colors.HexColor("#F0EDFF")
    light_amber = colors.HexColor("#FFF1E7")
    light_red = colors.HexColor("#FEE2E2")
    light_green = colors.HexColor("#DCFCE7")
    light_gray = colors.HexColor("#E2E8F0")

    def set_font(size: float, bold: bool = False, color=ink) -> None:
        c.setFont(bold_font if bold else regular_font, size)
        c.setFillColor(color)

    def width(text: str, size: float, bold: bool = False) -> float:
        return c.stringWidth(text, bold_font if bold else regular_font, size)

    def draw_wrapped(
        text: str,
        x: float,
        y: float,
        max_width: float,
        size: float = 10.5,
        leading: float = 14,
        bold: bool = False,
        color=ink,
    ) -> float:
        set_font(size, bold=bold, color=color)
        for paragraph in text.split("\n"):
            words = paragraph.split()
            if not words:
                y -= leading
                continue
            line_text = ""
            for word in words:
                candidate = f"{line_text} {word}".strip()
                if width(candidate, size, bold=bold) <= max_width or not line_text:
                    line_text = candidate
                else:
                    c.drawString(x, y, line_text)
                    y -= leading
                    line_text = word
            if line_text:
                c.drawString(x, y, line_text)
                y -= leading
        return y

    def bullet_list(items: list[str], x: float, y: float, max_width: float) -> float:
        for item in items:
            c.setFillColor(teal)
            c.circle(x + 3, y + 4, 2.4, fill=1, stroke=0)
            y = draw_wrapped(item, x + 12, y, max_width - 12, size=10, leading=13.5)
            y -= 2
        return y

    def draw_link(label: str, url: str, x: float, y: float, size: float = 10.5) -> float:
        set_font(size, color=blue)
        c.drawString(x, y, label)
        link_width = width(label, size)
        c.linkURL(url, (x, y - 2, x + link_width, y + size + 2), relative=0)
        c.setStrokeColor(blue)
        c.line(x, y - 2, x + link_width, y - 2)
        return x + link_width

    def card(x: float, y: float, w: float, h: float, fill=panel, stroke=line, radius: float = 10) -> None:
        c.setFillColor(fill)
        c.setStrokeColor(stroke)
        c.roundRect(x, y, w, h, radius, stroke=1, fill=1)

    def section_header(title: str, page: int) -> None:
        c.setFillColor(canvas_bg)
        c.rect(0, 0, page_width, page_height, stroke=0, fill=1)
        c.setFillColor(colors.HexColor("#172126"))
        c.rect(0, page_height - 58, page_width, 58, stroke=0, fill=1)
        set_font(20, bold=True, color=colors.white)
        c.drawString(margin, page_height - 36, title)
        set_font(9, color=colors.HexColor("#B8C4C9"))
        c.drawRightString(page_width - margin, page_height - 34, "IB Audit Workstation")
        set_font(8.5, color=muted)
        c.drawString(margin, 18, "GitHub:")
        draw_link(GITHUB_REPO, GITHUB_REPO, margin + 38, 18, size=8.5)
        set_font(8.5, color=muted)
        c.drawRightString(page_width - margin, 18, f"Страница {page}")

    def arrow(x1: float, y1: float, x2: float, y2: float, color=teal) -> None:
        c.setStrokeColor(color)
        c.setLineWidth(2.2)
        c.line(x1, y1, x2, y2)
        if x2 >= x1:
            points = [(x2, y2), (x2 - 8, y2 + 5), (x2 - 8, y2 - 5)]
        else:
            points = [(x2, y2), (x2 + 8, y2 + 5), (x2 + 8, y2 - 5)]
        c.setFillColor(color)
        path = c.beginPath()
        path.moveTo(points[0][0], points[0][1])
        path.lineTo(points[1][0], points[1][1])
        path.lineTo(points[2][0], points[2][1])
        path.close()
        c.drawPath(path, stroke=0, fill=1)

    def label_box(
        title: str,
        body: str,
        x: float,
        y: float,
        w: float,
        h: float,
        fill=panel,
        title_color=ink,
    ) -> None:
        card(x, y, w, h, fill=fill)
        set_font(12, bold=True, color=title_color)
        c.drawString(x + 12, y + h - 22, title)
        draw_wrapped(body, x + 12, y + h - 42, w - 24, size=9.3, leading=12.5, color=muted)

    def pill(text: str, x: float, y: float, fill, color=ink, pad: float = 8) -> None:
        set_font(9, bold=True, color=color)
        w = width(text, 9, bold=True) + pad * 2
        c.setFillColor(fill)
        c.roundRect(x, y, w, 20, 10, stroke=0, fill=1)
        set_font(9, bold=True, color=color)
        c.drawString(x + pad, y + 6, text)

    def draw_simple_window(x: float, y: float, w: float, h: float) -> None:
        c.setFillColor(colors.white)
        c.setStrokeColor(line)
        c.roundRect(x, y, w, h, 10, stroke=1, fill=1)
        c.setFillColor(colors.HexColor("#172126"))
        c.rect(x, y + h - 62, w, 62, stroke=0, fill=1)
        set_font(18, bold=True, color=colors.white)
        c.drawString(x + 20, y + h - 38, "IB Audit Workstation")
        set_font(8.5, color=colors.HexColor("#B8C4C9"))
        c.drawString(x + 20, y + h - 52, "Рабочая станция специалиста информационной безопасности")
        c.setFillColor(teal)
        c.rect(x + w - 92, y + h - 43, 70, 26, stroke=0, fill=1)
        set_font(8.5, bold=True, color=colors.white)
        c.drawCentredString(x + w - 57, y + h - 34, "Готово")

        rail_w = 160
        c.setFillColor(colors.white)
        c.rect(x, y, rail_w, h - 62, stroke=0, fill=1)
        c.setStrokeColor(line)
        c.line(x + rail_w, y, x + rail_w, y + h - 62)
        set_font(7.5, bold=True, color=muted)
        c.drawString(x + 16, y + h - 88, "НОВЫЙ АНАЛИЗ")
        c.setFillColor(teal)
        c.rect(x + 16, y + h - 124, rail_w - 32, 28, stroke=0, fill=1)
        set_font(8.4, bold=True, color=colors.white)
        c.drawCentredString(x + rail_w / 2, y + h - 115, "Полный аудит")
        for i, text in enumerate(["Проверить HTML", "Обновить базы", "Отменить"]):
            yy = y + h - 160 - i * 34
            c.setFillColor(colors.HexColor("#EDF2F4"))
            c.rect(x + 16, yy, rail_w - 32, 26, stroke=0, fill=1)
            set_font(8.2, bold=i < 2, color=ink if i < 2 else muted)
            c.drawCentredString(x + rail_w / 2, yy + 8, text)
        set_font(7.5, bold=True, color=muted)
        c.drawString(x + 16, y + 118, "РЕЗУЛЬТАТЫ")
        c.setFillColor(colors.HexColor("#EDF2F4"))
        c.rect(x + 16, y + 82, rail_w - 32, 26, stroke=0, fill=1)
        set_font(8, bold=True, color=ink)
        c.drawCentredString(x + rail_w / 2, y + 90, "Открыть отчёт")
        set_font(7.3, color=muted)
        c.drawString(x + 16, y + 28, "Разработал: Абдрахманов")
        c.drawString(x + 16, y + 16, "Амаль Даулетович")

        content_x = x + rail_w + 16
        content_w = w - rail_w - 32
        panel_h = 42
        panels = [
            ("Источники проверки", ["CISA KEV", "NVD", "ФСТЭК"]),
            ("Режим проверки уязвимостей", ["Полный онлайн", "Быстрый кэш"]),
            ("Папка отчётов", ["outputs"]),
        ]
        for idx, (title_text, tags) in enumerate(panels):
            yy = y + h - 118 - idx * 54
            card(content_x, yy, content_w, panel_h, fill=colors.white, radius=4)
            set_font(8.8, bold=True, color=ink)
            c.drawString(content_x + 10, yy + 25, title_text)
            tx = content_x + 150
            for tag in tags:
                tag_fill = light_blue if tag == "CISA KEV" else light_violet if tag == "NVD" else light_amber
                pill(tag, tx, yy + 12, tag_fill, color=blue if tag == "CISA KEV" else violet if tag == "NVD" else amber, pad=5)
                tx += width(tag, 9, True) + 22
        card(content_x, y + 30, content_w, 128, fill=colors.white, radius=4)
        set_font(8.8, bold=True, color=ink)
        c.drawString(content_x + 10, y + 136, "Журнал выполнения")
        set_font(7.5, color=muted)
        c.drawString(content_x + 10, y + 114, "Прогресс: сбор инвентаря")
        c.setFillColor(colors.HexColor("#DDE6E8"))
        c.rect(content_x + 10, y + 96, content_w - 20, 8, stroke=0, fill=1)
        c.setFillColor(teal)
        c.rect(content_x + 10, y + 96, (content_w - 20) * 0.58, 8, stroke=0, fill=1)
        c.setFillColor(colors.HexColor("#F8FAFB"))
        c.rect(content_x + 10, y + 48, content_w - 20, 36, stroke=0, fill=1)
        set_font(7, color=muted)
        c.drawString(content_x + 18, y + 68, "Running collector: system_hardware")
        c.drawString(content_x + 18, y + 56, "Assessing vulnerabilities...")

    def draw_cover_window(x: float, y: float, w: float, h: float) -> None:
        c.setFillColor(colors.white)
        c.setStrokeColor(line)
        c.roundRect(x, y, w, h, 10, stroke=1, fill=1)

        header_h = 56
        rail_w = 100
        c.setFillColor(colors.HexColor("#172126"))
        c.rect(x, y + h - header_h, w, header_h, stroke=0, fill=1)
        set_font(13, bold=True, color=colors.white)
        c.drawString(x + 14, y + h - 28, "IB Audit Workstation")
        set_font(6.5, color=colors.HexColor("#B8C4C9"))
        c.drawString(x + 14, y + h - 43, "Рабочая станция ИБ")
        c.setFillColor(teal)
        c.rect(x + w - 72, y + h - 39, 56, 24, stroke=0, fill=1)
        set_font(7.2, bold=True, color=colors.white)
        c.drawCentredString(x + w - 44, y + h - 30, "Готово")

        body_h = h - header_h
        c.setFillColor(colors.white)
        c.rect(x, y, rail_w, body_h, stroke=0, fill=1)
        c.setStrokeColor(line)
        c.line(x + rail_w, y, x + rail_w, y + body_h)
        set_font(6.5, bold=True, color=muted)
        c.drawString(x + 12, y + body_h - 24, "НОВЫЙ АНАЛИЗ")

        def nav_button(text: str, yy: float, active: bool = False) -> None:
            c.setFillColor(teal if active else colors.HexColor("#EDF2F4"))
            c.rect(x + 12, yy, rail_w - 24, 24, stroke=0, fill=1)
            set_font(6.7, bold=True, color=colors.white if active else ink)
            c.drawCentredString(x + rail_w / 2, yy + 8, text)

        nav_button("Полный аудит", y + body_h - 58, active=True)
        nav_button("Проверить HTML", y + body_h - 88)
        nav_button("Обновить базы", y + body_h - 118)
        set_font(6.5, bold=True, color=muted)
        c.drawString(x + 12, y + body_h - 152, "РЕЗУЛЬТАТЫ")
        nav_button("Открыть отчёт", y + body_h - 186)
        set_font(6.1, color=muted)
        c.drawString(x + 12, y + 28, "Разработал: Абдрахманов")
        c.drawString(x + 12, y + 16, "Амаль Даулетович")

        content_x = x + rail_w + 12
        content_w = w - rail_w - 24
        panel_h = 36
        for idx, (title_text, tag_text, tag_fill, tag_color) in enumerate(
            [
                ("Источники", "CISA / NVD / ФСТЭК", light_blue, blue),
                ("Режим проверки", "Быстрый кэш", light_amber, amber),
                ("Папка отчётов", "outputs", light_amber, amber),
            ]
        ):
            yy = y + h - header_h - 18 - idx * 48 - panel_h
            card(content_x, yy, content_w, panel_h, fill=colors.white, radius=5)
            set_font(7.2, bold=True, color=ink)
            c.drawString(content_x + 8, yy + 22, title_text)
            c.setFillColor(tag_fill)
            c.roundRect(content_x + 8, yy + 6, content_w - 16, 13, 6.5, stroke=0, fill=1)
            set_font(6.2, bold=True, color=tag_color)
            c.drawCentredString(content_x + content_w / 2, yy + 10, tag_text)

        log_y = y + 20
        log_h = 58
        card(content_x, log_y, content_w, log_h, fill=colors.white, radius=5)
        set_font(7.2, bold=True, color=ink)
        c.drawString(content_x + 8, log_y + 42, "Журнал")
        set_font(6.1, color=muted)
        c.drawString(content_x + 8, log_y + 30, "Прогресс: аудит")
        c.setFillColor(colors.HexColor("#DDE6E8"))
        c.rect(content_x + 8, log_y + 20, content_w - 16, 6, stroke=0, fill=1)
        c.setFillColor(teal)
        c.rect(content_x + 8, log_y + 20, (content_w - 16) * 0.55, 6, stroke=0, fill=1)
        c.setFillColor(colors.HexColor("#F8FAFB"))
        c.rect(content_x + 8, log_y + 6, content_w - 16, 10, stroke=0, fill=1)
        set_font(5.5, color=muted)
        c.drawString(content_x + 12, log_y + 9, "Assessing vulnerabilities...")

    # Page 1 - cover
    c.setFillColor(colors.HexColor("#172126"))
    c.rect(0, 0, page_width, page_height, stroke=0, fill=1)
    c.setFillColor(teal)
    c.rect(0, 0, 170, page_height, stroke=0, fill=1)
    c.setFillColor(colors.HexColor("#0B4D49"))
    c.circle(120, page_height - 110, 84, stroke=0, fill=1)
    set_font(34, bold=True, color=colors.white)
    c.drawString(205, page_height - 145, "IB Audit Workstation")
    set_font(20, color=colors.HexColor("#B8C4C9"))
    c.drawString(205, page_height - 180, "Подробная инструкция пользователя")
    set_font(12.5, color=colors.white)
    y = page_height - 238
    y = draw_wrapped(
        "Локальная read-only рабочая станция для аудита Windows, анализа HTML-отчётов "
        "и проверки известных уязвимостей по CISA KEV, NVD и ФСТЭК БДУ.",
        205,
        y,
        320,
        size=12.5,
        leading=18,
        color=colors.white,
    )
    y -= 18
    set_font(12, color=colors.white)
    c.drawString(205, y, "Разработал: Абдрахманов Амаль Даулетович")
    y -= 26
    c.drawString(205, y, f"Дата инструкции: {date.today().strftime('%d.%m.%Y')}")
    y -= 34
    draw_link("GitHub: Amtonsi/ib-audit-workstation", GITHUB_REPO, 205, y, size=12)
    draw_cover_window(548, 112, 252, 308)
    c.showPage()

    # Page 2 - GitHub and quick start
    section_header("1. Где находится проект и как начать", 2)
    x = margin
    y = page_height - 92
    card(x, y - 118, 370, 118, fill=panel)
    set_font(15, bold=True)
    c.drawString(x + 16, y - 26, "GitHub-репозиторий")
    draw_link("Открыть репозиторий", GITHUB_REPO, x + 16, y - 54, size=10.5)
    draw_link("README на GitHub", GITHUB_README, x + 16, y - 78, size=10.5)
    draw_link("Раздел Releases", GITHUB_RELEASES, x + 16, y - 102, size=10.5)

    card(x + 400, y - 118, 370, 118, fill=panel)
    set_font(15, bold=True)
    c.drawString(x + 416, y - 26, "Что публикуется")
    bullet_list(
        [
            "исходный код, тесты, README, MIT-лицензия",
            "безопасные SVG-схемы без реальных данных",
            "скрипты сборки и GitHub Actions",
        ],
        x + 416,
        y - 54,
        330,
    )

    y -= 160
    set_font(16, bold=True)
    c.drawString(x, y, "Быстрый старт из исходников")
    y -= 26
    step_w = 220
    step_gap = 42
    label_box(
        "1. Клонировать",
        "git clone https://github.com/Amtonsi/ib-audit-workstation.git",
        x,
        y - 72,
        step_w,
        72,
        fill=light_blue,
        title_color=blue,
    )
    label_box(
        "2. Запустить GUI",
        "python run_app.py\nДля полного сбора лучше использовать запуск от администратора.",
        x + step_w + step_gap,
        y - 72,
        step_w,
        72,
        fill=light_teal,
        title_color=teal,
    )
    label_box(
        "3. Проверить качество",
        "python -m unittest discover -s tests\npython -m compileall -q src run_app.py run_audit.py scripts",
        x + (step_w + step_gap) * 2,
        y - 72,
        step_w,
        72,
        fill=light_green,
        title_color=green,
    )
    arrow(x + step_w + 5, y - 36, x + step_w + step_gap - 8, y - 36)
    arrow(x + step_w * 2 + step_gap + 5, y - 36, x + (step_w + step_gap) * 2 - 8, y - 36)

    y -= 116
    set_font(16, bold=True)
    c.drawString(x, y, "Готовая Windows-сборка")
    y = draw_wrapped(
        "Если сборка опубликована в GitHub Releases, скачайте ZIP, полностью распакуйте папку "
        "IBAuditWorkstation и запускайте IBAuditWorkstation.exe. Не запускайте EXE прямо из ZIP.",
        x,
        y - 24,
        760,
        size=11,
        leading=15,
    )
    draw_link("Открыть GitHub Releases", GITHUB_RELEASES, x, y - 4, size=11)
    c.showPage()

    # Page 3 - UI
    section_header("2. Оболочка приложения", 3)
    draw_simple_window(margin, 92, 470, 382)
    x2 = margin + 500
    y = page_height - 100
    set_font(16, bold=True)
    c.drawString(x2, y, "Основные зоны окна")
    y -= 26
    y = bullet_list(
        [
            "левая панель запускает полный аудит, пакетную HTML-проверку и обновление источников",
            "кнопка Отменить активна только во время операции и останавливает работу в безопасной точке",
            "панель источников показывает CISA KEV, NVD и ФСТЭК БДУ",
            "кнопка Обновить базы сначала ищет vulnerability_sources.db в папке проекта и подпапках, затем докачивает только актуальные или отсутствующие источники",
            "режимы уязвимостей переключают полный онлайн-поиск или быстрый кэш NVD/CISA",
            "журнал выполнения показывает текущий этап, ошибки и прогресс",
            "нижняя подпись фиксирует автора приложения",
        ],
        x2,
        y,
        230,
    )
    y -= 12
    card(x2, y - 86, 238, 86, fill=light_amber)
    set_font(12.5, bold=True, color=amber)
    c.drawString(x2 + 14, y - 22, "Практический совет")
    draw_wrapped(
        "Для максимального покрытия запускайте программу от администратора. "
        "Если источник данных недоступен, объект получает статус insufficient_data, а не скрывается.",
        x2 + 14,
        y - 42,
        210,
        size=9.5,
        leading=12.5,
    )
    c.showPage()

    # Page 4 - usage instructions
    section_header("Как пользоваться", 4)
    instructions = [
        (
            "1. Запустить от администратора",
            "Полностью распакуйте Windows-сборку. Нажмите правой кнопкой по "
            "IBAuditWorkstation.exe и выберите «Запуск от имени администратора».",
            light_teal,
            teal,
        ),
        (
            "2. Выбрать папку отчётов",
            "Проверьте поле «Папка отчётов». Нажмите «Изменить», если HTML и "
            "локальную историю нужно сохранять в другую папку.",
            light_blue,
            blue,
        ),
        (
            "3. Обновить базы",
            "Нажмите «Обновить базы». Программа найдёт существующую "
            "vulnerability_sources.db и добавит только отсутствующие или "
            "обновлённые данные.",
            light_violet,
            violet,
        ),
        (
            "4. Выбрать режим",
            "«Полный онлайн ФСТЭК» выполняет онлайн-поиск БДУ. Быстрый режим "
            "использует локальные базы NVD и CISA без длительных запросов ФСТЭК.",
            light_amber,
            amber,
        ),
        (
            "5. Запустить проверку",
            "«Полный аудит компьютера» проверяет текущую систему. «Проверить "
            "HTML-отчёты» позволяет выбрать несколько документов и получить "
            "один сводный HTML.",
            light_green,
            green,
        ),
        (
            "6. Следить или отменить",
            "Текущий этап отображается в журнале выполнения. Кнопка «Отменить» "
            "останавливает операцию в ближайшей безопасной точке.",
            light_red,
            red,
        ),
        (
            "7. Открыть результат",
            "После завершения нажмите «Открыть последний отчёт» либо «Открыть "
            "папку отчётов». Сетевые источники и ошибки перечисляются в диагностике.",
            light_blue,
            blue,
        ),
        (
            "8. Перейти к риску",
            "В сводном HTML раскройте компьютер и полный инвентарь. Нажмите "
            "компактную ссылку CVE/БДУ под объектом для перехода к точной "
            "карточке риска.",
            light_teal,
            teal,
        ),
    ]
    column_gap = 20
    column_width = (page_width - margin * 2 - column_gap) / 2
    card_height = 78
    row_gap = 12
    top_y = page_height - 92
    for index, (title_text, body_text, fill, title_color) in enumerate(instructions):
        column = index % 2
        row = index // 2
        card_x = margin + column * (column_width + column_gap)
        card_y = top_y - card_height - row * (card_height + row_gap)
        card(card_x, card_y, column_width, card_height, fill=fill)
        set_font(12, bold=True, color=title_color)
        c.drawString(card_x + 14, card_y + card_height - 22, title_text)
        draw_wrapped(
            body_text,
            card_x + 14,
            card_y + card_height - 42,
            column_width - 28,
            size=8.8,
            leading=11.5,
            color=ink,
        )

    note_y = 54
    card(margin, note_y, page_width - margin * 2, 56, fill=light_amber)
    set_font(11.5, bold=True, color=amber)
    c.drawString(margin + 14, note_y + 34, "После обновления приложения")
    draw_wrapped(
        "Старые HTML-файлы не изменяются автоматически. Чтобы увидеть новые "
        "элементы отчёта, запустите проверку исходных HTML-документов повторно.",
        margin + 205,
        note_y + 34,
        page_width - margin * 2 - 220,
        size=9.2,
        leading=12,
        color=ink,
    )
    c.showPage()

    # Page 5 - logic pipeline
    section_header("3. Логика обработки данных", 5)
    y = page_height - 128
    x = margin
    box_w = 108
    step_gap = 18
    box_h = 90
    steps = [
        ("1. Вход", "Windows collectors\nили HTML-отчёты"),
        ("2. Инвентарь", "единые объекты\nи evidence-поля"),
        ("3. Диагностика", "ошибки доступа\nи недоступные источники"),
        ("4. Правила", "JSON rulepacks\nи статусы объектов"),
        ("5. Уязвимости", "CISA, NVD,\nФСТЭК БДУ"),
    ]
    for idx, (title_text, body_text) in enumerate(steps):
        xx = x + idx * (box_w + step_gap)
        label_box(title_text, body_text, xx, y - box_h, box_w, box_h, fill=panel, title_color=teal)
        if idx < len(steps) - 1:
            arrow(xx + box_w + 3, y - box_h / 2, xx + box_w + step_gap - 4, y - box_h / 2)
    label_box("6. Результат", "SQLite-история\nHTML-отчёт\nсводный batch-отчёт", x + 5 * (box_w + step_gap), y - box_h, box_w, box_h, fill=light_green, title_color=green)
    arrow(x + 4 * (box_w + step_gap) + box_w + 3, y - box_h / 2, x + 5 * (box_w + step_gap) - 4, y - box_h / 2)

    y -= 136
    set_font(16, bold=True)
    c.drawString(margin, y, "Статусы объектов")
    y -= 34
    statuses = [
        ("risk", "найден риск или нарушение", light_red, red),
        ("passed", "применимые правила пройдены", light_green, green),
        ("insufficient_data", "данных недостаточно для вывода", light_amber, amber),
        ("not_applicable", "нет применимых правил", light_gray, muted),
    ]
    for idx, (name, desc, fill, color) in enumerate(statuses):
        xx = margin + idx * 198
        card(xx, y - 72, 180, 72, fill=fill)
        pill(name, xx + 14, y - 30, colors.white, color=color, pad=8)
        draw_wrapped(desc, xx + 14, y - 48, 150, size=9.3, leading=12, color=ink)

    y -= 114
    card(margin, y - 74, page_width - margin * 2, 74, fill=light_blue)
    set_font(13, bold=True, color=blue)
    c.drawString(margin + 16, y - 24, "Ключевой принцип")
    draw_wrapped(
        "Отсутствие доказательств не считается безопасностью. Если объект найден, но данных для проверки мало, "
        "он явно попадает в отчёт как insufficient_data.",
        margin + 16,
        y - 44,
        page_width - margin * 2 - 32,
        size=10.5,
        leading=14,
    )
    c.showPage()

    # Page 6 - vulnerability sources
    section_header("4. Источники уязвимостей и режимы", 6)
    x = margin
    y = page_height - 108
    set_font(15, bold=True)
    c.drawString(x, y, "Как сопоставляются уязвимости")
    y -= 34
    src_boxes = [
        ("CISA KEV", "каталог известных эксплуатируемых уязвимостей", light_blue, blue),
        ("NVD CVE", "bulk feeds, recent и modified snapshots", light_violet, violet),
        ("ФСТЭК БДУ", "онлайн-поиск по применимым объектам", light_amber, amber),
    ]
    for idx, (title_text, body_text, fill, color) in enumerate(src_boxes):
        xx = x + idx * 250
        label_box(title_text, body_text, xx, y - 88, 220, 88, fill=fill, title_color=color)
        if idx < len(src_boxes) - 1:
            arrow(xx + 224, y - 44, xx + 244, y - 44, color=muted)
    y -= 118
    set_font(15, bold=True)
    c.drawString(x, y, "Режимы в интерфейсе")
    y -= 24
    label_box(
        "Полный онлайн ФСТЭК",
        "Использует CISA KEV, NVD и онлайн-запросы ФСТЭК БДУ. Подходит для максимально полной проверки при наличии интернета.",
        x,
        y - 86,
        370,
        86,
        fill=panel,
        title_color=teal,
    )
    label_box(
        "Быстро: кэш NVD/CISA",
        "Использует локальные snapshots NVD/CISA без длительного онлайн-поиска ФСТЭК. Подходит для быстрой проверки.",
        x + 410,
        y - 86,
        370,
        86,
        fill=panel,
        title_color=blue,
    )
    y -= 112
    set_font(15, bold=True)
    c.drawString(x, y, "CPE, версии и аппаратные риски")
    y -= 24
    label_box(
        "Что сравнивается",
        "Для ПО и оборудования нормализуются производитель, название, модель и версия. Объект связывается с CPE/NVD; CPE Match включается флагом --with-cpe-match.",
        x,
        y - 86,
        245,
        86,
        fill=panel,
        title_color=teal,
    )
    label_box(
        "Подтверждено",
        "Риск подтверждён, когда продукт совпал с CPE и установленная версия входит в уязвимый диапазон CVE.",
        x + 270,
        y - 86,
        245,
        86,
        fill=light_green,
        title_color=green,
    )
    label_box(
        "Потенциальный риск",
        "Для процессоров, BIOS и прошивок модель может совпасть, но версии firmware/microcode нет. Такой случай помечается как потенциальный риск.",
        x + 540,
        y - 86,
        245,
        86,
        fill=light_amber,
        title_color=amber,
    )
    y -= 104
    set_font(15, bold=True)
    c.drawString(x, y, "Официальные ссылки")
    y -= 22
    for index, (label, url) in enumerate(SOURCE_LINKS):
        link_x = x + (index // 2) * 390
        link_y = y - (index % 2) * 18
        set_font(10, bold=True)
        c.drawString(link_x, link_y, f"{label}:")
        draw_link(url, url, link_x + 118, link_y, size=9.2)
    c.showPage()

    # Page 7 - batch HTML and cancellation
    section_header("5. Проверка нескольких HTML-документов", 7)
    x = margin + 18
    y = page_height - 124
    for idx, name in enumerate(["host-a.html", "host-b.html", "host-c.html"]):
        card(x, y - idx * 46, 128, 30, fill=colors.white, radius=5)
        set_font(9.5, bold=True)
        c.drawCentredString(x + 64, y + 10 - idx * 46, name)
    import_x = x + 205
    assess_x = x + 405
    report_x = x + 610
    arrow(x + 140, y - 39, import_x - 14, y - 39)
    label_box("Импорт", "HTML разбирается в единый инвентарь и диагностику.", import_x, y - 82, 145, 86, fill=light_blue, title_color=blue)
    arrow(import_x + 150, y - 39, assess_x - 14, y - 39)
    label_box("Оценка", "Правила и источники уязвимостей применяются к каждому документу.", assess_x, y - 82, 155, 86, fill=light_teal, title_color=teal)
    arrow(assess_x + 160, y - 39, report_x - 14, y - 39)
    label_box("Сводный HTML", "Один отчёт сравнивает компьютеры, риски и ошибки файлов.", report_x, y - 82, 140, 86, fill=light_green, title_color=green)

    y -= 148
    set_font(16, bold=True)
    c.drawString(margin, y, "Что показывает сводный отчёт")
    y -= 28
    y = bullet_list(
        [
            "общую статистику по всем выбранным документам",
            "сравнение компьютеров по критическим и высоким рискам",
            "повторяющиеся CVE, БДУ и нарушения конфигурации",
            "ошибки отдельных входных HTML-файлов без остановки всей партии",
            "детализацию по каждому обработанному документу",
        ],
        margin,
        y,
        370,
    )
    card(margin + 410, page_height - 358, 330, 150, fill=light_amber)
    set_font(14, bold=True, color=amber)
    c.drawString(margin + 448, page_height - 238, "Отмена проверки")
    draw_wrapped(
        "Кнопка Отменить отправляет cooperative cancel-сигнал. Уже запущенный системный или сетевой вызов "
        "завершается по своему тайм-ауту, после чего приложение останавливается в безопасной точке. "
        "Если часть HTML-документов обработана, может быть создан частичный отчёт.",
        margin + 428,
        page_height - 262,
        292,
        size=10.2,
        leading=13.5,
    )
    c.showPage()

    # Page 8 - report, privacy
    section_header("6. Отчёт, приватность и публикация", 8)
    x = margin
    y = page_height - 104
    set_font(16, bold=True)
    c.drawString(x, y, "HTML-отчёт")
    y -= 28
    label_box("Навигация", "левая структура разделов, как в WinAudit-подобном отчёте", x, y - 74, 235, 74, fill=panel, title_color=teal)
    label_box("Карточки объектов", "каждый объект показывает evidence-поля, статус и применённые правила", x + 270, y - 74, 235, 74, fill=panel, title_color=blue)
    label_box("Рекомендации", "риски сопровождаются объяснением и действиями по исправлению", x + 540, y - 74, 235, 74, fill=panel, title_color=amber)
    y -= 124
    set_font(16, bold=True)
    c.drawString(x, y, "Граница приватности")
    y -= 26
    safe_w = 350
    card(x, y - 160, safe_w, 160, fill=light_green)
    set_font(13, bold=True, color=green)
    c.drawString(x + 16, y - 24, "Можно публиковать")
    bullet_list(
        ["src, tests, scripts", "README, LICENSE, SECURITY", "docs/images и этот PDF", "GitHub Actions workflow"],
        x + 16,
        y - 48,
        safe_w - 32,
    )
    card(x + 400, y - 160, safe_w, 160, fill=light_red)
    set_font(13, bold=True, color=red)
    c.drawString(x + 416, y - 24, "Оставить локально")
    bullet_list(
        ["outputs и локальные HTML-отчёты", "SQLite-базы аудита", "EXE/ZIP, если внутри реальные результаты", "логи с пользователями, путями, IP"],
        x + 416,
        y - 48,
        safe_w - 32,
    )
    y -= 206
    draw_link("GitHub Issues для замечаний и задач", GITHUB_ISSUES, x, y, size=11)
    y -= 22
    draw_link("GitHub Actions для проверки тестов", GITHUB_ACTIONS, x, y, size=11)
    c.showPage()

    # Page 9 - commands and build
    section_header("7. Команды сборки и проверки", 9)
    x = margin
    y = page_height - 104
    set_font(16, bold=True)
    c.drawString(x, y, "Запуск")
    y -= 30
    commands = [
        ("GUI", "python run_app.py"),
        ("CLI-аудит", "python run_audit.py --no-open"),
        ("Offline-аудит", "python run_audit.py --offline --no-open"),
        ("Обновление БД", "python scripts/update_vulnerability_database.py --output outputs\\vulnerability-database\nпереиспользует CPE Dictionary; большой CPE Match включается флагом --with-cpe-match"),
        ("Сборка EXE", "python -m PyInstaller build\\pyinstaller\\IBAuditWorkstation.spec --noconfirm --clean --distpath outputs\\dist --workpath build\\pyinstaller\\work-batch-html"),
        ("Сборка PDF", "python scripts\\build_user_guide_pdf.py --output docs\\IBAuditWorkstation_UserGuide_RU.pdf"),
        ("Тесты", "python -m unittest discover -s tests"),
    ]
    row_h = 45
    table_w = page_width - margin * 2
    c.setStrokeColor(line)
    c.setFillColor(colors.white)
    c.roundRect(x, y - row_h * len(commands) - 14, table_w, row_h * len(commands) + 14, 8, stroke=1, fill=1)
    yy = y - 22
    for label, command in commands:
        set_font(9.5, bold=True)
        c.drawString(x + 14, yy, label)
        draw_wrapped(command, x + 160, yy, table_w - 180, size=8.4, leading=10.5, color=muted)
        yy -= row_h
        c.setStrokeColor(colors.HexColor("#EEF2F4"))
        c.line(x + 10, yy + 14, x + table_w - 10, yy + 14)

    y = yy - 8
    card(x, y - 68, table_w, 68, fill=light_amber)
    set_font(13, bold=True, color=amber)
    c.drawString(x + 16, y - 24, "Важно про PyInstaller")
    draw_wrapped(
        "Используйте готовый build\\pyinstaller\\IBAuditWorkstation.spec. Он добавляет rulepacks JSON в сборку. "
        "Если регенерировать spec через --name и --specpath, приложение может не найти windows_base.json.",
        x + 16,
        y - 44,
        table_w - 32,
        size=10,
        leading=13,
    )
    c.showPage()

    c.save()
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Russian PDF user guide with diagrams and GitHub links.")
    parser.add_argument("--output", default="docs/IBAuditWorkstation_UserGuide_RU.pdf")
    args = parser.parse_args()
    path = build_pdf(args.output)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
