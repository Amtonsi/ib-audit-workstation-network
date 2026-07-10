from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont


RUSSIAN_LAWS = (
    (
        "УК РФ, статья 272",
        "Неправомерный доступ к охраняемой компьютерной информации, повлекший её уничтожение, блокирование, модификацию или копирование.",
        "https://www.consultant.ru/document/cons_doc_LAW_10699/4398865e2a04f4d3cd99e389c6c5d62e684676f1/",
    ),
    (
        "УК РФ, статья 273",
        "Создание, использование и распространение вредоносных компьютерных программ и иной компьютерной информации.",
        "https://www.consultant.ru/document/cons_doc_LAW_10699/4398865e2a04f4d3cd99e389c6c5d62e684676f1/",
    ),
    (
        "УК РФ, статья 274",
        "Нарушение правил эксплуатации, хранения, обработки или передачи компьютерной информации с предусмотренными законом последствиями.",
        "https://www.consultant.ru/document/cons_doc_LAW_10699/4398865e2a04f4d3cd99e389c6c5d62e684676f1/",
    ),
    (
        "УК РФ, статья 274.1",
        "Неправомерное воздействие на критическую информационную инфраструктуру Российской Федерации.",
        "https://www.consultant.ru/document/cons_doc_LAW_10699/4398865e2a04f4d3cd99e389c6c5d62e684676f1/",
    ),
    (
        "149-ФЗ, статья 16",
        "Защита информации: правовые, организационные и технические меры против неправомерного доступа и иных неправомерных действий.",
        "https://www.consultant.ru/document/cons_doc_LAW_61798/0e9ec16b786dcbdaaa7f44abfc4a15e601d5be22/",
    ),
    (
        "152-ФЗ, статья 19",
        "Меры по обеспечению безопасности персональных данных при их обработке в информационных системах.",
        "https://www.consultant.ru/document/cons_doc_LAW_61801/ca9e5658710519f09ab2fdb8196fcb3eb024a051/",
    ),
)

INTERNATIONAL_LAWS = (
    (
        "Будапештская конвенция",
        "Международная модель противодействия незаконному доступу, перехвату, вмешательству в данные и работу систем.",
        "https://www.coe.int/en/web/cybercrime/the-budapest-convention",
    ),
    (
        "Директива ЕС 2013/40/EU",
        "Определяет незаконный доступ, вмешательство в систему и данные, а также незаконный перехват без права на такие действия.",
        "https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=celex:32013L0040",
    ),
    (
        "США: 18 U.S.C. § 1030",
        "Computer Fraud and Abuse Act охватывает доступ без разрешения или с превышением предоставленного доступа.",
        "https://uscode.house.gov/view.xhtml?req=granuleid:USC-prelim-title18-section1030",
    ),
    (
        "Великобритания: CMA 1990",
        "Computer Misuse Act устанавливает ответственность за несанкционированный доступ и связанные компьютерные правонарушения.",
        "https://www.legislation.gov.uk/ukpga/1990/18/section/1",
    ),
)


def _register_fonts() -> tuple[str, str]:
    regular_candidates = (
        Path("C:/Windows/Fonts/segoeui.ttf"),
        Path("C:/Windows/Fonts/arial.ttf"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
    )
    bold_candidates = (
        Path("C:/Windows/Fonts/seguisb.ttf"),
        Path("C:/Windows/Fonts/arialbd.ttf"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    )
    regular = next((path for path in regular_candidates if path.exists()), None)
    bold = next((path for path in bold_candidates if path.exists()), None)
    if regular is None or bold is None:
        return "Helvetica", "Helvetica-Bold"
    if "LegalGuide" not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont("LegalGuide", str(regular)))
    if "LegalGuide-Bold" not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont("LegalGuide-Bold", str(bold)))
    return "LegalGuide", "LegalGuide-Bold"


def _wrap_text(pdf, text: str, font: str, size: float, width: float) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if current and pdf.stringWidth(candidate, font, size) > width:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines


def _page_header(pdf, title: str, subtitle: str, regular: str, bold: str) -> None:
    width, height = landscape(A4)
    pdf.setFillColor(colors.HexColor("#F2F7F8"))
    pdf.rect(0, 0, width, height, fill=1, stroke=0)
    pdf.setFillColor(colors.HexColor("#153F3D"))
    pdf.roundRect(32, height - 112, width - 64, 80, 18, fill=1, stroke=0)
    pdf.setFont(bold, 23)
    pdf.setFillColor(colors.white)
    pdf.drawString(54, height - 68, title)
    pdf.setFont(regular, 9.5)
    pdf.setFillColor(colors.HexColor("#C9E8E4"))
    pdf.drawString(54, height - 91, subtitle)


def _law_card(
    pdf,
    item: tuple[str, str, str],
    x: float,
    y: float,
    width: float,
    height: float,
    regular: str,
    bold: str,
    accent: str,
) -> None:
    title, body, url = item
    pdf.setFillColor(colors.white)
    pdf.setStrokeColor(colors.HexColor("#D7E3E5"))
    pdf.roundRect(x, y, width, height, 13, fill=1, stroke=1)
    pdf.setFillColor(colors.HexColor(accent))
    pdf.roundRect(x + 14, y + height - 39, 6, 24, 3, fill=1, stroke=0)
    pdf.setFillColor(colors.HexColor("#20383E"))
    pdf.setFont(bold, 11.5)
    pdf.drawString(x + 30, y + height - 31, title)
    pdf.setFont(regular, 8.6)
    pdf.setFillColor(colors.HexColor("#60747B"))
    lines = _wrap_text(pdf, body, regular, 8.6, width - 46)
    text_y = y + height - 54
    for line in lines[:3]:
        pdf.drawString(x + 22, text_y, line)
        text_y -= 12
    link_y = y + 15
    link_text = "Открыть актуальный текст"
    pdf.setFont(bold, 8.3)
    pdf.setFillColor(colors.HexColor(accent))
    pdf.drawString(x + 22, link_y, link_text)
    link_width = pdf.stringWidth(link_text, bold, 8.3)
    pdf.linkURL(url, (x + 20, link_y - 3, x + 25 + link_width, link_y + 10), relative=0)


def _footer(pdf, page: int, regular: str) -> None:
    width, _height = landscape(A4)
    pdf.setStrokeColor(colors.HexColor("#D7E3E5"))
    pdf.line(38, 28, width - 38, 28)
    pdf.setFont(regular, 8)
    pdf.setFillColor(colors.HexColor("#6B7D83"))
    pdf.drawString(38, 14, "IB Audit Workstation · руководство пользователя")
    pdf.drawRightString(width - 38, 14, f"Страница {page}")


def _draw_russian_law_page(pdf, regular: str, bold: str) -> None:
    width, height = landscape(A4)
    _page_header(
        pdf,
        "9. Правовые ограничения: Российская Федерация",
        "Справочный раздел · проверено 11.07.2026 · перед аудитом сверяйте актуальную редакцию",
        regular,
        bold,
    )
    pdf.setFillColor(colors.HexColor("#FFF6E3"))
    pdf.roundRect(38, height - 151, width - 76, 26, 9, fill=1, stroke=0)
    pdf.setFillColor(colors.HexColor("#7C4A08"))
    pdf.setFont(bold, 8.5)
    pdf.drawString(50, height - 141, "Техническая возможность не заменяет письменное разрешение владельца системы.")
    card_width = (width - 92) / 2
    card_height = 112
    y_positions = (height - 274, height - 396, height - 518)
    for index, item in enumerate(RUSSIAN_LAWS):
        column = index % 2
        row = index // 2
        _law_card(
            pdf,
            item,
            38 + column * (card_width + 16),
            y_positions[row],
            card_width,
            card_height,
            regular,
            bold,
            "#0F766E" if index < 4 else "#2563EB",
        )
    _footer(pdf, 11, regular)
    pdf.showPage()


def _draw_international_law_page(pdf, regular: str, bold: str) -> None:
    width, height = landscape(A4)
    _page_header(
        pdf,
        "10. Международные ориентиры и чек-лист допуска",
        "Учитывайте право страны владельца, место обработки данных и трансграничный характер трафика",
        regular,
        bold,
    )
    card_width = (width - 92) / 2
    card_height = 104
    y_positions = (height - 260, height - 374)
    for index, item in enumerate(INTERNATIONAL_LAWS):
        column = index % 2
        row = index // 2
        _law_card(
            pdf,
            item,
            38 + column * (card_width + 16),
            y_positions[row],
            card_width,
            card_height,
            regular,
            bold,
            "#2563EB" if index in {0, 1} else "#B45309",
        )

    pdf.setFillColor(colors.HexColor("#153F3D"))
    pdf.roundRect(38, 64, width - 76, 132, 16, fill=1, stroke=0)
    pdf.setFillColor(colors.white)
    pdf.setFont(bold, 12)
    pdf.drawString(58, 171, "Перед запуском аудита подтвердите:")
    checklist = (
        "1. Письменное разрешение и владельца каждого узла.",
        "2. Точный перечень целей, портов, методов, времени и ответственных.",
        "3. Правила обработки персональных данных и содержимого пакетов.",
        "4. Срок хранения, круг доступа и порядок безопасного удаления отчёта.",
    )
    pdf.setFont(regular, 9)
    pdf.setFillColor(colors.HexColor("#D8F4EF"))
    for index, line in enumerate(checklist):
        x = 58 + (index % 2) * 375
        y = 142 - (index // 2) * 32
        pdf.drawString(x, y, line)
    pdf.setFont(regular, 8)
    pdf.setFillColor(colors.HexColor("#9DD7CF"))
    pdf.drawString(58, 78, "Этот раздел не является юридическим заключением. При сомнении остановите проверку и получите консультацию.")
    _footer(pdf, 12, regular)
    pdf.showPage()


def draw_legal_pages(pdf) -> None:
    regular, bold = _register_fonts()
    _draw_russian_law_page(pdf, regular, bold)
    _draw_international_law_page(pdf, regular, bold)
