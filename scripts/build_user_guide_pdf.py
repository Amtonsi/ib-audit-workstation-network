from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _font_path() -> Path | None:
    candidates = [
        Path("C:/Windows/Fonts/arial.ttf"),
        Path("C:/Windows/Fonts/segoeui.ttf"),
        Path("C:/Windows/Fonts/calibri.ttf"),
    ]
    return next((path for path in candidates if path.exists()), None)


def build_pdf(output_path: str | Path) -> Path:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.platypus import ListFlowable, ListItem, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise SystemExit("reportlab is required to build the PDF guide. Install it with: python -m pip install reportlab") from exc

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    font_name = "Helvetica"
    font = _font_path()
    if font is not None:
        pdfmetrics.registerFont(TTFont("GuideFont", str(font)))
        font_name = "GuideFont"

    styles = getSampleStyleSheet()
    title = ParagraphStyle("GuideTitle", parent=styles["Title"], fontName=font_name, fontSize=22, leading=28, spaceAfter=12)
    h1 = ParagraphStyle("GuideH1", parent=styles["Heading1"], fontName=font_name, fontSize=16, leading=21, spaceBefore=12, spaceAfter=8)
    body = ParagraphStyle("GuideBody", parent=styles["BodyText"], fontName=font_name, fontSize=10.5, leading=15, spaceAfter=6)
    small = ParagraphStyle("GuideSmall", parent=body, fontSize=9, leading=12, textColor=colors.HexColor("#475569"))

    doc = SimpleDocTemplate(
        str(output),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="IB Audit Workstation - инструкция пользователя",
    )

    def bullets(items: list[str]) -> ListFlowable:
        return ListFlowable([ListItem(Paragraph(item, body), leftIndent=8) for item in items], bulletType="bullet", leftIndent=12)

    def table_cell(text: str) -> Paragraph:
        return Paragraph(text, body)

    story = [
        Paragraph("IB Audit Workstation", title),
        Paragraph("Инструкция пользователя и администратора", h1),
        Paragraph(
            "IB Audit Workstation - локальная read-only программа для полного аудита Windows, "
            "проверки известных уязвимостей и формирования автономного HTML-отчёта.",
            body,
        ),
        Paragraph("1. Что входит в поставку", h1),
        bullets(
            [
                "папка IBAuditWorkstation со скомпилированным EXE;",
                "локальная база vulnerability_sources.db;",
                "исходные snapshots NVD и CISA KEV;",
                "правило возраста пароля пользователей: warning после 60 дней, critical после 90 дней;",
                "LICENSE с MIT-лицензией;",
                "данная PDF-инструкция и release-manifest.json с SHA256;",
            ]
        ),
        Paragraph("2. Рекомендуемый запуск", h1),
        bullets(
            [
                "запустите IBAuditWorkstation.exe от администратора;",
                "для максимальной проверки оставьте доступ к интернету;",
                "дождитесь завершения прогресс-бара;",
                "откройте созданный HTML-отчёт из папки outputs;",
            ]
        ),
        Paragraph("3. Значение показателей отчёта", h1),
        Table(
            [
                [table_cell("Показатель"), table_cell("Значение")],
                [table_cell("объектов обработано"), table_cell("доля объектов, сохранённых, классифицированных и отображённых в отчёте")],
                [table_cell("проверено правилами"), table_cell("доля объектов с автоматическим pass/risk по применимым правилам")],
                [table_cell("недостаточно данных"), table_cell("объект есть, но не хватает источника, версии или права доступа")],
                [table_cell("не применимо"), table_cell("объект не имеет применимой автоматической проверки")],
            ],
            colWidths=[42 * mm, 122 * mm],
            style=[
                ("FONTNAME", (0, 0), (-1, -1), font_name),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ],
        ),
        Spacer(1, 8),
        Paragraph("4. Источники уязвимостей", h1),
        bullets(
            [
                "NVD CVE 2.0 загружается как bulk feeds за годы с 2002 по текущий год, плюс recent и modified;",
                "CISA KEV загружается как полный JSON-каталог;",
                "ФСТЭК БДУ проверяется по всем применимым объектам документа; глобальный bulk mirror ФСТЭК не заявляется без официального export-файла;",
            ]
        ),
        Paragraph("5. Offline-режим", h1),
        Paragraph(
            "Offline-режим использует уже загруженные snapshots и локальные правила. Если snapshots отсутствуют, "
            "объекты будут отмечены как недостаточно данных по внешним источникам.",
            body,
        ),
        Paragraph("6. Обновление базы из исходников", h1),
        Paragraph("В PowerShell из папки проекта:", body),
        Paragraph("python scripts/update_vulnerability_database.py --output outputs\\vulnerability-database", small),
        Paragraph("Скрипт показывает progress bar скачивания по байтам, переиспользует валидные snapshots и перекачивает частичные файлы.", body),
        Paragraph("7. Сборка release ZIP", h1),
        Paragraph("python scripts/build_release_package.py --output outputs\\release\\IBAuditWorkstation_release.zip", small),
        Paragraph("8. Лицензия", h1),
        Paragraph("Проект распространяется по лицензии MIT. Правообладатель: Абдрахманов Амаль Даулетович.", body),
        Paragraph("9. Ограничения", h1),
        bullets(
            [
                "программа не гарантирует нахождение неизвестных уязвимостей;",
                "качество CVE-сопоставления зависит от названий продуктов и версий;",
                "часть Windows-данных требует запуска от администратора;",
                "outputs может содержать чувствительную информацию и не должен публиковаться в GitHub;",
            ]
        ),
    ]
    doc.build(story)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Russian PDF user guide.")
    parser.add_argument("--output", default="outputs/release/IBAuditWorkstation_UserGuide_RU.pdf")
    args = parser.parse_args()
    path = build_pdf(args.output)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
