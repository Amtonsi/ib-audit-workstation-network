# PDF User Usage Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add exactly one step-by-step usage page to the existing Russian PDF guide without changing its established visual design or removing existing content.

**Architecture:** The ReportLab generator will render a new page after the application-shell overview. The page will use the existing card, typography, palette, header, footer, and wrapping helpers; later page footer numbers will shift by one. A source-level regression test will lock the required eight actions and the re-generation warning, while PDF extraction and rendered PNG inspection will verify the generated artifact.

**Tech Stack:** Python 3, ReportLab, `unittest`, pypdf/pdfplumber, Poppler or the bundled PDF renderer.

---

## File map

- Modify `tests/test_user_guide_pdf.py`: assert the new page contains all required user actions.
- Modify `scripts/build_user_guide_pdf.py`: draw one usage page and increment later page numbers.
- Regenerate `docs/IBAuditWorkstation_UserGuide_RU.pdf`: final user-facing guide.
- Generate `tmp/pdfs/ib-audit-guide-page-*.png`: temporary visual QA images; do not commit.

### Task 1: Lock the usage-page content

**Files:**
- Modify: `tests/test_user_guide_pdf.py`

- [ ] **Step 1: Write the failing test**

Add:

```python
def test_usage_page_contains_complete_operator_workflow(self) -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "scripts" / "build_user_guide_pdf.py").read_text(
        encoding="utf-8"
    )
    usage_page = source.split("# Page 4 - usage instructions", 1)[1].split(
        "# Page 5 - logic pipeline", 1
    )[0]

    expected = (
        "Запустить от администратора",
        "Выбрать папку отчётов",
        "Обновить базы",
        "Выбрать режим",
        "Запустить проверку",
        "Следить или отменить",
        "Открыть результат",
        "Перейти к риску",
        "Старые HTML-файлы не изменяются автоматически",
    )
    for text in expected:
        self.assertIn(text, usage_page)
```

- [ ] **Step 2: Run the focused test and confirm RED**

```powershell
python -m unittest tests.test_user_guide_pdf.UserGuidePdfTests.test_usage_page_contains_complete_operator_workflow
```

Expected: `ERROR` or `FAIL` because the `# Page 4 - usage instructions` section does not exist.

### Task 2: Draw the new instruction page

**Files:**
- Modify: `scripts/build_user_guide_pdf.py`

- [ ] **Step 1: Add the ReportLab page after the UI page**

Insert after the current page 3 `c.showPage()`:

```python
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
        "HTML-отчёты» позволяет выбрать несколько документов и получить один "
        "сводный HTML.",
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
        "компактную ссылку CVE/БДУ под объектом для перехода к точной карточке "
        "риска.",
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
```

- [ ] **Step 2: Renumber only later page footers and comments**

Change:

```python
# Page 4 - logic pipeline
section_header("3. Логика обработки данных", 4)
```

to:

```python
# Page 5 - logic pipeline
section_header("3. Логика обработки данных", 5)
```

Apply the same one-page increment to the later page comments and the numeric
argument passed to `section_header`, ending with:

```python
# Page 9 - commands and build
section_header("7. Команды сборки и проверки", 9)
```

Do not change their section titles or body content.

- [ ] **Step 3: Run the focused test and confirm GREEN**

```powershell
python -m unittest tests.test_user_guide_pdf
```

Expected: two tests pass with `OK`.

- [ ] **Step 4: Commit the generator and test**

```powershell
git add -- scripts/build_user_guide_pdf.py tests/test_user_guide_pdf.py
git commit -m "docs: add PDF usage instruction page"
```

### Task 3: Generate and verify the PDF artifact

**Files:**
- Regenerate: `docs/IBAuditWorkstation_UserGuide_RU.pdf`
- Generate: `tmp/pdfs/ib-audit-guide-page-*.png`

- [ ] **Step 1: Build the PDF with the bundled document runtime**

```powershell
& 'C:\Users\impal\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' `
  scripts\build_user_guide_pdf.py `
  --output docs\IBAuditWorkstation_UserGuide_RU.pdf
```

Expected: the command prints `docs\IBAuditWorkstation_UserGuide_RU.pdf` and exits
with code `0`.

- [ ] **Step 2: Verify page count and required text**

Use the bundled Python runtime:

```python
from pypdf import PdfReader

reader = PdfReader("docs/IBAuditWorkstation_UserGuide_RU.pdf")
assert len(reader.pages) == 9
text = "\n".join(page.extract_text() or "" for page in reader.pages)
for value in (
    "Как пользоваться",
    "Запустить от администратора",
    "Выбрать папку отчётов",
    "Перейти к риску",
    "Старые HTML-файлы не изменяются автоматически",
):
    assert value in text
```

Expected: `pages=9`, all required text is found.

- [ ] **Step 3: Render all PDF pages to PNG**

Create `tmp/pdfs/`, then use the available Poppler `pdftoppm` executable. If
Poppler is unavailable, use the bundled PDF rendering helper documented by the
workspace runtime.

Expected: nine numbered PNG files are created.

- [ ] **Step 4: Inspect the new and adjacent pages**

Visually inspect pages 3, 4, and 5 first, then review the remaining page
thumbnails for:

- no text overlap or clipping;
- readable Russian glyphs;
- consistent page headers and footers;
- correct two-column card alignment;
- no changes to existing illustrations.

- [ ] **Step 5: Run the complete repository test suite**

```powershell
python -m unittest discover -s tests
python -m compileall -q src scripts tests run_app.py run_audit.py
```

Expected: all tests pass and compilation exits `0`.

- [ ] **Step 6: Commit and publish the regenerated PDF**

```powershell
git add -- docs/IBAuditWorkstation_UserGuide_RU.pdf
git commit -m "docs: rebuild PDF user guide"
git push origin main
git rev-parse HEAD
git rev-parse origin/main
```

Expected: local and remote hashes match. The only remaining worktree changes are
unrelated files, if any.
