# Compact Inventory Risk Links Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace verbose risk details below inventory objects with compact CVE/BDU links that open the matching computer and scroll to the exact risk card.

**Architecture:** `BatchHtmlReportBuilder` will assign a unique stable anchor to every per-computer risk card while rendering it. The same `(RuleResult, anchor)` pairs will be grouped by `object_uid` and rendered below the corresponding inventory table as compact links. A focused JavaScript handler will reuse the existing document-opening behavior, scroll to the exact card, update the hash, and apply a temporary highlight.

**Tech Stack:** Python 3 standard library, `unittest`, autonomous HTML/CSS/JavaScript, PyInstaller.

---

## File map

- Modify `src/ib_audit/batch_report.py`: generate finding anchors, render compact links, navigate and highlight targets.
- Modify `tests/test_batch_report.py`: cover exact links, duplicate risk identifiers, missing risks, JavaScript navigation, and CSS containment.
- Create `outputs/verification/compact-inventory-risk-links.html`: generated visual verification fixture; do not commit.

### Task 1: Unique risk-card anchors and compact object links

**Files:**
- Modify: `tests/test_batch_report.py`
- Modify: `src/ib_audit/batch_report.py`

- [ ] **Step 1: Write the failing compact-link test**

Replace `test_inventory_object_with_risk_shows_specific_risk_below_fields` with:

```python
def test_inventory_object_risk_is_a_compact_link_to_exact_finding(self):
    result = make_result("PC-A", "critical")
    batch = BatchAssessment.create(
        [Path("PC-A.html")],
        [result],
        [],
        "completed",
    )
    anchor = BatchHtmlReportBuilder._document_anchor(result)

    rendered = BatchHtmlReportBuilder().render(batch)
    object_card = rendered.split("class='object-card'", 1)[1].split("</article>", 1)[0]

    self.assertIn("class='object-risk-links'", object_card)
    self.assertIn("CVE-2099-0001", object_card)
    self.assertIn(f"href='#{anchor}-finding-cve-2099-0001-1'", object_card)
    self.assertIn(
        f"onclick=\"return openComputerFinding('{anchor}',"
        f"'{anchor}-finding-cve-2099-0001-1')\"",
        object_card,
    )
    self.assertNotIn("Example Tool 1.0", object_card)
    self.assertIn(
        f"id='{anchor}-finding-cve-2099-0001-1' class='host-finding critical'",
        rendered,
    )
```

- [ ] **Step 2: Run the focused test and confirm RED**

Run:

```powershell
python -m unittest tests.test_batch_report.BatchHtmlReportBuilderTests.test_inventory_object_risk_is_a_compact_link_to_exact_finding
```

Expected: `FAIL` because `object-risk-links`, the target anchor, and `openComputerFinding` do not exist.

- [ ] **Step 3: Add unique finding anchors and grouped targets**

In `_document_section`, replace the existing `risks_by_object` and
`findings_html` construction with:

```python
finding_entries = [
    (result, self._finding_anchor(anchor, result.rule_id, index))
    for index, result in enumerate(findings, 1)
]
risks_by_object: dict[str, list] = defaultdict(list)
for result, target_id in finding_entries:
    risks_by_object[result.object_uid].append((result, target_id))
findings_html = "".join(
    f"<article id='{target_id}' class='host-finding "
    f"{html.escape(result.severity.casefold())}'>"
    f"<span class='severity {html.escape(result.severity.casefold())}'>"
    f"{html.escape(self._severity_label(result.severity))}</span>"
    f"<h4>{html.escape(result.rule_id)} · {html.escape(result.title)}</h4>"
    f"<p>{html.escape(result.evidence)}</p>"
    f"<p><strong>Рекомендация:</strong> {html.escape(result.remediation)}</p>"
    f"{self._reference_links(result.references)}"
    "</article>"
    for result, target_id in finding_entries
) or "<p class='empty'>Подтверждённые риски не найдены.</p>"
```

Add next to `_document_anchor`:

```python
@staticmethod
def _finding_anchor(document_anchor: str, rule_id: str, index: int) -> str:
    slug = "".join(
        char if char.isalnum() else "-"
        for char in str(rule_id).casefold()
    ).strip("-")
    return f"{document_anchor}-finding-{slug or 'risk'}-{index}"
```

- [ ] **Step 4: Replace verbose object details with compact links**

Replace `_object_risk_details` with:

```python
def _object_risk_links(self, document_anchor: str, results: list) -> str:
    if not results:
        return ""
    links = []
    for result, target_id in sorted(
        results,
        key=lambda item: (
            SEVERITY_ORDER.get(
                str(item[0].severity).casefold(),
                SEVERITY_ORDER["info"],
            ),
            str(item[0].rule_id).casefold(),
            item[1],
        ),
    ):
        severity = str(result.severity).casefold()
        links.append(
            f"<a class='object-risk-link {html.escape(severity)}' "
            f"href='#{html.escape(target_id, quote=True)}' "
            f"onclick=\"return openComputerFinding('{document_anchor}',"
            f"'{target_id}')\">{html.escape(result.rule_id)}</a>"
        )
    return (
        "<div class='object-risk-links'><strong>Риски:</strong>"
        + "".join(links)
        + "</div>"
    )
```

Change `_inventory_category` to call:

```python
risk_links = self._object_risk_links(
    self._document_anchor(document),
    risks_by_object.get(obj.uid, []),
)
```

and append `risk_links` after the inventory table.

- [ ] **Step 5: Run the focused test and confirm GREEN**

Run the command from Step 2.

Expected: `OK`.

### Task 2: Duplicate identifiers and objects without risks

**Files:**
- Modify: `tests/test_batch_report.py`
- Modify: `src/ib_audit/batch_report.py` only if the tests reveal a defect.

- [ ] **Step 1: Add regression tests**

Add `import re` and:

```python
def test_duplicate_rule_ids_receive_unique_finding_targets(self):
    result = make_result("PC-A", "critical")
    original = result.assessment.rule_results[0]
    result.assessment.rule_results.append(
        RuleResult(
            original.object_uid,
            original.rule_id,
            original.rule_version,
            original.kind,
            original.status,
            original.severity,
            "Вторая уязвимость",
            original.actual,
            original.expected,
            "Второе подтверждение",
            original.confidence,
            original.remediation,
            original.references,
        )
    )
    batch = BatchAssessment.create([Path("PC-A.html")], [result], [], "completed")

    rendered = BatchHtmlReportBuilder().render(batch)
    targets = re.findall(
        r"id='([^']+-finding-cve-2099-0001-\\d+)' class='host-finding",
        rendered,
    )

    self.assertEqual(2, len(targets))
    self.assertEqual(2, len(set(targets)))
    for target in targets:
        self.assertIn(f"href='#{target}'", rendered)

def test_inventory_object_without_risk_has_no_risk_link_row(self):
    result = make_result("PC-A")
    result.assessment.rule_results.clear()
    batch = BatchAssessment.create([Path("PC-A.html")], [result], [], "completed")

    rendered = BatchHtmlReportBuilder().render(batch)
    object_card = rendered.split("class='object-card'", 1)[1].split("</article>", 1)[0]

    self.assertNotIn("object-risk-links", object_card)
```

- [ ] **Step 2: Run both tests**

Run:

```powershell
python -m unittest tests.test_batch_report.BatchHtmlReportBuilderTests.test_duplicate_rule_ids_receive_unique_finding_targets tests.test_batch_report.BatchHtmlReportBuilderTests.test_inventory_object_without_risk_has_no_risk_link_row
```

Expected: both tests pass. If either fails, change only anchor generation or empty-list rendering and rerun until `OK`.

- [ ] **Step 3: Commit the data-linking change**

```powershell
git add -- src/ib_audit/batch_report.py tests/test_batch_report.py
git commit -m "feat: link inventory risks to exact findings"
```

### Task 3: Browser navigation, highlighting, and compact CSS

**Files:**
- Modify: `tests/test_batch_report.py`
- Modify: `src/ib_audit/batch_report.py`

- [ ] **Step 1: Write the failing navigation and CSS test**

Add:

```python
def test_exact_risk_navigation_opens_host_and_highlights_target(self):
    rendered = BatchHtmlReportBuilder().render(
        BatchAssessment.create(
            [Path("PC-A.html")],
            [make_result("PC-A", "critical")],
            [],
            "completed",
        )
    )

    self.assertIn("function openComputerFinding(anchor,targetId)", rendered)
    self.assertIn("node.classList.add('risk-target')", rendered)
    self.assertIn("node.closest('.document-section')", rendered)
    self.assertIn(".object-risk-links{display:flex", rendered)
    self.assertIn("flex-wrap:wrap", rendered)
    self.assertIn(".host-finding.risk-target", rendered)
```

- [ ] **Step 2: Run the focused test and confirm RED**

```powershell
python -m unittest tests.test_batch_report.BatchHtmlReportBuilderTests.test_exact_risk_navigation_opens_host_and_highlights_target
```

Expected: `FAIL` because the JavaScript handler and compact CSS do not exist.

- [ ] **Step 3: Add compact styles**

Replace the verbose `.object-risk-list` and `.object-risk-item` rules with:

```css
.object-card{margin:10px;border:1px solid #e5eaed;border-radius:8px;padding:12px}
.object-risk-links{display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-top:9px;border-top:1px solid #e5eaed;padding-top:9px;min-width:0}
.object-risk-links>strong{color:var(--red);font-size:12px;margin-right:2px}
.object-risk-link{display:inline-block;max-width:100%;border-radius:999px;padding:3px 8px;background:#e2e8f0;color:#475569;font-size:12px;font-weight:700;text-decoration:none;overflow-wrap:anywhere}
.object-risk-link.critical{background:#fee2e2;color:#991b1b}
.object-risk-link.high{background:#ffedd5;color:#9a3412}
.object-risk-link.medium{background:#dbeafe;color:#1d4ed8}
.object-risk-link:hover{outline:2px solid currentColor;outline-offset:1px}
.host-finding.risk-target{outline:3px solid var(--teal);outline-offset:3px;background:#ecfdf5}
```

- [ ] **Step 4: Add exact-target navigation**

Insert after `openComputerSection`:

```javascript
function openComputerFinding(anchor,targetId){
  var section=document.getElementById(anchor);
  if(!section){return true;}
  var details=section.querySelector('details');
  if(details){details.open=true;}
  var node=document.getElementById(targetId)||document.getElementById(anchor+'-risks')||section;
  document.querySelectorAll('.host-finding.risk-target').forEach(function(item){
    item.classList.remove('risk-target');
  });
  if(node.classList&&node.classList.contains('host-finding')){
    node.classList.add('risk-target');
    window.setTimeout(function(){node.classList.remove('risk-target');},2200);
  }
  node.scrollIntoView({behavior:'smooth',block:'center'});
  if(window.history&&window.history.replaceState){
    window.history.replaceState(null,'','#'+targetId);
  }
  return false;
}
```

Update `openSectionForHash` so exact target hashes open their parent document:

```javascript
function openSectionForHash(){
  var hash=(window.location.hash||'').replace(/^#/,'');
  if(!hash){return;}
  var node=document.getElementById(hash);
  var section=node&&node.closest?node.closest('.document-section'):null;
  if(!section){
    var anchor=hash.replace(/-(risks|inventory|diagnostics)$/,'');
    section=document.getElementById(anchor);
  }
  if(section&&section.classList.contains('document-section')){
    var details=section.querySelector('details');
    if(details){details.open=true;}
  }
}
```

- [ ] **Step 5: Run the focused and complete batch-report tests**

```powershell
python -m unittest tests.test_batch_report
```

Expected: all batch-report tests pass with `OK`.

- [ ] **Step 6: Commit navigation and styling**

```powershell
git add -- src/ib_audit/batch_report.py tests/test_batch_report.py
git commit -m "feat: navigate from inventory to exact risks"
```

### Task 4: Full verification, visual inspection, packaging, and publication

**Files:**
- Generate: `outputs/verification/compact-inventory-risk-links.html`
- Generate: packaged EXE and release ZIP using the existing project build process.

- [ ] **Step 1: Run the full automated suite**

```powershell
python -m unittest discover -s tests
```

Expected: all tests pass, zero failures and errors.

- [ ] **Step 2: Compile all Python modules**

```powershell
python -m compileall -q src scripts tests run_app.py run_audit.py
```

Expected: exit code `0`, no output.

- [ ] **Step 3: Generate a demonstration report**

Use `make_result`-equivalent fixture data with at least three risks on one object
and call:

```python
BatchHtmlReportBuilder().build(
    Path("outputs/verification"),
    BatchAssessment.create(
        [Path("PC-A.html")],
        [result],
        [],
        "completed",
    ),
)
```

Expected: an autonomous HTML file appears under `outputs/verification`.

- [ ] **Step 4: Inspect the report in the in-app browser**

Open the generated `file:///.../compact-inventory-risk-links.html`, expand the
computer and inventory category, and verify:

- links stay inside the object card and wrap;
- clicking each identifier opens the correct computer;
- the browser scrolls to the matching risk card;
- the target receives temporary teal highlighting.

- [ ] **Step 5: Rebuild the Windows executable and release archive**

Run the repository's current PyInstaller packaging command, copy the verified
EXE to `C:\Users\impal\Downloads\IBAuditWorkstation\IBAuditWorkstation.exe`,
and produce a dated ZIP under `outputs/release`.

Expected: PyInstaller exits `0`; the EXE launches, remains responsive, and the
ZIP contains the rebuilt executable.

- [ ] **Step 6: Verify repository scope and publish**

```powershell
git status --short
git log -3 --oneline
git push origin main
git rev-parse HEAD
git rev-parse origin/main
```

Expected: only the pre-existing user changes to
`docs/IBAuditWorkstation_UserGuide_RU.pdf` and
`scripts/build_user_guide_pdf.py` remain unstaged; local and remote hashes match.
