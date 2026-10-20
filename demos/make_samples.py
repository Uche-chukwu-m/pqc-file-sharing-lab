"""Write the fictional sample files used by the demos (one per category).

    python -m demos.make_samples

Every file is invented. Never put real medical, legal, personal or financial data here.
The Week 4 size experiment needs a larger generator with realistic sizes; this is
only the demo set.
"""

from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "samples"

# The invoice is laid out so "Amount: $100.00" is exactly the second 16-byte AES
# block (bytes 16-31). The Version A bit-flip demo edits it through block 1.
INVOICE = (
    "FAKE INVOICE 01\n"   # bytes 0-15  (block 0)
    "Amount: $100.00\n"   # bytes 16-31 (block 1)
    "Payee: Harbor Point Services (fictional)\n"
    "Client: Jordan Example (fictional)\n"
    "Due: 2026-12-01\n"
    "FICTIONAL DATA - CLASSROOM DEMO ONLY\n"
)

SAMPLES = {
    "financial_invoice.txt": INVOICE,
    "medical_lab_report.txt": (
        "FICTIONAL LAB REPORT - CLASSROOM DEMO ONLY\n"
        "Patient: Sam Placeholder (fictional)\n"
        "Test: Complete blood count\n"
        "Hemoglobin: 13.9 g/dL (reference 12.0-17.5)\n"
        "White cells: 6.1 x10^9/L (reference 4.0-11.0)\n"
        "Comment: All values within reference range.\n"
    ),
    "legal_case_note.txt": (
        "FICTIONAL CASE NOTE - CLASSROOM DEMO ONLY\n"
        "Matter: Example v. Placeholder (invented)\n"
        "Privileged and confidential (simulation)\n"
        "Summary: Client wishes to settle before the hearing on 2026-11-20.\n"
        "Next step: Draft settlement letter for review.\n"
    ),
    "personal_family_message.txt": (
        "FICTIONAL PERSONAL MESSAGE - CLASSROOM DEMO ONLY\n"
        "Hi Alex, the spare key is under the blue plant pot.\n"
        "Grandma's birthday dinner is Saturday at 6pm.\n"
        "- Riley (fictional)\n"
    ),
}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, text in SAMPLES.items():
        (OUT / name).write_text(text)
        print(f"wrote {OUT / name} ({len(text.encode())} B)")


if __name__ == "__main__":
    main()
