/**
 * dashboard/static/js/dashboard.js
 * Interactive features: instant search, column sorting, and copy utilities.
 */

document.addEventListener("DOMContentLoaded", () => {
  // ── 1. Search Filter ────────────────────────────────────────────────
  const searchInput = document.getElementById("search-input");
  const tableRows = document.querySelectorAll(".indicators-table tbody tr");

  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      const query = e.target.value.toLowerCase().trim();
      tableRows.forEach((row) => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(query) ? "" : "none";
      });
    });
  }

  // ── 2. Copy IP to Clipboard ────────────────────────────────────────
  document.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      const ip = btn.getAttribute("data-ip");
      if (ip) {
        navigator.clipboard.writeText(ip).then(() => {
          const original = btn.textContent;
          btn.textContent = "✓";
          btn.style.color = "#10B981";
          setTimeout(() => {
            btn.textContent = original;
            btn.style.color = "";
          }, 1200);
        });
      }
    });
  });

  // ── 3. Table Column Sorting ────────────────────────────────────────
  const headers = document.querySelectorAll(".indicators-table th.sortable");
  headers.forEach((th) => {
    th.addEventListener("click", () => {
      const table = th.closest("table");
      const tbody = table.querySelector("tbody");
      const rows = Array.from(tbody.querySelectorAll("tr"));
      const colIndex = th.cellIndex;
      const isAsc = th.classList.contains("asc");

      // Reset header classes
      headers.forEach((h) => h.classList.remove("asc", "desc"));
      th.classList.toggle("asc", !isAsc);
      th.classList.toggle("desc", isAsc);

      rows.sort((a, b) => {
        const aText = a.cells[colIndex]?.innerText.trim() || "";
        const bText = b.cells[colIndex]?.innerText.trim() || "";

        // Check for numeric values (e.g. score)
        const aNum = parseFloat(aText);
        const bNum = parseFloat(bText);
        if (!isNaN(aNum) && !isNaN(bNum)) {
          return isAsc ? aNum - bNum : bNum - aNum;
        }

        return isAsc ? aText.localeCompare(bText) : bText.localeCompare(aText);
      });

      rows.forEach((row) => tbody.appendChild(row));
    });
  });
});
