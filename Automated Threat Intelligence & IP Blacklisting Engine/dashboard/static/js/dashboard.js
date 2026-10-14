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

  // ── 4. Interactive SOC Actions: Whitelist & Unblock ─────────────────
  window.handleSocAction = async function(ip, action) {
    const actionLabel = action === "whitelist" ? "Whitelist & Mark False Positive" : "Unblock";
    const defaultReason = action === "whitelist" ? "False positive reported by analyst" : "Analyst early unblock";
    const reason = prompt(`Enter justification for ${actionLabel} on ${ip}:`, defaultReason);
    if (reason === null) return; // user cancelled

    try {
      const response = await fetch(`/api/indicators/${encodeURIComponent(ip)}/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: reason || defaultReason, analyst: "SOC Analyst" }),
      });
      const data = await response.json();
      if (data.success) {
        showToast(data.message, "success");
        // Update DOM row state dynamically
        const row = document.querySelector(`tr[data-ip="${ip}"]`);
        if (row) {
          const statusCell = row.querySelector(".enforcement-cell");
          if (statusCell) {
            const badgeColor = action === "whitelist" ? "#3B82F6" : "#6B7280";
            statusCell.innerHTML = `<span class="enforce-dot" style="background: ${badgeColor};"></span><span style="font-size: 11px; color: ${badgeColor}; font-family: var(--font-mono);">${action.toUpperCase()}</span>`;
          }
          const actionsCell = row.querySelector(".actions-cell");
          if (actionsCell) {
            actionsCell.innerHTML = `<span style="font-size: 11px; color: var(--text-dim); font-family: var(--font-mono);">Resolved</span>`;
          }
        }
      } else {
        showToast(data.error || "Action failed", "error");
      }
    } catch (err) {
      showToast("Network error: " + err.message, "error");
    }
  };

  function showToast(message, type = "info") {
    let toast = document.getElementById("soc-toast");
    if (!toast) {
      toast = document.createElement("div");
      toast.id = "soc-toast";
      toast.style.position = "fixed";
      toast.style.bottom = "24px";
      toast.style.right = "24px";
      toast.style.padding = "12px 20px";
      toast.style.borderRadius = "8px";
      toast.style.fontFamily = "var(--font-mono, monospace)";
      toast.style.fontSize = "12px";
      toast.style.zIndex = "9999";
      toast.style.boxShadow = "0 8px 24px rgba(0,0,0,0.5)";
      toast.style.transition = "opacity 0.3s ease";
      document.body.appendChild(toast);
    }
    toast.style.background = type === "success" ? "#064e3b" : "#7f1d1d";
    toast.style.color = type === "success" ? "#34d399" : "#f87171";
    toast.style.border = `1px solid ${type === "success" ? "#059669" : "#dc2626"}`;
    toast.textContent = message;
    toast.style.opacity = "1";
    setTimeout(() => { toast.style.opacity = "0"; }, 3500);
  }
});
