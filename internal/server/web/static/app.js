// Inventory UI helpers. No inline scripts (CSP).
(function () {
  "use strict";
  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-confirm]");
    if (btn && !window.confirm(btn.getAttribute("data-confirm"))) {
      e.preventDefault();
      e.stopPropagation();
      return;
    }
    var copy = e.target.closest("[data-copy]");
    if (copy) {
      var input = copy.parentElement.querySelector("input");
      input.select();
      var done = function () { copy.textContent = "Copied"; setTimeout(function () { copy.textContent = "Copy"; }, 1500); };
      if (navigator.clipboard) { navigator.clipboard.writeText(input.value).then(done, function () { document.execCommand("copy"); done(); }); }
      else { document.execCommand("copy"); done(); }
    }
  }, true);

  document.addEventListener("change", function (e) {
    var t = e.target;
    if (t.hasAttribute("data-autosubmit")) { t.form.submit(); }
    if (t.hasAttribute("data-selectall")) {
      var name = t.getAttribute("data-selectall");
      document.querySelectorAll('input[type=checkbox][name="' + name + '"]').forEach(function (cb) {
        if (cb.closest("tr").style.display !== "none") cb.checked = t.checked;
      });
    }
    if (t.hasAttribute("data-toggle-class")) {
      var target = document.querySelector(t.getAttribute("data-target"));
      if (target) target.classList.toggle(t.getAttribute("data-toggle-class"), t.checked);
    }
  });

  document.addEventListener("input", function (e) {
    var t = e.target;
    if (!t.hasAttribute("data-filter")) return;
    var q = t.value.toLowerCase().trim();
    var table = document.querySelector(t.getAttribute("data-filter"));
    if (!table) return;
    table.querySelectorAll("tbody tr").forEach(function (tr) {
      tr.style.display = !q || tr.textContent.toLowerCase().indexOf(q) >= 0 ? "" : "none";
    });
  });
})();
