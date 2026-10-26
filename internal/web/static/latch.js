// Latch: closes the account menu when you click outside it or press
// Escape. The menu is a <details> element, so it works without this.
(function () {
  "use strict";
  var menu = document.querySelector(".account-menu");
  if (!menu) {
    return;
  }
  document.addEventListener("click", function (event) {
    if (menu.open && !menu.contains(event.target)) {
      menu.open = false;
    }
  });
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && menu.open) {
      menu.open = false;
      menu.querySelector("summary").focus();
    }
  });
})();
