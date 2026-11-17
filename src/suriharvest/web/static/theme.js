// suriharvest: set the colour theme before the first paint (loaded in <head>, no inline script under the CSP).
(function () {
  "use strict";
  var root = document.documentElement;
  try {
    var saved = localStorage.getItem("suriharvest-theme");
    if (saved === "light" || saved === "dark") root.setAttribute("data-theme", saved);
  } catch (e) { /* storage blocked: follow the system theme */ }
  root.classList.add("js");
})();
