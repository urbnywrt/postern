// Adds a copy button after every value of the section "enter manually". The
// page is complete without this script: the values can be selected and copied
// by hand.
(function () {
  "use strict";
  if (!navigator.clipboard || !navigator.clipboard.writeText) {
    return;
  }
  var values = document.querySelectorAll("code[data-copy]");
  for (var i = 0; i < values.length; i++) {
    addButton(values[i]);
  }

  function addButton(value) {
    var button = document.createElement("button");
    button.type = "button";
    button.className = "copy";
    button.textContent = value.getAttribute("data-copy");
    button.addEventListener("click", function () {
      navigator.clipboard.writeText(value.textContent).then(function () {
        button.textContent = value.getAttribute("data-copied");
        setTimeout(function () {
          button.textContent = value.getAttribute("data-copy");
        }, 1500);
      }, function () {
        var range = document.createRange();
        range.selectNodeContents(value);
        var selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
      });
    });
    value.insertAdjacentElement("afterend", button);
  }
})();
