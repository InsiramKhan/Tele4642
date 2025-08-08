// Utility: Get query param by key
function getQueryParam(key) {
  const urlParams = new URLSearchParams(window.location.search);
  return urlParams.get(key);
}

// Search bar handler (used in index.html and results.html)
function goSearch(event) {
  event.preventDefault();
  const input = document.getElementById("search-input").value.trim();
  if (input !== "") {
    window.location.href = `results.html?q=${encodeURIComponent(input)}`;
  }
  return false;
}

// Auto-fill the query in the results page
function populateSearchBar() {
  const q = getQueryParam("q");
  if (q && document.getElementById("search-input")) {
    document.getElementById("search-input").value = q;
  }
}

// Optional: Highlight keyword matches in result titles/snippets
function highlightMatches() {
  const query = getQueryParam("q");
  if (!query) return;

  const terms = query.toLowerCase().split(" ");
  const results = document.querySelectorAll(".result");

  results.forEach(result => {
    ["a", "p"].forEach(tag => {
      const element = result.querySelector(tag);
      if (!element) return;

      let text = element.textContent;
      terms.forEach(term => {
        const regex = new RegExp(`(${term})`, "gi");
        text = text.replace(regex, `<mark>$1</mark>`);
      });
      element.innerHTML = text;
    });
  });
}


