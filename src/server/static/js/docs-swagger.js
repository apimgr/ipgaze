// Initialize Swagger UI only on its documentation page.
document.addEventListener('DOMContentLoaded', function() {
  const el = document.getElementById('swagger-ui');
  if (!el || typeof SwaggerUIBundle === 'undefined') { return; }
  SwaggerUIBundle({
    url: el.dataset.specUrl,
    dom_id: '#swagger-ui',
    deepLinking: true,
    presets: [
      SwaggerUIBundle.presets.apis,
      SwaggerUIBundle.SwaggerUIStandalonePreset
    ]
  });
});
