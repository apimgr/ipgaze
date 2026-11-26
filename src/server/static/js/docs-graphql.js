// Mount the pinned GraphiQL application on its documentation page.
document.addEventListener('DOMContentLoaded', function() {
  const container = document.getElementById('graphiql');
  if (!container || !window.React || !window.ReactDOM || !window.GraphiQL) { return; }
  const GraphiQL = window.GraphiQL.GraphiQL || window.GraphiQL.default || window.GraphiQL;

  const endpoint = container.dataset.endpoint || '/api/v1/server/graphql';
  const query = `query {
  health {
    status
    version
  }
  myIP {
    ip
    country
    city
    asn
  }
}`;
  const fetcher = function(params) {
    return fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(params)
    }).then(function(response) {
      return response.json();
    });
  };
  const root = window.ReactDOM.createRoot(container);
  const render = function() {
    const theme = document.documentElement.classList.contains('theme-light') ? 'light' :
      document.documentElement.classList.contains('theme-auto') ? 'system' : 'dark';
    root.render(window.React.createElement(GraphiQL, {
      defaultQuery: query,
      fetcher: fetcher,
      forcedTheme: theme
    }));
  };

  render();
  new MutationObserver(render).observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['class']
  });
});
