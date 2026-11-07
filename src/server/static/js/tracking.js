(function () {
  'use strict';

  var loader = document.currentScript;
  if (!loader) return;

  var provider = loader.dataset.provider || '';
  var id = loader.dataset.id || '';
  var configURL = loader.dataset.url || '';
  var sourceURL = loader.dataset.sourceUrl || '';
  var source;
  try {
    source = new URL(sourceURL, window.location.href);
  } catch (error) {
    return;
  }

  if (source.protocol !== 'https:' && source.origin !== window.location.origin) return;
  if (window.location.hostname.toLowerCase().endsWith('.onion') && source.origin !== window.location.origin) return;

  function appendScript(url, attributes) {
    var parsed;
    try {
      parsed = new URL(url, window.location.href);
    } catch (error) {
      return;
    }
    if (parsed.protocol !== 'https:' && parsed.origin !== window.location.origin) return;
    if (window.location.hostname.toLowerCase().endsWith('.onion') && parsed.origin !== window.location.origin) return;
    var script = document.createElement('script');
    script.async = true;
    script.src = parsed.href;
    Object.keys(attributes || {}).forEach(function (name) {
      script.setAttribute(name, attributes[name]);
    });
    document.head.appendChild(script);
  }

  switch (provider) {
    case 'google':
      if (id.indexOf('G-') === 0) {
        window.dataLayer = window.dataLayer || [];
        window.gtag = window.gtag || function () { window.dataLayer.push(arguments); };
        window.gtag('js', new Date());
        window.gtag('config', id);
        appendScript(source.href + (source.search ? '&' : '?') + 'id=' + encodeURIComponent(id));
      } else {
        window.ga = window.ga || function () { (window.ga.q = window.ga.q || []).push(arguments); };
        window.ga.l = window.ga.l || Date.now();
        window.ga('create', id, 'auto');
        window.ga('send', 'pageview');
        appendScript(source.href);
      }
      break;
    case 'matomo':
    case 'piwik':
      window._paq = window._paq || [];
      window._paq.push(['trackPageView']);
      window._paq.push(['enableLinkTracking']);
      window._paq.push(['setTrackerUrl', configURL.replace(/\/$/, '') + '/matomo.php']);
      window._paq.push(['setSiteId', id]);
      appendScript(source.href);
      break;
    case 'owa':
      window.owa_baseUrl = configURL.replace(/\/$/, '') + '/';
      window.owa_cmds = window.owa_cmds || [];
      window.owa_cmds.push(['setSiteId', id]);
      window.owa_cmds.push(['trackPageView']);
      window.owa_cmds.push(['trackClicks']);
      appendScript(source.href);
      break;
    case 'fathom':
      appendScript(source.href, { 'data-site': id });
      break;
    case 'plausible':
      appendScript(source.href, { 'data-domain': id });
      break;
    case 'umami':
      appendScript(source.href, { 'data-website-id': id });
      break;
    case 'simple':
      appendScript(source.href);
      break;
    case 'cloudflare':
      appendScript(source.href, { 'data-cf-beacon': JSON.stringify({ token: id }) });
      break;
    default:
      break;
  }
}());
