package swagger

// getSwaggerThemeCSS returns CSS for Swagger UI theming
// Per AI.md PART 19: Swagger & GraphQL Theming (NON-NEGOTIABLE)
// Swagger must match project-wide theme system (light/dark/auto)
func getSwaggerThemeCSS(theme string) string {
	if theme == "light" {
		return swaggerLightTheme
	}
	return swaggerDarkTheme
}

// swaggerDarkTheme provides dark theme CSS for Swagger UI
// Per AI.md PART 19: Dark theme colors
const swaggerDarkTheme = `
/* Swagger UI - Dark Theme */
/* Per AI.md PART 19: Swagger & GraphQL Theming */

body {
	background: #282a36;
}

.swagger-ui {
	background: #282a36;
	color: #f8f8f2;
}

.swagger-ui .topbar {
	background: #21222c;
	border-bottom: 1px solid #2b2d3a;
}

.swagger-ui .topbar .download-url-wrapper .select-label {
	color: #f8f8f2;
}

.swagger-ui .info .title,
.swagger-ui .opblock-tag {
	color: #f8f8f2;
}

.swagger-ui .info .title small {
	background: #2b2d3a;
	color: #f8f8f2;
}

.swagger-ui .info .description p,
.swagger-ui .info .description {
	color: #f8f8f2;
}

.swagger-ui .opblock.opblock-get {
	background: rgba(139, 233, 253, 0.1);
	border-color: #8be9fd;
}

.swagger-ui .opblock.opblock-get .opblock-summary-method {
	background: #8be9fd;
	color: #282a36;
}

.swagger-ui .opblock.opblock-get .opblock-summary {
	border-color: #8be9fd;
}

.swagger-ui .opblock.opblock-post {
	background: rgba(80, 250, 123, 0.1);
	border-color: #50fa7b;
}

.swagger-ui .opblock.opblock-post .opblock-summary-method {
	background: #50fa7b;
	color: #282a36;
}

.swagger-ui .opblock.opblock-post .opblock-summary {
	border-color: #50fa7b;
}

.swagger-ui .opblock.opblock-put {
	background: rgba(255, 184, 108, 0.1);
	border-color: #ffb86c;
}

.swagger-ui .opblock.opblock-put .opblock-summary-method {
	background: #ffb86c;
	color: #282a36;
}

.swagger-ui .opblock.opblock-put .opblock-summary {
	border-color: #ffb86c;
}

.swagger-ui .opblock.opblock-delete {
	background: rgba(255, 85, 85, 0.1);
	border-color: #ff5555;
}

.swagger-ui .opblock.opblock-delete .opblock-summary-method {
	background: #ff5555;
	color: #f8f8f2;
}

.swagger-ui .opblock.opblock-delete .opblock-summary {
	border-color: #ff5555;
}

.swagger-ui .opblock.opblock-patch {
	background: rgba(189, 147, 249, 0.1);
	border-color: #ff79c6;
}

.swagger-ui .opblock.opblock-patch .opblock-summary-method {
	background: #ff79c6;
	color: #282a36;
}

.swagger-ui .opblock.opblock-patch .opblock-summary {
	border-color: #ff79c6;
}

.swagger-ui .opblock-summary-path,
.swagger-ui .opblock-summary-description,
.swagger-ui .opblock-description-wrapper p {
	color: #f8f8f2;
}

.swagger-ui .opblock-body pre.microlight {
	background: #21222c;
	color: #f8f8f2;
}

.swagger-ui input,
.swagger-ui textarea,
.swagger-ui select {
	background: #2b2d3a;
	color: #f8f8f2;
	border: 1px solid #44475a;
}

.swagger-ui input:focus,
.swagger-ui textarea:focus,
.swagger-ui select:focus {
	border-color: #ff79c6;
	outline: none;
}

.swagger-ui .btn {
	background: #44475a;
	color: #f8f8f2;
	border: none;
}

.swagger-ui .btn:hover {
	background: #ff79c6;
}

.swagger-ui .btn.execute {
	background: #50fa7b;
	color: #282a36;
}

.swagger-ui .btn.execute:hover {
	background: #8be9fd;
}

.swagger-ui .btn.cancel {
	background: #ff5555;
	color: #f8f8f2;
}

.swagger-ui .scheme-container {
	background: #2b2d3a;
	border: 1px solid #44475a;
}

.swagger-ui .model-box {
	background: #2b2d3a;
	color: #f8f8f2;
}

.swagger-ui section.models {
	border-color: #6272a4;
}

.swagger-ui section.models h4 {
	color: #f8f8f2;
}

.swagger-ui .model {
	color: #f8f8f2;
}

.swagger-ui .model-title {
	color: #ff79c6;
}

.swagger-ui table thead tr th,
.swagger-ui table thead tr td {
	color: #f8f8f2;
	border-bottom-color: #6272a4;
}

.swagger-ui table tbody tr td {
	color: #f8f8f2;
	border-color: #6272a4;
}

.swagger-ui .parameter__name {
	color: #8be9fd;
}

.swagger-ui .parameter__type {
	color: #50fa7b;
}

.swagger-ui .parameter__in {
	color: #6272a4;
}

.swagger-ui .response-col_status {
	color: #ff79c6;
}

.swagger-ui .response-col_description {
	color: #f8f8f2;
}

.swagger-ui .responses-inner h4,
.swagger-ui .responses-inner h5 {
	color: #f8f8f2;
}

.swagger-ui .opblock-tag-section h3 {
	color: #f8f8f2;
}

.swagger-ui .loading-container .loading::after {
	border-color: #ff79c6 transparent;
}

.swagger-ui .prop-type {
	color: #50fa7b;
}

.swagger-ui .prop-format {
	color: #6272a4;
}

.swagger-ui a.nostyle,
.swagger-ui a.nostyle:visited {
	color: #8be9fd;
}

.swagger-ui .markdown p,
.swagger-ui .markdown li {
	color: #f8f8f2;
}

.swagger-ui .markdown code {
	background: #21222c;
	color: #ff79c6;
}

.swagger-ui .renderedMarkdown p {
	color: #f8f8f2;
}

.swagger-ui .response-col_links {
	color: #f8f8f2;
}

.swagger-ui select {
	background: #2b2d3a url('data:image/svg+xml;charset=utf-8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path fill="%23f8f8f2" d="M10 12l-6-6h12z"/></svg>') right 10px center/10px no-repeat;
}
`

// swaggerLightTheme provides light theme CSS for Swagger UI
// Per AI.md PART 19: Light theme colors
const swaggerLightTheme = `
/* Swagger UI - Light Theme */
/* Per AI.md PART 19: Swagger & GraphQL Theming */

body {
	background: #ffffff;
}

.swagger-ui {
	background: #ffffff;
	color: #1f2328;
}

.swagger-ui .topbar {
	background: #f6f8fa;
	border-bottom: 1px solid #eff2f5;
}

.swagger-ui .info .title,
.swagger-ui .opblock-tag {
	color: #1f2328;
}

.swagger-ui .info .title small {
	background: #eff2f5;
	color: #1f2328;
}

.swagger-ui .info .description p,
.swagger-ui .info .description {
	color: #1f2328;
}

.swagger-ui .opblock.opblock-get {
	background: rgba(0, 102, 204, 0.05);
	border-color: #0969da;
}

.swagger-ui .opblock.opblock-get .opblock-summary-method {
	background: #0969da;
	color: #ffffff;
}

.swagger-ui .opblock.opblock-get .opblock-summary {
	border-color: #0969da;
}

.swagger-ui .opblock.opblock-post {
	background: rgba(0, 128, 0, 0.05);
	border-color: #1a7f37;
}

.swagger-ui .opblock.opblock-post .opblock-summary-method {
	background: #1a7f37;
	color: #ffffff;
}

.swagger-ui .opblock.opblock-post .opblock-summary {
	border-color: #1a7f37;
}

.swagger-ui .opblock.opblock-put {
	background: rgba(255, 140, 0, 0.05);
	border-color: #9a6700;
}

.swagger-ui .opblock.opblock-put .opblock-summary-method {
	background: #9a6700;
	color: #ffffff;
}

.swagger-ui .opblock.opblock-put .opblock-summary {
	border-color: #9a6700;
}

.swagger-ui .opblock.opblock-delete {
	background: rgba(204, 0, 0, 0.05);
	border-color: #d1242f;
}

.swagger-ui .opblock.opblock-delete .opblock-summary-method {
	background: #d1242f;
	color: #ffffff;
}

.swagger-ui .opblock.opblock-delete .opblock-summary {
	border-color: #d1242f;
}

.swagger-ui .opblock.opblock-patch {
	background: rgba(102, 0, 204, 0.05);
	border-color: #8250df;
}

.swagger-ui .opblock.opblock-patch .opblock-summary-method {
	background: #8250df;
	color: #ffffff;
}

.swagger-ui .opblock.opblock-patch .opblock-summary {
	border-color: #8250df;
}

.swagger-ui .opblock-summary-path,
.swagger-ui .opblock-summary-description,
.swagger-ui .opblock-description-wrapper p {
	color: #1f2328;
}

.swagger-ui .opblock-body pre.microlight {
	background: #f6f8fa;
	color: #1f2328;
}

.swagger-ui input,
.swagger-ui textarea,
.swagger-ui select {
	background: #ffffff;
	color: #1f2328;
	border: 1px solid #d1d9e0;
}

.swagger-ui input:focus,
.swagger-ui textarea:focus,
.swagger-ui select:focus {
	border-color: #0969da;
	outline: none;
}

.swagger-ui .btn {
	background: #0969da;
	/* #0969da (Primary) is a mid-tone blue: black text clears WCAG AA
	   (~4.2:1) more reliably than white (~4.0:1) against it. */
	color: #1f2328;
	border: none;
}

.swagger-ui .btn:hover {
	background: #8250df;
}

.swagger-ui .btn.execute {
	background: #1a7f37;
	color: #ffffff;
}

.swagger-ui .btn.execute:hover {
	background: #0969da;
}

.swagger-ui .btn.cancel {
	background: #d1242f;
	color: #ffffff;
}

.swagger-ui .scheme-container {
	background: #f6f8fa;
	border: 1px solid #d1d9e0;
}

.swagger-ui .model-box {
	background: #f6f8fa;
	color: #1f2328;
}

.swagger-ui section.models {
	border-color: #d1d9e0;
}

.swagger-ui section.models h4 {
	color: #1f2328;
}

.swagger-ui .model {
	color: #1f2328;
}

.swagger-ui .model-title {
	color: #0969da;
}

.swagger-ui table thead tr th,
.swagger-ui table thead tr td {
	color: #1f2328;
	border-bottom-color: #d1d9e0;
}

.swagger-ui table tbody tr td {
	color: #1f2328;
	border-color: #d1d9e0;
}

.swagger-ui .parameter__name {
	color: #0969da;
}

.swagger-ui .parameter__type {
	color: #1a7f37;
}

.swagger-ui .parameter__in {
	color: #59636e;
}

.swagger-ui .response-col_status {
	color: #8250df;
}

.swagger-ui .response-col_description {
	color: #1f2328;
}

.swagger-ui .responses-inner h4,
.swagger-ui .responses-inner h5 {
	color: #1f2328;
}

.swagger-ui .opblock-tag-section h3 {
	color: #1f2328;
}

.swagger-ui .prop-type {
	color: #1a7f37;
}

.swagger-ui .prop-format {
	color: #59636e;
}

.swagger-ui a.nostyle,
.swagger-ui a.nostyle:visited {
	color: #0969da;
}

.swagger-ui .markdown p,
.swagger-ui .markdown li {
	color: #1f2328;
}

.swagger-ui .markdown code {
	background: #f6f8fa;
	color: #8250df;
}

.swagger-ui .renderedMarkdown p {
	color: #1f2328;
}

.swagger-ui .response-col_links {
	color: #1f2328;
}
`
