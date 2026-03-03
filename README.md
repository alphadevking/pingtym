<div align="center">

<img src="./web/assets/logo.svg" width="80" height="80" />

# Pingtym Insights
**The Precision Observability Platform for Modern Infrastructure.**

[![Go Version](https://img.shields.io/badge/Go-1.24%2B-10b981?style=for-the-badge&logo=go)](https://golang.org)
[![HTMX](https://img.shields.io/badge/HTMX-1.9-10b981?style=for-the-badge)](https://htmx.org)
[![Vercel](https://img.shields.io/badge/Vercel-Ready-10b981?style=for-the-badge&logo=vercel)](https://vercel.com)
[![Theme](https://img.shields.io/badge/Theme-Almost%20Black-050505?style=for-the-badge)](https://github.com/Alphadevking/Pingtym)
[![License](https://img.shields.io/badge/License-MIT-10b981?style=for-the-badge)](LICENSE)

</div>

---

### 🛰️ Wire-Level Ground Truth
Pingtym Insights doesn't just "ping" your services; it performs deep network tracing using Go's `httptrace` stack. Get the absolute truth about your infrastructure performance, from the first byte to the final handshake.

### ✨ Premium Features

-   **Emerald Latency Tracing:** High-precision SVG sparklines scaled to your asset's unique performance profile.
-   **Almost-Black Interface:** A high-contrast, premium dark theme (`#050505`) optimized for professional OLED monitoring.
-   **Security Governance:** Automated SSL/TLS expiry tracking with proactive 30-day renewal warnings.
-   **SaaS Correlation:** Real-time health synchronization with upstream providers like MongoDB, GitHub, and Cloudflare.
-   **Instant Registry Search:** Zero-latency infrastructure filtering as you type.
-   **Isolated Multi-Tenancy:** Secure, persistent browser sessions ensured via encrypted UUIDs.

---

### 🛠️ Technology Stack

| Component | Technology |
| :--- | :--- |
| **Engine** | High-concurrency Go (Golang) |
| **Frontend** | HTMX + Vanilla CSS (Emerald Identity) |
| **Database** | SQLite with WAL (Write-Ahead Logging) |
| **Deployment** | Vercel Serverless Ready |

---

### 🚀 Getting Started

Launch the full observability suite in seconds:

```bash
# Clone and enter the workspace
git clone https://github.com/Alphadevking/Pingtym.git
cd pingtym

# Launch the engine
go run cmd/server/main.go
```

Your dashboard will be ready at `http://localhost:8080`.

---
<div align="center">
Built with ❤️ by <b>Favour Orukpe (alphadevking)</b> for Site Reliability Engineers who demand zero-latency insights.
</div>
