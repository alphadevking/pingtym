<div align="center">

<img src="./web/assets/logo.svg" width="80" height="80" />

# Pingtym Insights
**The Precision Observability Platform for Modern Infrastructure.**

[![Go Version](https://img.shields.io/badge/Go-1.24%2B-10b981?style=for-the-badge&logo=go)](https://golang.org)
[![HTMX](https://img.shields.io/badge/HTMX-1.9-10b981?style=for-the-badge)](https://htmx.org)
[![Turso](https://img.shields.io/badge/Database-Turso-10b981?style=for-the-badge&logo=turso)](https://turso.tech)
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
-   **Isolated Multi-Tenancy:** Secure, persistent sessions with encrypted UUIDs.
-   **Proxy-Aware IP Extraction:** Optimized for Istio, Envoy, and Vercel edge networks.

---

### 🛠️ Technology Stack

| Component | Technology |
| :--- | :--- |
| **Engine** | High-concurrency Go (Golang) |
| **Frontend** | HTMX + Vanilla CSS (Emerald Identity) |
| **Database** | Turso (libSQL) / SQLite with WAL |
| **Deployment** | Vercel Serverless Ready |

---

### 🚀 Getting Started

**1. Clone and enter the workspace:**
```bash
git clone https://github.com/Alphadevking/Pingtym.git
cd pingtym
```

**2. Configure Environment:**
Copy `.env.example` to `.env` and set your `SESSION_SECRET`. For production persistence, provide your Turso database credentials.

**3. Launch the engine:**
```bash
go run cmd/server/main.go
```

Your dashboard will be ready at `http://localhost:8080`.

---

### 🤝 Open for Collaboration
Pingtym Insights is an open-source project and we welcome contributions! Whether you're fixing bugs, adding new features, or improving documentation, your help is appreciated. 

- **Found a bug?** Open an issue.
- **Have a feature idea?** Start a discussion.
- **Want to code?** Submit a pull request.

Let's build the future of precision observability together.

---
<div align="center">
Built with ❤️ for Site Reliability Engineers who demand zero-latency insights.
</div>
