# ProofOfAuthenticity

[![npm version](https://img.shields.io/npm/v/n8n-nodes-proofofauthenticity.svg)](https://www.npmjs.com/package/n8n-nodes-proofofauthenticity)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Developed by **[CHECKHC](https://checkhc.net)** - Blockchain content certification experts

## Overview

**ProofOfAuthenticity** is an n8n community node that provides blockchain timestamping with optional AI authenticity detection and C2PA content authenticity metadata.

### Features

- **Blockchain Timestamping** - SHA-256 hash certified on Solana blockchain
- **AI Authenticity Detection** - Detect AI-generated vs human-created content
- **C2PA Integration** - Content Authenticity Initiative standard metadata

## Operations

### Create Certificate

Certify content with blockchain timestamp.

| Parameter | Description |
|-----------|-------------|
| Input Type | URL or Base64 |
| File URL/Data | The file to certify |
| Title | Certificate title (required) |
| Author | Author name (optional) |
| Description | Description (optional) |
| Certification Mode | Simple or AI + C2PA |

### List Certificates

List blockchain certificates with optional filters (hash, filename, signature).

## Installation

### Via n8n Community Nodes

1. Go to **Settings** > **Community Nodes**
2. Select **Install**
3. Enter `n8n-nodes-proofofauthenticity`
4. Click **Install**

### Manual Installation

```bash
cd ~/.n8n/nodes
yarn add n8n-nodes-proofofauthenticity
```

## Configuration

1. Create a credential of type **ProofOfAuthenticity API**
2. Enter your DigiCryptoStore instance URL
3. Enter your API Key (Settings > API Keys)

## Support

- **GitHub**: Issues/Discussions
- **Email**: contact@checkhc.net
- **Website**: [https://checkhc.net](https://checkhc.net)

## License

MIT

---

**Powered by [CHECKHC](https://checkhc.net)**
