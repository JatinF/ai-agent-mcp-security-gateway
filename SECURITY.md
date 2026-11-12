# Security

This repository is a self-directed lab. It has no production deployment and no customer data.

Tokens in the lab are minted in memory. Do not commit a private key, a bearer token, or a filled `.env`. The scanner in `scripts/reject_private_keys.py` rejects PEM private-key markers.

Report a defect in this lab by opening a GitHub issue on `JatinF/ai-agent-mcp-security-gateway`. Include the command you ran and the reason code you observed. Leave out tokens and environment values.
