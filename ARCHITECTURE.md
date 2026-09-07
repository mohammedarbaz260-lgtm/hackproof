# 🏗️ HackProof AI — Architecture

## 1. Overview

HackProof AI is a modular cybersecurity learning and authorized security-analysis platform.

The application combines a web interface, authentication, AI assistance, local cybersecurity knowledge, security-analysis modules, threat correlation, and report storage.

---

## 2. High-Level Architecture

```text
                    ┌──────────────────────┐
                    │       User           │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   Web Interface      │
                    │     Flask App        │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   Authentication     │
                    │    Flask-Login       │
                    └──────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
       ┌────────────┐   ┌────────────┐   ┌────────────┐
       │ AI / Chat  │   │  Security  │   │ Knowledge  │
       │ Assistant  │   │  Analysis  │   │    Base    │
       └─────┬──────┘   └─────┬──────┘   └─────┬──────┘
             │                │                │
             ▼                ▼                ▼
       ┌────────────┐   ┌────────────┐   ┌────────────┐
       │  Memory    │   │ Threat     │   │ Local      │
       │            │   │ Correlation│  │ Knowledge  │
       └────────────┘   └─────┬──────┘   └────────────┘
                              │
                    ┌─────────┴─────────┐
                    │                   │
                    ▼                   ▼
             ┌────────────┐      ┌────────────┐
             │  Security  │      │  Reports   │
             │  Results   │      │  Database  │
             └────────────┘      └────────────┘
