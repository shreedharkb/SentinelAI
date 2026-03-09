# SentinelAI
<<<<<<< HEAD

AI-Powered Dynamic Access Control System

## Overview

SentinelAI is an intelligent access control system that goes beyond traditional role-based access control (RBAC). It uses AI/ML to make real-time, context-aware access decisions based on user behavior patterns, risk assessment, and dynamic policy evaluation.

## Problem Statement

Traditional access control systems are static and cannot:
- Adapt to unusual behavior patterns (insider threats)
- Consider contextual factors (time, location, device)
- Learn and improve from historical decisions

SentinelAI addresses these limitations by implementing Attribute-Based Access Control (ABAC) enhanced with AI-driven risk assessment.

## Key Features

- **Dynamic Policy Engine** - Context-aware access decisions
- **AI Risk Assessment** - Real-time behavioral analysis
- **Audit Logging** - Complete access trail for compliance
- **Admin Dashboard** - Policy management and monitoring
- **Real-time Alerts** - Suspicious activity notifications

## Tech Stack

### Backend
- **Framework**: Python (FastAPI)
- **Database**: MongoDB
- **Cache/Pub-Sub**: Redis
- **AI/ML**: LangChain + OpenAI

### Frontend
- **Framework**: React + TypeScript
- **State Management**: Redux Toolkit
- **UI Components**: Material-UI / Tailwind CSS

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│    Frontend     │────▶│   API Gateway   │────▶│  Policy Engine  │
│    (React)      │     │    (FastAPI)    │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ▼
                                               ┌─────────────────┐
                                               │   AI Decision   │
                                               │     Engine      │
                                               └─────────────────┘
                                                        │
                                ┌───────────────────────┴───────────────────────┐
                                ▼                                               ▼
                        ┌─────────────────┐                             ┌─────────────────┐
                        │    MongoDB      │                             │     Redis       │
                        │  (Persistent)   │                             │    (Cache)      │
                        └─────────────────┘                             └─────────────────┘
```

## Project Status

🚧 Under Development

## License

MIT License - See [LICENSE](LICENSE) file for details
=======
AI-Agent based Automated Secure Dynamic Access Control solution.
