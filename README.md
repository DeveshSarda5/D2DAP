# Adaptive Trust-Aware Drone Security Framework Using D2DAP Authentication and Machine Learning-Based Intrusion Detection

## Project Overview

This repository provides the foundational structure for a final-year B.Tech major project focused on secure drone communication in an Internet of Drones environment. The long-term goal is to design and evaluate an adaptive trust-aware security framework that combines Drone-to-Drone Authentication Protocol (D2DAP) mechanisms with machine learning-based intrusion detection and an adaptive trust engine.

## Problem Statement

Modern drone networks face increasing risks from compromised nodes, adversarial communication, and evolving intrusion attempts. Traditional static security rules are insufficient in dynamic multi-drone environments, where trustworthiness can change over time. This project addresses the need for a scalable and adaptive framework that can detect suspicious behavior, evaluate trust continuously, and enforce policy decisions in a realistic simulation environment.

## Project Objectives

The initial Phase 0 foundation establishes the repository structure, development tooling, documentation, and backend skeleton required for the later implementation of:

- Internet of Drones simulation infrastructure
- Drone-to-Drone Authentication (D2DAP) simulation components
- Machine learning-based intrusion detection
- Adaptive trust evaluation
- Policy enforcement mechanisms
- REST API and dashboard interfaces

## Existing Research Used

This project builds on prior research directions in two primary areas:

- D2DAP: The repository structure is prepared for future implementation of drone-to-drone authentication simulation concepts and protocol-oriented experimentation.
- Machine Learning Intrusion Detection: The repository layout supports future integration of supervised and unsupervised learning techniques for anomaly detection and intrusion classification.

## Actual Contribution

The project contribution is centered on an adaptive security architecture composed of:

- Adaptive Trust Engine for continuous evaluation of drone behavior
- Dynamic Policy Engine for enforcement of security rules
- Continuous Trust Evaluation to support resilient decision-making in changing network conditions

These components will be implemented incrementally in later phases.

## High-Level Architecture

The repository is organized around a modular backend application with clearly separated concerns:

- Authentication and communication modules for future D2DAP-related logic
- Drone, network, and simulator modules for environment modeling
- Attack and feature extraction modules for intrusion analysis
- IDS, trust, and policy modules for decision-making workflows
- Database, API, and utility layers for persistence and future service interfaces

## Technology Stack

- Python 3.12+
- FastAPI
- SQLite
- NetworkX
- pytest
- Black
- isort
- Ruff
- mypy
- uvicorn
- python-dotenv

## Repository Structure

```text
D2DAP/
├── backend/
│   ├── app/
│   │   ├── authentication/
│   │   ├── drones/
│   │   ├── simulator/
│   │   ├── network/
│   │   ├── communication/
│   │   ├── attacks/
│   │   ├── feature_extraction/
│   │   ├── ids/
│   │   ├── trust/
│   │   ├── policy/
│   │   ├── database/
│   │   ├── api/
│   │   ├── config/
│   │   ├── core/
│   │   ├── utils/
│   │   └── main.py
│   ├── tests/
│   ├── requirements.txt
│   ├── pyproject.toml
│   └── README.md
├── frontend/
├── datasets/
├── docs/
├── scripts/
├── .github/
├── .gitignore
├── LICENSE
├── README.md
└── CONTRIBUTING.md
```

## Development Roadmap

The project will proceed in phases:

1. Phase 0: Project foundation, repository structure, tooling, and documentation
2. Phase 1: Simulation environment and core domain models
3. Phase 2: D2DAP communication and trust representation
4. Phase 3: Intrusion detection and feature engineering
5. Phase 4: Adaptive trust and policy engine integration
6. Phase 5: API and dashboard interfaces

## Installation Instructions

### Prerequisites

- Python 3.12 or later
- Git
- Virtual environment support

### Virtual Environment Setup

```bash
python -m venv .venv
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Dependency Installation

```bash
cd backend
pip install -r requirements.txt
```

### Running the Backend

```bash
cd backend
uvicorn app.main:app --reload
```

## Coding Standards

- Use type hints for public functions and methods.
- Include module docstrings for all Python files.
- Follow Black formatting and Ruff linting rules.
- Keep modules focused and avoid unnecessary placeholder logic.
- Prefer clarity over premature optimization.

## Branching Strategy

- main: stable production-ready branch
- feature/: new feature development
- chore/: maintenance and repository foundation work
- docs/: documentation-only updates

## Testing Strategy

- Unit tests should cover backend behavior at the module level.
- Integration tests should validate service interactions as they are introduced.
- Run tests using pytest from the backend directory.

```bash
cd backend
pytest
```

## Future Work

Future work will focus on implementing the simulation engine, expanding the security model, integrating ML components, and exposing the architecture through a dashboard and API layer.

## License

This project is licensed under the MIT License. See the LICENSE file for details. Implemented Phase 1

## Contributors

This repository is maintained by the project team and contributors working on the Phase 0 foundation and future development milestones.
