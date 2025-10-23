📘 PROJECT OVERVIEW

Panopticon Analytics is a modular data intelligence framework designed to analyze, visualize, and narrate human behavior during live events.
It powers The Wall — an interactive installation that visualizes the collective “data soul” of a crowd in real time.

The system bridges sociological data, marketing algorithms, and aesthetic storytelling, structured across four analytical layers:

Pan_Analytics – Core computation and data structuring

V_Cramer – Relationship mapping via Cramér’s V and similarity matrices

Guest_Similarity – Compatibility pairing and network graph creation

Pan_Validation – System checks, sheet integrity, and rebuild triggers

Each layer feeds both front-end visualizations (Wall.html, MM.html, Map.html, Terminal.html) and back-end datasets (Pan_Master, Pan_Dict, V_Cramers_Categories, etc.).

⚙️ FUNCTIONAL RULES

All AI systems contributing to this repository (Claude, ChatGPT, Copilot, etc.) must strictly adhere to these rules:

1. Edit Scope

Only perform function-by-function modifications.

Do not rewrite full files unless explicitly requested.

Preserve variable naming conventions (Pan_, V_, Guest_, Edges_, etc.).

2. Descriptive Comments

Each function must include a descriptive header:

/**
 * Function: buildPanMaster()
 * Purpose: Filters checked-in guests, encodes categorical data, and builds Pan_Master.
 * Inputs: Form Responses (Clean)
 * Outputs: Pan_Master sheet, Pan_Dict sheet
 * Notes: Runs only when column AB == "Y"
 */


Inline comments should explain logic intent, not just syntax.
