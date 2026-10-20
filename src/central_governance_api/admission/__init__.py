"""Admission registry for MCP servers, skills and plugins (OHS item 1.5 / chapter 6).

Design: ``OHS_admission_design_gate2.md`` (in the openhands-governance folder). This
package is step C1: the registry, its state machine, and the submit / approve /
first-use APIs. There is no check pipeline yet (C5, C6), so nothing can reach
``checked`` through the API and nothing can be approved: that is deliberate and fails
closed.
"""
