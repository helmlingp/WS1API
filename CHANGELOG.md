# Changelog

All notable changes to this project will be documented in this file.

## 1.0.0 - May 2026

This release delivers comprehensive WS1 UEM automation coverage across major workflows:

- Authentication and configuration (OAuth 2.0, basic auth, retry-enabled API invocation)
- Organization discovery and search (OG lookup, enrollment context retrieval)
- Device discovery, tagging, and lifecycle management (stale/duplicate/problematic detection, bulk deletion, passcode clear, device property updates)
- Application lifecycle operations (icon upload, chunked upload, app creation, catalog queries, URL-based uploads)
- Baseline reporting and assignment insights (templates, devices, policies, summary views)
- Agent deployment and maintenance (download, install, uninstall, cleanup, app/profile wait operations)
- User identity and enrollment correlation (SID lookups, duplicate user detection and cleanup)
- Local system and utility operations (registry access, task creation, notifications, tagging)
- Logging and reporting utilities for operational visibility

Total functions exported: 57

Notes:
- Capability descriptions can be sourced from each function's PowerShell help .DESCRIPTION block
- Example: Get-Help <FunctionName> -Full
