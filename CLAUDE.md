# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

This repository is a living knowledge base built by Claude across penetration testing sessions, CTF competitions, HackTheBox challenges, and other offensive security practice. It accumulates methodology, frameworks, techniques, and notes so that each new session starts with full context from prior work.

## How This Repo Grows

After each session or engagement, Claude commits:
- **Methodology docs** — structured approaches for recon, enumeration, exploitation, post-exploitation, etc.
- **Technique notes** — specific tools, payloads, or patterns discovered during practice
- **Checklists** — per-category checklists refined through experience
- **Challenge writeups** — key lessons from CTF/HTB boxes
- **Skills assessment writeups** — the skills assessment at the end of every HTB module is the most important writeup; it tests everything learned in the module and must always be committed. Write the full attack chain, key payloads, and lessons learned.

## HTB Module Lab Rules — MANDATORY

When working through an HTB Academy module section and answering lab questions:

1. **Use only the tools and methodology from the current section.** The section content provides the exact commands, tools, and techniques needed. Apply them directly to the lab target — nothing more.
2. **Never write custom scripts when the section provides a tool.** If the section references a tool (e.g. `joomla-brute.py`, `wpscan`, `droopescan`), find and use that tool. Do not replace it with a custom alternative.
3. **Never reach for tools not taught in the section.** If the section doesn't mention it, don't use it.
4. **Read the section content before suggesting any command.** The answer to "what do I run?" is always in the section — find it there first.
5. **Simple before complex.** If the approach is getting complicated, you skipped a step in the section.

Violating these rules wastes time and defeats the purpose of the module. This is a hard requirement, not a preference.

## Security Context

All content is for authorized penetration testing, CTF challenges, and defensive security research. Nothing here is intended for unauthorized access or malicious use.

## Repo Structure (evolves over time)

```
methodology/     # General attack phase frameworks
techniques/      # Tool-specific and technique-specific notes
checklists/      # Per-category enumeration and attack checklists
writeups/        # CTF and HTB box writeups with key takeaways
```
