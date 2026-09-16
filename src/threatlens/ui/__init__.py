"""Terminal presentation. Consumes models only; contains no collection or detection logic.

Security rule for this package: process names, paths, command lines and usernames are
attacker-controlled. They are always rendered via ``rich.text.Text`` (which treats content
literally and strips terminal control codes), never interpolated into Rich markup strings.
"""
