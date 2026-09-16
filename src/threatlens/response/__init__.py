"""Response actions. Only ever invoked from an explicit, confirmed user command — never by
detection. Every action is guarded (protected-process policy, PID-reuse check) and audited."""
