# Dummy-Opaque-Predicate-Removal
Remove opaque predicates which lead to unreachable blocks to simplify control flow. This was written back in January of 2023 for control flow obfuscation research as I worked on an LLVM control flow obfuscation compiler pass. It works by identifying opaque predicates through common instruction patterns, then NOPing them.

**Disclaimer: ** this project was for educational research (anti-tampering, IP protection) to test the strength of control flow obfuscation techniques. Only use on software you own or have explicit permission to test or protect.
