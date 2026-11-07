# Dinit backend

This is the only module allowed to translate service lifecycle requests into Dinit-native operations.

It must not emulate systemd job objects or depend on systemd manager APIs. The backend protocol and failure semantics will be specified before implementation.
