# Python Support Policy

Android Trust Lab supports Python 3.11, 3.12, 3.13, and 3.14. Python 3.11 is
the minimum because it provides the standard-library TOML reader and a modern,
maintained typing/runtime baseline without compatibility-only dependencies.

Package metadata, classifiers, documentation, and the CI matrix are checked for
consistency. Wheel and sdist builds run on the oldest supported interpreter as
part of the Python 3.11 job; every supported interpreter runs the complete
repository gate.

Revisit the floor when Python 3.11 approaches the end of upstream security
support, or earlier if required dependencies or CI providers stop supporting it.
Raising the floor requires an explicit compatibility note and coordinated
metadata, documentation, and CI changes.
