"""Experimental, non-shipped attack designs.

Modules in this package are **not** registered in the attack registry and are
**not** part of the supported toolkit. They are retained for documentation and
future work only.

``mac_abuse.MACCommandAbuse`` was designed but deliberately excluded from the
shipped attack set: in its current form it builds MAC-command bytes, captures
them to the local packet log, and mutates local ADR state without ever
transmitting an authenticated frame to (or validating any response from) the
target Network Server. It therefore cannot demonstrate a valid threat model
within the current scope and is documented as such in the thesis.
"""
