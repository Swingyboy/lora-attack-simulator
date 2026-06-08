"""Attack plugin registry with spec-based architecture."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Type

if TYPE_CHECKING:
    from lora_attack_toolkit.attacks.base import BaseAttack


@dataclass
class AttackSpec:
    """Complete plugin specification for an attack type.
    
    Owns all attack-type-specific logic:
    - Config parsing/validation
    - Aliases for backwards compatibility
    
    This removes hardcoded logic from runner - each plugin is self-contained.
    
    Example:
        spec = AttackSpec(
            name="join_devnonce",
            attack_class=JoinDevNonceAttack,
            config_parser=parse_join_devnonce_config,
            description="Test DevNonce replay protection",
        )
        
        AttackRegistry.register(spec)
    """
    
    name: str
    attack_class: Type[BaseAttack]
    config_parser: Callable[[dict[str, Any]], Any]
    aliases: list[str] = field(default_factory=list)
    description: str = ""
    version: str = "1.0"


class AttackRegistry:
    """Central registry for attack plugins.
    
    Provides:
    - Registration with duplicate detection
    - Alias resolution
    - Spec lookup
    
    Usage:
        # Bootstrap (in app startup):
        register_builtin_attacks()
        
        # Lookup (in runner):
        spec = AttackRegistry.get_spec("join_devnonce")
        config = spec.config_parser(scenario.attack.config)
        attack_cls = AttackRegistry.get_attack_class("join_devnonce")
        attack = attack_cls()
        result = attack.run(ctx)
    """
    
    _specs: dict[str, AttackSpec] = {}
    _aliases: dict[str, str] = {}  # alias -> canonical name
    _lock: Any = None  # For thread safety if needed later
    
    @classmethod
    def register(cls, spec: AttackSpec) -> None:
        """Register an attack plugin spec.
        
        Args:
            spec: The attack specification
            
        Raises:
            ValueError: If name or alias already registered
        """
        # Check for duplicate name
        if spec.name in cls._specs:
            raise ValueError(
                f"Attack type '{spec.name}' already registered. "
                f"Existing: {cls._specs[spec.name].description}"
            )
        
        # Check for alias collisions
        for alias in spec.aliases:
            if alias in cls._aliases:
                existing = cls._aliases[alias]
                raise ValueError(
                    f"Alias '{alias}' already registered for attack '{existing}'"
                )
            if alias in cls._specs:
                raise ValueError(
                    f"Alias '{alias}' conflicts with existing attack name"
                )
        
        # Register spec
        cls._specs[spec.name] = spec
        
        # Register aliases
        for alias in spec.aliases:
            cls._aliases[alias] = spec.name
    
    @classmethod
    def get_spec(cls, name_or_alias: str) -> AttackSpec:
        """Get attack spec by name or alias.
        
        Args:
            name_or_alias: Attack type or alias
            
        Returns:
            AttackSpec for the attack
            
        Raises:
            ValueError: If attack type unknown
        """
        # Resolve alias to canonical name
        canonical = cls._aliases.get(name_or_alias, name_or_alias)
        
        if canonical not in cls._specs:
            # Provide helpful error with available types
            available = sorted(list(cls._specs.keys()) + list(cls._aliases.keys()))
            raise ValueError(
                f"Unknown attack type: '{name_or_alias}'. "
                f"Available types: {', '.join(available)}"
            )
        
        return cls._specs[canonical]

    @classmethod
    def get(cls, name_or_alias: str) -> Type["BaseAttack"]:
        """Get the attack class by name or alias."""
        return cls.get_spec(name_or_alias).attack_class

    @classmethod
    def get_attack_class(cls, name_or_alias: str) -> Type["BaseAttack"]:
        """Backward-compatible alias for get()."""
        return cls.get(name_or_alias)
    
    @classmethod
    def list_attacks(cls) -> list[str]:
        """List all registered attack types (canonical names only)."""
        return sorted(cls._specs.keys())
    
    @classmethod
    def list_all_names(cls) -> list[str]:
        """List all registered names and aliases."""
        return sorted(list(cls._specs.keys()) + list(cls._aliases.keys()))
    
    @classmethod
    def get_info(cls, name_or_alias: str) -> dict[str, Any]:
        """Get info about an attack type.
        
        Returns:
            Dict with name, description, aliases, version
        """
        spec = cls.get_spec(name_or_alias)
        return {
            "name": spec.name,
            "description": spec.description,
            "aliases": spec.aliases,
            "version": spec.version,
            "class": spec.attack_class.__name__,
        }
    
    @classmethod
    def clear(cls) -> None:
        """Clear all registrations (for testing)."""
        cls._specs.clear()
        cls._aliases.clear()
