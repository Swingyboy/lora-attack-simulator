"""Base attack class for all attack implementations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lora_attack_toolkit.attacks.context import AttackContext
    from lora_attack_toolkit.attacks.result import AttackResult


class BaseAttack(ABC):
    """
    Abstract base class for all attack implementations.
    
    This is the plugin interface - attacks only need to implement run(ctx).
    
    The AttackContext provides everything needed:
    - Device and gateway simulators
    - Logger and packet capture
    - Attack configuration
    - Expected behavior / security criteria
    - Radio metadata
    
    Attacks should not store framework internals as instance variables.
    Everything is accessed through the context parameter.
    
    Example:
        class MyAttack(BaseAttack):
            name = "my_attack"
            
            def run(self, ctx: AttackContext) -> AttackResult:
                # Access services through context
                ctx.logger.info("Starting attack")
                ctx.gateway.start()
                
                # Perform attack logic
                ctx.device.send_join_request()
                
                # Return result
                return AttackResult(
                    attack_name=self.name,
                    success=True,
                    message="Attack completed",
                    metrics={},
                )
    """
    
    # Attack name - set as class attribute
    name: str = "base_attack"
    
    @abstractmethod
    def run(self, ctx: AttackContext) -> AttackResult:
        """
        Execute the complete attack with given context.
        
        This is the only method attacks need to implement.
        
        Args:
            ctx: AttackContext containing all services and configuration
        
        Returns:
            AttackResult with execution outcome
        """
        raise NotImplementedError
