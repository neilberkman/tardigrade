"""Tiny deterministic target model for success-implies-effect tests.

The injected path returns success before changing a synthetic durable
generation marker.
"""


class GenerationTarget:
    def __init__(self, generation=5):
        self.commit_generation = generation

    def persist_generation(self, new_generation, injected=False):
        if injected:
            return 0
        self.commit_generation = max(self.commit_generation, new_generation)
        return 0
