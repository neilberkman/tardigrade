# Python mirror of WritebackDomain for unit testing.
# The C# implementation lives in peripherals/FaultTracker.cs and is tested
# via Renode integration.  This model validates the overlay semantics in
# isolation so regressions are caught without spinning up an emulator.


class WritebackDomain:
    def __init__(self, base_addr: int, size: int, capacity: int = 0):
        self.base_address = base_addr
        self.size = size
        self.capacity = capacity
        self.overlay: dict[int, int] = {}
        self.dirty = False
        self.write_count = 0
        self.committed_count = 0
        self.timeline: list[tuple] = []

    def write(self, offset: int, value: int) -> bool:
        if offset < 0 or offset >= self.size:
            return False
        self.overlay[offset] = value & 0xFFFFFFFF
        self.dirty = True
        self.write_count += 1
        self.timeline.append(("write", offset, value & 0xFFFFFFFF, self.write_count))
        if self.capacity > 0 and self.write_count >= self.capacity:
            self.commit("buffer_full")
        return True

    def read(self, offset: int, flash_value: int) -> int:
        if offset in self.overlay:
            return self.overlay[offset]
        return flash_value & 0xFFFFFFFF

    def commit(self, reason: str = "explicit") -> dict[int, int]:
        committed = dict(self.overlay)
        self.committed_count += len(self.overlay)
        self.timeline.append(("commit", reason, len(committed)))
        self.overlay.clear()
        self.dirty = False
        self.write_count = 0
        return committed

    def discard(self) -> int:
        lost = len(self.overlay)
        self.timeline.append(("discard", lost))
        self.overlay.clear()
        self.dirty = False
        self.write_count = 0
        return lost

    @property
    def pending(self) -> int:
        return len(self.overlay)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_write_then_read_overlay_hit():
    d = WritebackDomain(0x1000, 0x100)
    d.write(0x10, 0xDEADBEEF)
    assert d.read(0x10, 0xFFFFFFFF) == 0xDEADBEEF


def test_read_fallthrough_to_flash():
    d = WritebackDomain(0x1000, 0x100)
    assert d.read(0x20, 0xCAFEBABE) == 0xCAFEBABE


def test_write_sets_dirty():
    d = WritebackDomain(0x1000, 0x100)
    assert not d.dirty
    d.write(0x00, 0x01)
    assert d.dirty


def test_write_out_of_range_rejected():
    d = WritebackDomain(0x1000, 0x100)
    assert d.write(-1, 0x01) is False
    assert d.write(0x100, 0x01) is False
    assert d.pending == 0


def test_write_at_boundary_accepted():
    d = WritebackDomain(0x1000, 0x100)
    assert d.write(0x00, 0xAA) is True
    assert d.write(0xFF, 0xBB) is True
    assert d.pending == 2


def test_commit_returns_data_and_clears_overlay():
    d = WritebackDomain(0x1000, 0x100)
    d.write(0x00, 0x11111111)
    d.write(0x04, 0x22222222)
    committed = d.commit("sync")
    assert committed == {0x00: 0x11111111, 0x04: 0x22222222}
    assert d.pending == 0
    assert not d.dirty
    assert d.write_count == 0


def test_commit_accumulates_committed_count():
    d = WritebackDomain(0x1000, 0x100)
    d.write(0x00, 0xAA)
    d.write(0x04, 0xBB)
    d.commit("a")
    d.write(0x08, 0xCC)
    d.commit("b")
    assert d.committed_count == 3


def test_discard_loses_data_returns_count():
    d = WritebackDomain(0x1000, 0x100)
    d.write(0x00, 0x11)
    d.write(0x04, 0x22)
    lost = d.discard()
    assert lost == 2
    assert d.pending == 0
    assert not d.dirty
    # After discard, flash value falls through
    assert d.read(0x00, 0xFFFFFFFF) == 0xFFFFFFFF


def test_buffer_full_auto_commit():
    """Third write to a capacity=3 domain must trigger auto-commit."""
    d = WritebackDomain(0x1000, 0x100, capacity=3)
    d.write(0x00, 0xAA)
    d.write(0x04, 0xBB)
    assert d.pending == 2
    d.write(0x08, 0xCC)
    # Auto-commit fired — overlay cleared
    assert d.pending == 0
    assert d.committed_count == 3
    assert not d.dirty


def test_buffer_full_auto_commit_before_capacity():
    """Writes before capacity threshold must NOT auto-commit."""
    d = WritebackDomain(0x1000, 0x100, capacity=5)
    for i in range(4):
        d.write(i * 4, i)
    assert d.pending == 4
    assert d.committed_count == 0


def test_domain_isolation():
    """Two domains at different base addresses must not interfere."""
    a = WritebackDomain(0x0000, 0x100)
    b = WritebackDomain(0x1000, 0x100)
    a.write(0x00, 0xAAAAAAAA)
    b.write(0x00, 0xBBBBBBBB)
    assert a.read(0x00, 0) == 0xAAAAAAAA
    assert b.read(0x00, 0) == 0xBBBBBBBB
    a.discard()
    assert b.pending == 1
    assert b.read(0x00, 0) == 0xBBBBBBBB


def test_domain_isolation_commit():
    """Committing one domain does not affect another."""
    a = WritebackDomain(0x0000, 0x100)
    b = WritebackDomain(0x1000, 0x100)
    a.write(0x00, 0x11)
    b.write(0x00, 0x22)
    a.commit("flush_a")
    assert b.pending == 1
    assert b.dirty


def test_timeline_records_writes_and_commits():
    d = WritebackDomain(0x1000, 0x100)
    d.write(0x00, 0xAA)
    d.write(0x04, 0xBB)
    d.commit("explicit")
    events = [e[0] for e in d.timeline]
    assert events.count("write") == 2
    assert events.count("commit") == 1


def test_timeline_records_discard():
    d = WritebackDomain(0x1000, 0x100)
    d.write(0x00, 0x01)
    d.discard()
    assert any(e[0] == "discard" for e in d.timeline)


def test_timeline_buffer_full_commit_recorded():
    d = WritebackDomain(0x1000, 0x100, capacity=2)
    d.write(0x00, 0x01)
    d.write(0x04, 0x02)  # triggers auto-commit
    commit_events = [e for e in d.timeline if e[0] == "commit"]
    assert len(commit_events) == 1
    assert commit_events[0][1] == "buffer_full"


def test_overlay_overwrite_same_offset():
    """Writing the same offset twice keeps the latest value."""
    d = WritebackDomain(0x1000, 0x100)
    d.write(0x00, 0x11)
    d.write(0x00, 0x22)
    assert d.read(0x00, 0xFF) == 0x22
    assert d.pending == 1  # still one entry, not two
    assert d.write_count == 2  # but write_count tracks all writes (drives buffer-full)


def test_capacity_zero_means_no_auto_commit():
    # Domain is 0x100 bytes = 64 words.  Write all 64 valid word offsets.
    d = WritebackDomain(0x1000, 0x100, capacity=0)
    for i in range(64):
        d.write(i * 4, i)
    assert d.committed_count == 0
    assert d.pending == 64
