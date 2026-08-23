import pytest

from shadow_mission.protocol import ByteBoundedQueue, QueueCapacityError


def test_queue_enforces_item_and_byte_limits_before_enqueue() -> None:
    queue = ByteBoundedQueue(max_items=2, max_bytes=10)
    queue.put("first", b"1234")
    queue.put("second", b"5678")

    with pytest.raises(QueueCapacityError, match="item"):
        queue.put("third", b"9")

    assert queue.get() == "first"
    with pytest.raises(QueueCapacityError, match="byte"):
        queue.put("large", b"123456789")

    assert queue.item_count == 1
    assert queue.byte_count == 4


def test_queue_releases_exact_serialized_bytes_on_get() -> None:
    queue = ByteBoundedQueue(max_items=3, max_bytes=8)
    queue.put({"id": 1}, b"abc")
    queue.put({"id": 2}, b"defgh")

    assert queue.byte_count == 8
    assert queue.get() == {"id": 1}
    assert queue.byte_count == 5
    assert queue.get() == {"id": 2}
    assert queue.byte_count == 0
