
import asyncio
import collections

_buckets = {}


async def _executor(bucket):
    queue = _buckets[bucket]
    while queue:
        scheduled = queue.popleft()
        try:
            scheduled.set_result(await scheduled.coro)
        except Exception as e:
            scheduled.set_exception(e)
    del _buckets[bucket]


async def queue_async(bucket, coro):
    """ Chain the coro so it only runs after other coroutines in the same
    bucket have completed (or raised). """
    assert asyncio.iscoroutine(coro)
    if bucket not in _buckets:
        queue = _buckets[bucket] = collections.deque()
        inactive = True
    else:
        queue = _buckets[bucket]
        inactive = False
    scheduled = asyncio.Future()
    scheduled.coro = coro
    queue.append(scheduled)
    if inactive:
        asyncio.get_event_loop().create_task(_executor(bucket))
    return await scheduled
