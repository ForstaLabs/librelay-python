
import asyncio
import collections

gc_limit = 10000
_buckets = {}


async def _executor(bucket):
    queue = _buckets[bucket]
    while queue:
        scheduled = queue.popleft()
        try:
            scheduled.set_result(await scheduled.awaitable())
        except Exception as e:
            scheduled.set_exception(e)
    del _buckets[bucket]


async def queue_async(bucket, awaitable):
    """ Run the async awaitable only when all other async calls registered
    here have completed (or thrown).  The bucket argument is a hashable
    key representing the task queue to use. """
    if bucket not in _buckets:
        queue = _buckets[bucket] = collections.deque()
        inactive = True
    else:
        queue = _buckets[bucket]
        inactive = False
    scheduled = asyncio.Future()
    scheduled.awaitable = awaitable
    queue.append(scheduled)
    if inactive:
        asyncio.get_event_loop().create_task(_executor(bucket))
    return await scheduled
