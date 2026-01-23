const std = @import("std");
const constants = @import("constants.zig");
const Config = @import("config.zig").Config;
const Context = @import("context.zig").Context;

pub const TaskState = enum {
    pending,
    running,
    completed,
    failed,
    cancelled,
};

pub const TaskResult = union(enum) {
    success: void,
    value: []const u8,
    err: anyerror,
};

pub const Task = struct {
    id: u64,
    state: TaskState,
    func: *const fn (*Context) anyerror!void,
    result: ?TaskResult,
    created_at: i64,
    completed_at: ?i64,

    pub fn init(id: u64, func: *const fn (*Context) anyerror!void) Task {
        return Task{
            .id = id,
            .state = .pending,
            .func = func,
            .result = null,
            .created_at = std.time.milliTimestamp(),
            .completed_at = null,
        };
    }

    pub fn isPending(self: *const Task) bool {
        return self.state == .pending;
    }

    pub fn isRunning(self: *const Task) bool {
        return self.state == .running;
    }

    pub fn isCompleted(self: *const Task) bool {
        return self.state == .completed;
    }

    pub fn isFailed(self: *const Task) bool {
        return self.state == .failed;
    }

    pub fn isCancelled(self: *const Task) bool {
        return self.state == .cancelled;
    }

    pub fn isDone(self: *const Task) bool {
        return self.state == .completed or self.state == .failed or self.state == .cancelled;
    }

    pub fn duration(self: *const Task) ?i64 {
        if (self.completed_at) |completed| {
            return completed - self.created_at;
        }
        return null;
    }
};

pub const TaskQueue = struct {
    allocator: std.mem.Allocator,
    tasks: std.ArrayList(Task),
    next_id: u64,
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator) TaskQueue {
        return TaskQueue{
            .allocator = allocator,
            .tasks = .empty,
            .next_id = 1,
            .mutex = std.Thread.Mutex{},
        };
    }

    pub fn deinit(self: *TaskQueue) void {
        self.tasks.deinit(self.allocator);
    }

    pub fn enqueue(self: *TaskQueue, func: *const fn (*Context) anyerror!void) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const id = self.next_id;
        self.next_id += 1;

        const task = Task.init(id, func);
        self.tasks.append(self.allocator, task) catch return 0;

        return id;
    }

    pub fn getTask(self: *TaskQueue, id: u64) ?*Task {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.tasks.items) |*task| {
            if (task.id == id) {
                return task;
            }
        }
        return null;
    }

    pub fn cancelTask(self: *TaskQueue, id: u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.tasks.items) |*task| {
            if (task.id == id and task.state == .pending) {
                task.state = .cancelled;
                task.completed_at = std.time.milliTimestamp();
                return true;
            }
        }
        return false;
    }

    pub fn pendingCount(self: *TaskQueue) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var count: usize = 0;
        for (self.tasks.items) |task| {
            if (task.state == .pending) {
                count += 1;
            }
        }
        return count;
    }

    pub fn completedCount(self: *TaskQueue) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var count: usize = 0;
        for (self.tasks.items) |task| {
            if (task.isDone()) {
                count += 1;
            }
        }
        return count;
    }

    pub fn clear(self: *TaskQueue) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.tasks.clearRetainingCapacity();
    }
};

pub const Timer = struct {
    start_time: i64,
    end_time: ?i64,

    pub fn start() Timer {
        return Timer{
            .start_time = std.time.milliTimestamp(),
            .end_time = null,
        };
    }

    pub fn stop(self: *Timer) void {
        self.end_time = std.time.milliTimestamp();
    }

    pub fn elapsed(self: *const Timer) i64 {
        const end = self.end_time orelse std.time.milliTimestamp();
        return end - self.start_time;
    }

    pub fn elapsedNanos(self: *const Timer) i128 {
        return @as(i128, self.elapsed()) * std.time.ns_per_ms;
    }

    pub fn reset(self: *Timer) void {
        self.start_time = std.time.milliTimestamp();
        self.end_time = null;
    }
};

pub fn sleep(ms: u64) void {
    std.Thread.sleep(ms * std.time.ns_per_ms);
}

pub fn sleepNanos(ns: u64) void {
    std.Thread.sleep(ns);
}

pub fn timestamp() i64 {
    return std.time.timestamp();
}

pub fn milliTimestamp() i64 {
    return std.time.milliTimestamp();
}

pub fn nanoTimestamp() i128 {
    return std.time.nanoTimestamp();
}

pub const Debouncer = struct {
    delay_ms: u64,
    last_call: ?i64,

    pub fn init(delay_ms: u64) Debouncer {
        return Debouncer{
            .delay_ms = delay_ms,
            .last_call = null,
        };
    }

    pub fn shouldExecute(self: *Debouncer) bool {
        const now = std.time.milliTimestamp();

        if (self.last_call) |last| {
            if (now - last < @as(i64, @intCast(self.delay_ms))) {
                return false;
            }
        }

        self.last_call = now;
        return true;
    }

    pub fn reset(self: *Debouncer) void {
        self.last_call = null;
    }
};

pub const Throttler = struct {
    interval_ms: u64,
    last_execution: ?i64,

    pub fn init(interval_ms: u64) Throttler {
        return Throttler{
            .interval_ms = interval_ms,
            .last_execution = null,
        };
    }

    pub fn tryExecute(self: *Throttler) bool {
        const now = std.time.milliTimestamp();

        if (self.last_execution) |last| {
            if (now - last < @as(i64, @intCast(self.interval_ms))) {
                return false;
            }
        }

        self.last_execution = now;
        return true;
    }

    pub fn reset(self: *Throttler) void {
        self.last_execution = null;
    }
};

test "Task.init creates pending task" {
    const testing = std.testing;

    const func = struct {
        fn f(_: *Context) !void {}
    }.f;

    const task = Task.init(1, func);
    try testing.expectEqual(@as(u64, 1), task.id);
    try testing.expectEqual(TaskState.pending, task.state);
    try testing.expect(task.isPending());
    try testing.expect(!task.isDone());
}

test "TaskQueue.init creates empty queue" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var queue = TaskQueue.init(allocator);
    defer queue.deinit();

    try testing.expectEqual(@as(usize, 0), queue.pendingCount());
}

test "TaskQueue.enqueue adds tasks" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var queue = TaskQueue.init(allocator);
    defer queue.deinit();

    const func = struct {
        fn f(_: *Context) !void {}
    }.f;

    const id1 = queue.enqueue(func);
    const id2 = queue.enqueue(func);

    try testing.expectEqual(@as(u64, 1), id1);
    try testing.expectEqual(@as(u64, 2), id2);
    try testing.expectEqual(@as(usize, 2), queue.pendingCount());
}

test "TaskQueue.cancelTask cancels pending task" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var queue = TaskQueue.init(allocator);
    defer queue.deinit();

    const func = struct {
        fn f(_: *Context) !void {}
    }.f;

    const id = queue.enqueue(func);
    try testing.expect(queue.cancelTask(id));

    const task = queue.getTask(id);
    try testing.expect(task != null);
    try testing.expect(task.?.isCancelled());
}

test "Timer.elapsed measures time" {
    const testing = std.testing;

    var timer = Timer.start();
    sleep(10);
    timer.stop();

    const elapsed_time = timer.elapsed();
    try testing.expect(elapsed_time >= 10);
}

test "Debouncer.shouldExecute respects delay" {
    const testing = std.testing;

    var debouncer = Debouncer.init(100);

    try testing.expect(debouncer.shouldExecute());
    try testing.expect(!debouncer.shouldExecute());

    debouncer.reset();
    try testing.expect(debouncer.shouldExecute());
}

test "Throttler.tryExecute respects interval" {
    const testing = std.testing;

    var throttler = Throttler.init(100);

    try testing.expect(throttler.tryExecute());
    try testing.expect(!throttler.tryExecute());

    throttler.reset();
    try testing.expect(throttler.tryExecute());
}
