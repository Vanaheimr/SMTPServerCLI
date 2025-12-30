// Queue Processor - Event-based mail delivery with Channel<T>
// .NET 10 / C# 13

using System.Collections.Concurrent;
using System.Threading.Channels;

namespace AchimSmtpServer;

#region Queue Processor Configuration

public sealed record QueueProcessorConfig
{
    public int      MaxConcurrentDeliveries     { get; init; } = 10;
    public int      MaxDeliveriesPerDomain      { get; init; } = 5;
    public int      DomainCooldownSeconds       { get; init; } = 60;
    public bool     SendDelayNotifications      { get; init; } = true;
    public TimeSpan DelayNotificationAfter      { get; init; } = TimeSpan.FromHours(4);
}

#endregion

#region Queue Processor

/// <summary>
/// Event-based queue processor using Channel&lt;T&gt; for zero-latency delivery.
/// No polling - reacts immediately when new mail is queued.
/// </summary>
public sealed class QueueProcessor : IAsyncDisposable
{
    private readonly IMailQueue _queue;
    private readonly SmtpOutboundClient _outboundClient;
    private readonly BounceHandler _bounceHandler;
    private readonly QueueProcessorConfig _config;
    private readonly ILogger _logger;

    private readonly SemaphoreSlim _deliverySemaphore;
    private readonly ConcurrentDictionary<string, DateTime> _domainLastSend = new();
    private readonly ConcurrentDictionary<string, int> _domainSendCount = new();
    private readonly ConcurrentDictionary<string, bool> _processingIds = new();
    private readonly HashSet<string> _delayNotificationsSent = [];

    private CancellationTokenSource? _cts;
    private Task? _newMailTask;
    private Task? _retryCheckTask;

    public bool IsRunning { get; private set; }
    public int ActiveDeliveries => _config.MaxConcurrentDeliveries - _deliverySemaphore.CurrentCount;

    public QueueProcessor(
        IMailQueue              queue,
        SmtpOutboundClient      outboundClient,
        BounceHandler           bounceHandler,
        QueueProcessorConfig?   config,
        ILogger                 logger)
    {
        _queue = queue;
        _outboundClient = outboundClient;
        _bounceHandler = bounceHandler;
        _config = config ?? new QueueProcessorConfig();
        _logger = logger;
        _deliverySemaphore = new SemaphoreSlim(_config.MaxConcurrentDeliveries);
    }

    public Task StartAsync(CancellationToken ct = default)
    {
        if (IsRunning)
            return Task.CompletedTask;

        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        
        // Start two parallel consumers:
        // 1. New mail consumer - reacts immediately to new mails
        // 2. Retry check consumer - handles deferred mails ready for retry
        _newMailTask = ConsumeNewMailsAsync(_cts.Token);
        _retryCheckTask = ConsumeRetryChecksAsync(_cts.Token);
        
        IsRunning = true;

        _logger.Log(LogLevel.Info, $"Queue processor started (event-based, max {_config.MaxConcurrentDeliveries} concurrent)");

        return Task.CompletedTask;
    }

    public async Task StopAsync()
    {
        if (!IsRunning)
            return;

        _logger.Log(LogLevel.Info, "Stopping queue processor...");

        _cts?.Cancel();
        
        // Wait for both consumers to complete
        var tasks = new List<Task>();
        if (_newMailTask is not null) tasks.Add(_newMailTask);
        if (_retryCheckTask is not null) tasks.Add(_retryCheckTask);

        try
        {
            await Task.WhenAll(tasks);
        }
        catch (OperationCanceledException)
        {
            // Expected
        }

        IsRunning = false;
        _logger.Log(LogLevel.Info, "Queue processor stopped");
    }

    /// <summary>
    /// Consumes new mails from the channel - zero latency delivery
    /// </summary>
    private async Task ConsumeNewMailsAsync(CancellationToken ct)
    {
        _logger.Log(LogLevel.Debug, "New mail consumer started");

        try
        {
            await foreach (var mail in _queue.NewMailReader.ReadAllAsync(ct))
            {
                // Skip if already being processed (deduplication)
                if (!_processingIds.TryAdd(mail.Id, true))
                {
                    _logger.Log(LogLevel.Debug, $"Skipping duplicate: {mail.Id}");
                    continue;
                }

                // Check domain rate limiting
                if (!CanSendToDomain(mail.TargetDomain))
                {
                    _logger.Log(LogLevel.Debug, $"Rate limited, deferring: {mail.Id} to {mail.TargetDomain}");
                    _processingIds.TryRemove(mail.Id, out _);
                    
                    // Defer for later
                    mail.Status = QueueItemStatus.Deferred;
                    mail.NextRetry = DateTime.UtcNow.AddSeconds(_config.DomainCooldownSeconds);
                    await _queue.UpdateAsync(mail, ct);
                    continue;
                }

                // Start delivery in background (fire and forget with semaphore control)
                _ = DeliverWithSemaphoreAsync(mail, ct);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            _logger.Log(LogLevel.Debug, "New mail consumer stopped");
        }
        catch (ChannelClosedException)
        {
            _logger.Log(LogLevel.Debug, "New mail channel closed");
        }
    }

    /// <summary>
    /// Consumes retry check signals - handles deferred mails
    /// </summary>
    private async Task ConsumeRetryChecksAsync(CancellationToken ct)
    {
        _logger.Log(LogLevel.Debug, "Retry check consumer started");

        try
        {
            await foreach (var _ in _queue.RetryCheckReader.ReadAllAsync(ct))
            {
                await ProcessDeferredMailsAsync(ct);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            _logger.Log(LogLevel.Debug, "Retry check consumer stopped");
        }
        catch (ChannelClosedException)
        {
            _logger.Log(LogLevel.Debug, "Retry check channel closed");
        }
    }

    private async Task ProcessDeferredMailsAsync(CancellationToken ct)
    {
        // Reset domain counters
        ResetDomainCounters();

        var deferredMails = await _queue.GetPendingAsync(50, ct);
        
        if (deferredMails.Count == 0)
            return;

        _logger.Log(LogLevel.Debug, $"Processing {deferredMails.Count} deferred mails");

        foreach (var mail in deferredMails)
        {
            if (ct.IsCancellationRequested)
                break;

            // Skip if already being processed
            if (!_processingIds.TryAdd(mail.Id, true))
                continue;

            // Check domain rate limiting
            if (!CanSendToDomain(mail.TargetDomain))
            {
                _processingIds.TryRemove(mail.Id, out _);
                continue;
            }

            _ = DeliverWithSemaphoreAsync(mail, ct);
        }
    }

    private async Task DeliverWithSemaphoreAsync(QueuedMail mail, CancellationToken ct)
    {
        await _deliverySemaphore.WaitAsync(ct);
        try
        {
            await DeliverMailAsync(mail, ct);
        }
        finally
        {
            _deliverySemaphore.Release();
            _processingIds.TryRemove(mail.Id, out _);
        }
    }

    private async Task DeliverMailAsync(QueuedMail mail, CancellationToken ct)
    {
        try
        {
            RecordDomainSend(mail.TargetDomain);

            // Mark as processing
            mail.Status = QueueItemStatus.Processing;
            await _queue.UpdateAsync(mail, ct);

            _logger.Log(LogLevel.Info, $"→ Delivering {mail.Id} to {mail.TargetDomain} (attempt {mail.RetryCount + 1})");

            var result = await _outboundClient.SendAsync(
                mail.TargetDomain,
                mail.EnvelopeFrom,
                mail.EnvelopeTo,
                mail.MessageContent,
                mail.RequireTls,
                ct
            );

            await HandleDeliveryResultAsync(mail, result, ct);
        }
        catch (Exception ex)
        {
            _logger.Log(LogLevel.Error, $"Delivery exception for {mail.Id}: {ex.Message}");
            
            mail.LastError = ex.Message;
            mail.RetryCount++;
            mail.NextRetry = RetryCalculator.GetNextRetryTime(mail.RetryCount);
            mail.Status = QueueItemStatus.Deferred;
            
            await _queue.UpdateAsync(mail, ct);
        }
    }

    private async Task HandleDeliveryResultAsync(QueuedMail mail, SendResult result, CancellationToken ct)
    {
        switch (result.Status)
        {
            case SendStatus.Success:
                _logger.Log(LogLevel.Info, 
                    $"✓ Delivered {mail.Id} via {result.RemoteMx} in {result.Duration?.TotalMilliseconds:F0}ms");
                
                mail.Status = QueueItemStatus.Delivered;
                mail.DeliveredAt = DateTime.UtcNow;
                mail.RemoteMx = result.RemoteMx;
                mail.RemoteResponse = result.ResponseText;
                
                await _queue.UpdateAsync(mail, ct);
                break;

            case SendStatus.TempFail:
                mail.RetryCount++;
                mail.LastError = $"{result.ResponseCode} {result.ResponseText}";
                mail.RemoteMx = result.RemoteMx;

                if (RetryCalculator.ShouldGiveUp(mail))
                {
                    _logger.Log(LogLevel.Warning, 
                        $"✗ Giving up on {mail.Id} after {mail.RetryCount} attempts: {mail.LastError}");
                    
                    mail.Status = QueueItemStatus.Failed;
                    await _queue.UpdateAsync(mail, ct);
                    
                    await _bounceHandler.SendBounceAsync(mail, result, ct);
                }
                else
                {
                    mail.NextRetry = RetryCalculator.GetNextRetryTime(mail.RetryCount);
                    mail.Status = QueueItemStatus.Deferred;
                    
                    _logger.Log(LogLevel.Warning, 
                        $"↻ Deferred {mail.Id}: {mail.LastError} (retry #{mail.RetryCount} at {mail.NextRetry:HH:mm:ss})");
                    
                    await _queue.UpdateAsync(mail, ct);

                    // Send delay notification if applicable
                    if (_config.SendDelayNotifications && 
                        !_delayNotificationsSent.Contains(mail.Id) &&
                        DateTime.UtcNow - mail.QueuedAt > _config.DelayNotificationAfter)
                    {
                        await _bounceHandler.SendDelayNotificationAsync(mail, ct);
                        _delayNotificationsSent.Add(mail.Id);
                    }
                }
                break;

            case SendStatus.PermFail:
                _logger.Log(LogLevel.Warning, 
                    $"✗ Permanent failure {mail.Id}: {result.ResponseCode} {result.ResponseText}");
                
                mail.Status = QueueItemStatus.Failed;
                mail.LastError = $"{result.ResponseCode} {result.ResponseText}";
                mail.RemoteMx = result.RemoteMx;
                
                await _queue.UpdateAsync(mail, ct);
                
                await _bounceHandler.SendBounceAsync(mail, result, ct);
                break;
        }
    }

    #region Domain Rate Limiting

    private bool CanSendToDomain(string domain)
    {
        // Check cooldown
        if (_domainLastSend.TryGetValue(domain, out var lastSend))
        {
            var elapsed = DateTime.UtcNow - lastSend;
            if (elapsed < TimeSpan.FromSeconds(_config.DomainCooldownSeconds))
            {
                return false;
            }
        }

        // Check per-domain limit
        if (_domainSendCount.TryGetValue(domain, out var count))
        {
            if (count >= _config.MaxDeliveriesPerDomain)
            {
                return false;
            }
        }

        return true;
    }

    private void RecordDomainSend(string domain)
    {
        _domainLastSend[domain] = DateTime.UtcNow;
        _domainSendCount.AddOrUpdate(domain, 1, (_, c) => c + 1);
    }

    private void ResetDomainCounters()
    {
        var threshold = DateTime.UtcNow.AddSeconds(-_config.DomainCooldownSeconds * 2);
        
        foreach (var kvp in _domainLastSend)
        {
            if (kvp.Value < threshold)
            {
                _domainSendCount.TryRemove(kvp.Key, out _);
            }
        }
    }

    #endregion

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        _cts?.Dispose();
        _deliverySemaphore.Dispose();
    }
}

#endregion

#region Queue Statistics

public sealed record QueueStatistics(
    int     PendingCount,
    int     ProcessingCount,
    int     DeferredCount,
    int     FailedCount,
    int     DeliveredCount,
    int     TotalCount
);

public static class QueueStatisticsExtensions
{
    public static async Task<QueueStatistics> GetStatisticsAsync(this IMailQueue queue, CancellationToken ct = default)
    {
        var pending = await queue.GetQueueLengthAsync(ct);
        var failed = (await queue.GetFailedAsync(1000, ct)).Count;

        return new QueueStatistics(
            PendingCount: pending,
            ProcessingCount: 0,
            DeferredCount: 0,
            FailedCount: failed,
            DeliveredCount: 0,
            TotalCount: pending + failed
        );
    }
}

#endregion
