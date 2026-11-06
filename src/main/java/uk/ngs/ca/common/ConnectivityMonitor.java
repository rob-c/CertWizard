/*
 * CertWizard - UK eScience CA Certificate Management Client
 * Copyright (C) 2021 UKRI-STFC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package uk.ngs.ca.common;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.ngs.ca.certificate.client.PingService;
import uk.ngs.ca.tools.property.SysProperty;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Tracks whether the CA server is reachable and schedules the online checks
 * (pings).
 * <ul>
 * <li>While online, the server is re-checked every
 * {@code uk.ngs.ca.online.check.interval.secs} (default 600s, as before).</li>
 * <li>While offline, re-checks back off: 15s, 30s, 1m, 2m, 4m, 8m, then every
 * 10m ({@code uk.ngs.ca.offline.recheck.initial.secs} doubling up to
 * {@code uk.ngs.ca.offline.recheck.max.secs}). The first success returns to
 * the normal cadence.</li>
 * <li>{@link #checkNow()} re-checks immediately (blocking; concurrent callers
 * share one ping) and {@link #checkSoon()} does so in the background - use
 * them before user-initiated online actions and for a "retry now" button.</li>
 * <li>Requests through {@link CaHttpClient} report what they observe, so a
 * failed request flips the state to offline straight away (and later
 * requests fail fast) without waiting for the next ping.</li>
 * </ul>
 * Every result is also pushed to {@link SystemStatus#setIsOnline(boolean)}.
 * Listeners receive a {@link Status} snapshot on every change; they are
 * called on whichever thread caused the change.
 */
public final class ConnectivityMonitor implements ConnectivityTracker {

    private static final Logger logger = LogManager.getLogger(ConnectivityMonitor.class);

    public enum State {
        /** No check has completed yet. */
        UNKNOWN,
        ONLINE,
        OFFLINE
    }

    /** One connectivity check. */
    @FunctionalInterface
    public interface Probe {

        /**
         * @return true if the server answered correctly, false if it answered
         * with an error
         * @throws IOException if no answer was received
         */
        boolean isServerReachable() throws IOException;
    }

    /** Runs a task after a delay; replaceable for tests. */
    @FunctionalInterface
    public interface Scheduler {

        Cancellable schedule(Runnable task, Duration delay);
    }

    @FunctionalInterface
    public interface Cancellable {

        void cancel();
    }

    /** Immutable snapshot of the monitor's state. */
    public static final class Status {

        private final State state;
        private final boolean checking;
        private final Instant lastCheck;
        private final Instant nextCheck;
        private final int consecutiveFailures;
        private final String lastError;

        Status(State state, boolean checking, Instant lastCheck, Instant nextCheck, int consecutiveFailures, String lastError) {
            this.state = state;
            this.checking = checking;
            this.lastCheck = lastCheck;
            this.nextCheck = nextCheck;
            this.consecutiveFailures = consecutiveFailures;
            this.lastError = lastError;
        }

        public State getState() {
            return state;
        }

        /** True while a check is in progress. */
        public boolean isChecking() {
            return checking;
        }

        /** When the last check (or observed request outcome) happened, or null. */
        public Instant getLastCheck() {
            return lastCheck;
        }

        /** When the next automatic check is due, or null if none is scheduled. */
        public Instant getNextCheck() {
            return nextCheck;
        }

        public int getConsecutiveFailures() {
            return consecutiveFailures;
        }

        /** Why the server is considered unreachable, or null. */
        public String getLastError() {
            return lastError;
        }

        /** Whole seconds (rounded up) until the next automatic check, or -1. */
        public long secondsUntilNextCheck(Instant now) {
            if (nextCheck == null) {
                return -1;
            }
            long ms = Duration.between(now, nextCheck).toMillis();
            return ms <= 0 ? 0 : (ms + 999) / 1000;
        }

        @Override
        public String toString() {
            return state + (checking ? " (checking)" : "") + ", failures=" + consecutiveFailures
                    + ", next=" + nextCheck + (lastError == null ? "" : ", error=" + lastError);
        }
    }

    private final Probe probe;
    private final Scheduler scheduler;
    private final Clock clock;
    private final Duration onlineInterval;
    private final Duration offlineInitial;
    private final Duration offlineMax;
    private final Consumer<Boolean> onlineSink;
    private final List<Consumer<Status>> listeners = new CopyOnWriteArrayList<>();

    // guarded by this
    private State state = State.UNKNOWN;
    private boolean started;
    private int consecutiveFailures;
    private Instant lastCheck;
    private Instant nextCheck;
    private String lastError;
    private Cancellable pending;
    private CompletableFuture<Boolean> inFlight;

    /**
     * @param probe          the connectivity check (a single ping, no retries)
     * @param scheduler      runs scheduled checks
     * @param clock          time source
     * @param onlineInterval delay between checks while online
     * @param offlineInitial first re-check delay after going offline
     * @param offlineMax     cap for the offline re-check delay
     * @param onlineSink     receives every online/offline result
     */
    public ConnectivityMonitor(Probe probe, Scheduler scheduler, Clock clock, Duration onlineInterval,
                               Duration offlineInitial, Duration offlineMax, Consumer<Boolean> onlineSink) {
        this.probe = probe;
        this.scheduler = scheduler;
        this.clock = clock;
        this.onlineInterval = onlineInterval;
        this.offlineInitial = offlineInitial;
        this.offlineMax = offlineMax;
        this.onlineSink = onlineSink;
    }

    private static final class Holder {

        static final ConnectivityMonitor INSTANCE = new ConnectivityMonitor(
                () -> PingService.getPingService().ping(),
                executorScheduler(),
                Clock.systemUTC(),
                Duration.ofSeconds(Math.max(1, SysProperty.getInt("uk.ngs.ca.online.check.interval.secs", 600))),
                Duration.ofSeconds(Math.max(1, SysProperty.getInt("uk.ngs.ca.offline.recheck.initial.secs", 15))),
                Duration.ofSeconds(Math.max(1, SysProperty.getInt("uk.ngs.ca.offline.recheck.max.secs", 600))),
                online -> SystemStatus.getInstance().setIsOnline(online));
    }

    /** The application-wide monitor (pings via {@link PingService}). */
    public static ConnectivityMonitor getInstance() {
        return Holder.INSTANCE;
    }

    private static Scheduler executorScheduler() {
        ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ca-connectivity-monitor");
            t.setDaemon(true);
            return t;
        });
        return (task, delay) -> {
            ScheduledFuture<?> f = exec.schedule(task, delay.toMillis(), TimeUnit.MILLISECONDS);
            return () -> f.cancel(false);
        };
    }

    /**
     * The re-check delay after {@code consecutiveFailures} failed checks:
     * initial, doubling, capped at max.
     */
    public static Duration offlineDelay(int consecutiveFailures, Duration initial, Duration max) {
        long ms = initial.toMillis();
        for (int i = 1; i < consecutiveFailures && ms < max.toMillis(); i++) {
            ms *= 2;
        }
        return Duration.ofMillis(Math.min(ms, max.toMillis()));
    }

    /** Start automatic checking, beginning with an immediate check. Idempotent. */
    public void start() {
        synchronized (this) {
            if (started) {
                return;
            }
            started = true;
        }
        checkSoon();
    }

    /** Run a check in the background as soon as possible. */
    public void checkSoon() {
        synchronized (this) {
            cancelPendingLocked();
            nextCheck = clock.instant();
            pending = scheduler.schedule(this::checkNow, Duration.ZERO);
        }
        notifyListeners();
    }

    /**
     * Check connectivity now and wait for the result. If a check is already
     * running, waits for that one instead of pinging again. Blocks for up to
     * the connect/request timeout, so never call this on the Swing EDT.
     *
     * @return true if the server is reachable
     */
    public boolean checkNow() {
        CompletableFuture<Boolean> mine;
        CompletableFuture<Boolean> existing;
        synchronized (this) {
            existing = inFlight;
            mine = existing == null ? new CompletableFuture<>() : null;
            if (existing == null) {
                inFlight = mine;
                cancelPendingLocked();
                nextCheck = null;
            }
        }
        if (existing != null) {
            return existing.join();
        }
        notifyListeners();

        boolean reachable = false;
        String error = null;
        try {
            reachable = probe.isServerReachable();
            if (!reachable) {
                error = "the CA server did not answer the connection check correctly";
            }
        } catch (IOException e) {
            error = e.getMessage();
        } catch (RuntimeException e) {
            logger.error("Connectivity check failed unexpectedly", e);
            error = e.toString();
        } finally {
            synchronized (this) {
                inFlight = null;
                record(reachable, error);
            }
        }
        logger.info("CA server connectivity check: " + (reachable ? "online" : "offline - " + error));
        onlineSink.accept(reachable);
        notifyListeners();
        mine.complete(reachable);
        return reachable;
    }

    // ------------------------------------------------------------ ConnectivityTracker

    @Override
    public synchronized boolean isKnownOffline() {
        return state == State.OFFLINE;
    }

    @Override
    public String describeOffline() {
        Status s = getStatus();
        StringBuilder sb = new StringBuilder("The CA server cannot be reached at the moment");
        if (s.getLastError() != null) {
            sb.append(": ").append(s.getLastError());
        } else {
            sb.append('.');
        }
        long secs = s.secondsUntilNextCheck(clock.instant());
        if (secs >= 0) {
            sb.append("\nCertWizard will check the connection again automatically in ").append(secs)
                    .append("s, or use the refresh button next to the online status to check now.");
        }
        return sb.toString();
    }

    @Override
    public void reportReachable() {
        synchronized (this) {
            if (state == State.ONLINE || inFlight != null) {
                return; // nothing new, or a check in progress will decide
            }
            record(true, null);
        }
        onlineSink.accept(true);
        notifyListeners();
    }

    @Override
    public void reportUnreachable(String reason) {
        synchronized (this) {
            if (state == State.OFFLINE || inFlight != null) {
                return; // keep the existing backoff, or let the running check decide
            }
            record(false, reason);
        }
        onlineSink.accept(false);
        notifyListeners();
    }

    // ------------------------------------------------------------ state

    public synchronized Status getStatus() {
        return new Status(state, inFlight != null, lastCheck, nextCheck, consecutiveFailures, lastError);
    }

    public void addListener(Consumer<Status> listener) {
        listeners.add(listener);
    }

    public void removeListener(Consumer<Status> listener) {
        listeners.remove(listener);
    }

    /** Record an outcome and schedule the next check. Caller holds the lock. */
    private void record(boolean reachable, String error) {
        lastCheck = clock.instant();
        if (reachable) {
            state = State.ONLINE;
            consecutiveFailures = 0;
            lastError = null;
        } else {
            state = State.OFFLINE;
            consecutiveFailures++;
            lastError = error;
        }
        cancelPendingLocked();
        if (!started) {
            nextCheck = null;
            return;
        }
        Duration delay = reachable ? onlineInterval : offlineDelay(consecutiveFailures, offlineInitial, offlineMax);
        nextCheck = lastCheck.plus(delay);
        pending = scheduler.schedule(this::checkNow, delay);
    }

    private void cancelPendingLocked() {
        if (pending != null) {
            pending.cancel();
            pending = null;
        }
    }

    private void notifyListeners() {
        Status s = getStatus();
        for (Consumer<Status> l : listeners) {
            try {
                l.accept(s);
            } catch (RuntimeException e) {
                logger.warn("Connectivity listener failed", e);
            }
        }
    }
}
