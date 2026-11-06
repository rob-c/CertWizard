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
package uk.ngs.ca.wire;

import uk.ngs.ca.common.CaHttpClient;
import uk.ngs.ca.common.ConnectivityTracker;
import uk.ngs.ca.common.RetryPolicy;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Clients for tests: production retry policy and timeouts short enough for
 * tests, a sleeper that records instead of sleeping, and a fixed jitter
 * value (0.5 = no jitter) so delays are exact.
 */
public final class TestClients {

    private TestClients() {
    }

    /** Records requested delays without sleeping. */
    public static final class RecordingSleeper implements CaHttpClient.Sleeper {

        private final List<Duration> sleeps = Collections.synchronizedList(new ArrayList<>());

        @Override
        public void sleep(Duration duration) {
            sleeps.add(duration);
        }

        public List<Duration> getSleeps() {
            return new ArrayList<>(sleeps);
        }
    }

    public static CaHttpClient withoutTracking(CaHttpClient.Sleeper sleeper) {
        return create(null, sleeper, Clock.systemUTC());
    }

    public static CaHttpClient create(ConnectivityTracker tracker, CaHttpClient.Sleeper sleeper, Clock clock) {
        CaHttpClient.Settings settings = new CaHttpClient.Settings(
                Duration.ofSeconds(2), Duration.ofSeconds(5), RetryPolicy.defaults());
        return new CaHttpClient(settings, tracker, sleeper, clock, () -> 0.5);
    }
}
