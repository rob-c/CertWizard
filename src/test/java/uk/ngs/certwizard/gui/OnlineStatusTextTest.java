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
package uk.ngs.certwizard.gui;

import org.junit.Test;
import uk.ngs.ca.common.ConnectivityMonitor;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class OnlineStatusTextTest {

    @Test
    public void formatsTheRetryCountdown() {
        assertEquals("0s", OnlineStatus.formatDelay(0));
        assertEquals("45s", OnlineStatus.formatDelay(45));
        assertEquals("2m 05s", OnlineStatus.formatDelay(125));
        assertEquals("10m 00s", OnlineStatus.formatDelay(600));
    }

    @Test
    public void describesEachState() {
        Instant now = Instant.parse("2026-11-06T12:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        List<Runnable> scheduled = new ArrayList<>();
        ConnectivityMonitor m = new ConnectivityMonitor(() -> {
            throw new java.net.ConnectException();
        }, (task, delay) -> {
            scheduled.add(task);
            return () -> { };
        }, clock, Duration.ofMinutes(10), Duration.ofSeconds(15), Duration.ofMinutes(10), b -> { });

        assertEquals("Not yet checked.", OnlineStatus.describe(m.getStatus(), now));

        m.start();
        scheduled.get(0).run(); // first check fails
        String offline = OnlineStatus.describe(m.getStatus(), now.plusSeconds(5));
        assertEquals("Offline - cannot reach the CA server. Retrying in 10s, or click refresh to retry now.", offline);

        m.reportReachable();
        assertTrue(OnlineStatus.describe(m.getStatus(), now).startsWith("Online (last checked at "));
    }
}
