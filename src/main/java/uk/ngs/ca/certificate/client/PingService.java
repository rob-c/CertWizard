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
package uk.ngs.ca.certificate.client;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.ngs.ca.common.CaHttpClient;
import uk.ngs.ca.common.CaHttpRequest;
import uk.ngs.ca.common.CaHttpResponse;
import uk.ngs.ca.common.ConnectivityMonitor;
import uk.ngs.ca.tools.property.SysProperty;

import java.io.IOException;

/**
 * Ping the server.
 *
 * @author xw75
 */
public final class PingService {

    private static final Logger logger = LogManager.getLogger(PingService.class);

    private PingService() {  // force non-instantiation with private constructor.
    }

    /**
     * Get the shared, thread safe PingService instance.
     *
     * @return
     */
    public static PingService getPingService() {
        return PingServiceHolder.pingService;
    }

    /**
     * PingServiceHolder is loaded on the first execution of
     * PingService.getInstance() or the first access to
     * PingServiceHolder.pingService, not before.
     */
    private static class PingServiceHolder {

        public static final PingService pingService = new PingService();
    }

    /**
     * Ping the CA server now and update the application's online status
     * (via {@link ConnectivityMonitor#checkNow()}, which also re-schedules
     * the automatic checks and shares one ping between concurrent callers).
     * Blocks for up to the connect timeout: never call on the Swing EDT.
     *
     * @return true if successful ping otherwise false.
     */
    public boolean isPingService() {
        return ConnectivityMonitor.getInstance().checkNow();
    }

    /**
     * Send one ping request (no retries; the connectivity monitor provides
     * the backoff) and report whether the server answered 200 OK. Does not
     * update any state and is never short-circuited by the offline state.
     *
     * @return true if the server answered 200, false for any other status
     * @throws IOException if no response was received
     */
    public boolean ping() throws IOException {
        String pingURL = SysProperty.getValue("uk.ngs.ca.request.pingservice.url");
        logger.debug("pinging URL [" + pingURL + "]");
        CaHttpRequest request = CaHttpRequest.get(pingURL)
                .maxAttempts(1)
                .connectivityProbe()
                .build();
        CaHttpResponse response = CaHttpClient.getDefault().send(request);
        return response.getStatusCode() == 200;
    }
}
