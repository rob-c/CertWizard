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

import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * One capture server per JVM. Some client classes copy endpoint URLs into
 * static final fields when first loaded (e.g.
 * {@code OnlineCertRenewRequest.CSRURL}), so every test must see the same
 * port.
 */
public final class SharedCaptureServer {

    private static RawHttpCaptureServer server;

    private SharedCaptureServer() {
    }

    public static synchronized RawHttpCaptureServer get() {
        if (server == null) {
            try {
                server = new RawHttpCaptureServer();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            TestConfig.pointAllEndpointsAt(server.baseUrl());
        }
        server.reset();
        return server;
    }
}
