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

import org.junit.Test;
import uk.ngs.ca.common.CaHttpClient;
import uk.ngs.ca.common.CaHttpRequest;
import uk.ngs.ca.tools.property.SysProperty;

/**
 * {@code ClientHostName.getHostName()} returns null when the local host name
 * cannot be resolved. The fixture records what the original Restlet
 * implementation put on the wire in that case (an empty "LocalHost:"
 * header); this drives the same header-setting call that
 * {@link CaHttpRequest#get(String)} makes with a null host name.
 */
public class NullLocalHostCaptureTest {

    @Test
    public void nullLocalHostHeader() throws Exception {
        RawHttpCaptureServer server = SharedCaptureServer.get();
        server.enqueue(new RawHttpCaptureServer.Reply(200, "OK"));

        CaHttpRequest request = CaHttpRequest.get(SysProperty.getValue("uk.ngs.ca.request.pingservice.url"))
                .header("LocalHost", null)
                .build();
        CaHttpClient.getDefault().send(request);

        GoldenFixture.check("null-localhost", server.getCaptured(), false);
    }
}
