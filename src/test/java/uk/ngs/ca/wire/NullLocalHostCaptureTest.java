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
import org.restlet.Client;
import org.restlet.Request;
import org.restlet.data.Header;
import org.restlet.data.Method;
import org.restlet.data.Reference;
import org.restlet.util.Series;
import uk.ngs.ca.common.RestletClient;
import uk.ngs.ca.tools.property.SysProperty;

/**
 * {@code ClientHostName.getHostName()} returns null when the local host name
 * cannot be resolved. This records what the original implementation put on
 * the wire in that case, using exactly the header-setting code the client
 * classes used, so the replacement can be held to the same behaviour.
 */
public class NullLocalHostCaptureTest {

    @Test
    public void nullLocalHostHeader() throws Exception {
        RawHttpCaptureServer server = SharedCaptureServer.get();
        server.enqueue(new RawHttpCaptureServer.Reply(200, "OK"));

        Client client = RestletClient.getClient();
        Request request = new Request(Method.GET, new Reference(SysProperty.getValue("uk.ngs.ca.request.pingservice.url")));
        Series<Header> headers = request.getHeaders();
        headers.set("LocalHost", null);
        org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
        info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));
        request.setClientInfo(info);
        client.handle(request);

        GoldenFixture.check("null-localhost", server.getCaptured(), false);
    }
}
