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

import uk.ngs.ca.tools.property.SysProperty;

import java.lang.reflect.Field;
import java.util.Properties;

/**
 * Overrides values loaded from configure.properties for the current JVM.
 * Uses reflection so no test-only hooks are needed in production code.
 */
public final class TestConfig {

    private TestConfig() {
    }

    public static void set(String key, String value) {
        properties().setProperty(key, value);
    }

    private static Properties properties() {
        try {
            SysProperty.getValue("ngsca.certwizard.version"); // force lazy load first
            Field f = SysProperty.class.getDeclaredField("properties");
            f.setAccessible(true);
            return (Properties) f.get(null);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Point every CA endpoint at the given base URL (keeping the production
     * paths).
     */
    public static void pointAllEndpointsAt(String baseUrl) {
        set("uk.ngs.ca.request.csr.url", baseUrl + "/CSR");
        set("uk.ngs.ca.request.ca.url", baseUrl + "/CA");
        set("uk.ngs.ca.request.ca.motd.text.url", baseUrl + "/CA/motd/text");
        set("uk.ngs.ca.request.resource.publickey", baseUrl + "/resources/resource/publickey");
        set("uk.ngs.ca.request.certificate.url", baseUrl + "/certificate");
        set("uk.ngs.ca.request.revoke.url", baseUrl + "/revoke");
        set("uk.ngs.ca.request.pingservice.url", baseUrl + "/pingservice");
        set("uk.ngs.ca.request.bulkhost.reqid.url", baseUrl + "/CSRs");
    }
}
