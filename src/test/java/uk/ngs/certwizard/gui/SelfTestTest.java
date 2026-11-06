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
import uk.ngs.ca.common.SystemStatus;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Runs the {@code --self-test} checks in-process, so that {@code mvn test}
 * covers them on every CI platform and not only in the packaged macOS app.
 */
public class SelfTestTest {

    @Test
    public void selfTestPassesWithoutTouchingUserDataDirectory() {
        File userDataDirectory = SystemStatus.getInstance().getCwDataDirectory();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();

        int status = SelfTest.run(new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8));

        String stdout = out.toString(StandardCharsets.UTF_8);
        assertEquals("self-test failed: " + err.toString(StandardCharsets.UTF_8), 0, status);
        assertTrue(stdout, stdout.startsWith("CertWizard self-test OK: "));
        assertTrue(stdout, stdout.contains("truststore holds 2 CA certs"));
        assertEquals(userDataDirectory, SystemStatus.getInstance().getCwDataDirectory());
    }
}
