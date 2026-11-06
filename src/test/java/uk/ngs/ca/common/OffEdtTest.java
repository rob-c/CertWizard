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

import org.junit.BeforeClass;
import org.junit.Test;

import javax.swing.SwingUtilities;
import java.security.KeyStoreException;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;

/**
 * Runs headless: the wait dialog is skipped, but the work must still move
 * off the event dispatch thread and exceptions must come back unchanged.
 */
public class OffEdtTest {

    @BeforeClass
    public static void noWindows() {
        // Never open a window from the tests (only effective if AWT is not yet initialised).
        System.setProperty("java.awt.headless", "true");
    }

    @Test
    public void workCalledOnTheEdtRunsOnAnotherThread() throws Exception {
        AtomicReference<Thread> worker = new AtomicReference<>();
        AtomicReference<Boolean> workerOnEdt = new AtomicReference<>();
        AtomicReference<String> result = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> result.set(OffEdt.call(null, "test", () -> {
            worker.set(Thread.currentThread());
            workerOnEdt.set(SwingUtilities.isEventDispatchThread());
            return "done";
        })));
        assertEquals("done", result.get());
        assertFalse(workerOnEdt.get());
        assertEquals("certwizard-network-call", worker.get().getName());
    }

    @Test
    public void checkedExceptionsAreRethrownUnchanged() throws Exception {
        KeyStoreException thrown = new KeyStoreException("boom");
        AtomicReference<Throwable> caught = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try {
                OffEdt.call(null, "test", () -> {
                    throw thrown;
                });
            } catch (KeyStoreException e) {
                caught.set(e);
            }
        });
        assertSame(thrown, caught.get());

        IllegalStateException unchecked = new IllegalStateException("x");
        SwingUtilities.invokeAndWait(() -> {
            try {
                OffEdt.call(null, "test", () -> {
                    throw unchecked;
                });
            } catch (IllegalStateException e) {
                caught.set(e);
            }
        });
        assertSame(unchecked, caught.get());
    }

    @Test
    public void offTheEdtTheWorkRunsInline() {
        assertFalse(SwingUtilities.isEventDispatchThread());
        Thread ran = OffEdt.call(null, "test", Thread::currentThread);
        assertSame(Thread.currentThread(), ran);
    }
}
