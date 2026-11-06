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

/**
 * What {@link CaHttpClient} needs from the online/offline state: whether to
 * fail fast, and somewhere to report what it observed.
 */
public interface ConnectivityTracker {

    /** True when the server is known to be unreachable right now. */
    boolean isKnownOffline();

    /** User-facing explanation used when failing fast while offline. */
    String describeOffline();

    /** An HTTP response (any status) was received from the server. */
    void reportReachable();

    /**
     * A request gave up because the server could not be reached at all.
     *
     * @param reason user-readable description of the failure
     */
    void reportUnreachable(String reason);
}
