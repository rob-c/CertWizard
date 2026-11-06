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
package uk.ngs.ca.certificate.verify;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The outcome of verifying one certificate (and optionally its private key).
 */
public final class VerificationReport {

    /**
     * Severity of a finding, in increasing order of badness.
     */
    public enum Severity {
        PASS, INFO, WARN, FAIL
    }

    /**
     * One check result.
     */
    public static final class Finding {
        private final Severity severity;
        private final String check;
        private final String message;

        public Finding(Severity severity, String check, String message) {
            this.severity = severity;
            this.check = check;
            this.message = message;
        }

        public Severity getSeverity() {
            return severity;
        }

        /**
         * @return short machine-friendly id of the check, e.g. "chain".
         */
        public String getCheck() {
            return check;
        }

        public String getMessage() {
            return message;
        }

        @Override
        public String toString() {
            return severity + " [" + check + "] " + message;
        }
    }

    private final String subject;
    private final List<Finding> findings = new ArrayList<>();

    public VerificationReport(String subject) {
        this.subject = subject;
    }

    void add(Severity s, String check, String message) {
        findings.add(new Finding(s, check, message));
    }

    /**
     * @return the subject DN of the certificate that was verified.
     */
    public String getSubject() {
        return subject;
    }

    public List<Finding> getFindings() {
        return Collections.unmodifiableList(findings);
    }

    /**
     * @param check check id
     * @return findings for the given check
     */
    public List<Finding> findings(String check) {
        List<Finding> out = new ArrayList<>();
        for (Finding f : findings) {
            if (f.check.equals(check)) {
                out.add(f);
            }
        }
        return out;
    }

    /**
     * @return the worst severity of any finding (PASS if there are none).
     */
    public Severity overall() {
        Severity worst = Severity.PASS;
        for (Finding f : findings) {
            if (f.severity.compareTo(worst) > 0) {
                worst = f.severity;
            }
        }
        return worst;
    }

    /**
     * @return plain-text rendering, one finding per line.
     */
    public String toText() {
        StringBuilder sb = new StringBuilder();
        sb.append("Verification of ").append(subject).append(": ").append(overall()).append('\n');
        for (Finding f : findings) {
            sb.append("  ").append(f).append('\n');
        }
        return sb.toString();
    }

    /**
     * @return simple HTML rendering for Swing components.
     */
    public String toHtml() {
        StringBuilder sb = new StringBuilder("<html><body style='font-family:sans-serif'>");
        sb.append("<p><b>").append(escape(subject)).append("</b><br>Overall: ")
                .append(badge(overall())).append("</p><table cellpadding='3'>");
        for (Finding f : findings) {
            sb.append("<tr><td valign='top'>").append(badge(f.severity)).append("</td><td valign='top'><i>")
                    .append(escape(f.check)).append("</i></td><td>").append(escape(f.message).replace("\n", "<br>"))
                    .append("</td></tr>");
        }
        return sb.append("</table></body></html>").toString();
    }

    private static String badge(Severity s) {
        String colour;
        switch (s) {
            case PASS:
                colour = "#1a7f37";
                break;
            case INFO:
                colour = "#0969da";
                break;
            case WARN:
                colour = "#9a6700";
                break;
            default:
                colour = "#cf222e";
        }
        return "<b><font color='" + colour + "'>" + s + "</font></b>";
    }

    private static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
