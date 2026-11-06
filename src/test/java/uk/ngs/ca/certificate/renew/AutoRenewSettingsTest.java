package uk.ngs.ca.certificate.renew;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import static org.junit.Assert.*;

public class AutoRenewSettingsTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    @Test
    public void defaultsAreOffThirtyDaysAndUpdateGlobus() {
        AutoRenewSettings s = new AutoRenewSettings(tmp.getRoot().toPath().resolve("none.properties"));
        assertFalse(s.isEnabled());
        assertEquals(Duration.ofDays(30), s.getWindow());
        assertTrue(s.isUpdateGlobus());
    }

    @Test
    public void enabledIsPersisted() throws Exception {
        Path f = tmp.getRoot().toPath().resolve("s.properties");
        new AutoRenewSettings(f).setEnabled(true);
        assertTrue(new AutoRenewSettings(f).isEnabled());
    }

    @Test
    public void windowIsClampedToSaneValues() throws Exception {
        Path f = tmp.getRoot().toPath().resolve("s.properties");
        Files.writeString(f, "autorenew.windowDays=1000\n");
        assertEquals(Duration.ofDays(56), new AutoRenewSettings(f).getWindow());
        Files.writeString(f, "autorenew.windowDays=1\n");
        assertEquals(Duration.ofDays(7), new AutoRenewSettings(f).getWindow());
        Files.writeString(f, "autorenew.windowDays=junk\n");
        assertEquals(Duration.ofDays(30), new AutoRenewSettings(f).getWindow());
    }
}
