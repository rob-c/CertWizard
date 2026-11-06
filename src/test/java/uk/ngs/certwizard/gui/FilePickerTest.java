package uk.ngs.certwizard.gui;

import org.junit.Test;

import java.io.File;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

/**
 * Tests for the non-GUI logic in {@link FilePicker}. No dialogs are shown.
 */
public class FilePickerTest {

    private static final File DIR = new File("exports");

    @Test
    public void appendsDefaultExtensionWhenNameHasNone() {
        assertEquals(new File(DIR, "mycert.p12"), FilePicker.withDefaultExtension(new File(DIR, "mycert"), "p12"));
    }

    @Test
    public void appendsExtensionWithoutDoublingATrailingDot() {
        assertEquals(new File(DIR, "mycert.p12"), FilePicker.withDefaultExtension(new File(DIR, "mycert."), "p12"));
    }

    @Test
    public void keepsTheDefaultExtension() {
        File file = new File(DIR, "mycert.p12");
        assertSame(file, FilePicker.withDefaultExtension(file, "p12"));
    }

    @Test
    public void keepsAnyExtensionTheUserTyped() {
        File pfx = new File(DIR, "mycert.pfx");
        File key = new File(DIR, "userkey.key");
        assertSame(pfx, FilePicker.withDefaultExtension(pfx, "p12"));
        assertSame(key, FilePicker.withDefaultExtension(key, "pem"));
    }

    @Test
    public void leadingDotIsNotAnExtension() {
        assertEquals(new File(DIR, ".mycert.pem"), FilePicker.withDefaultExtension(new File(DIR, ".mycert"), "pem"));
    }

    @Test
    public void dotInDirectoryNameIsIgnored() {
        File dir = new File("my.folder");
        assertEquals(new File(dir, "mycert.cer"), FilePicker.withDefaultExtension(new File(dir, "mycert"), "cer"));
    }

    @Test
    public void fileWithoutParentKeepsNoParent() {
        assertEquals(new File("mycert.p7b"), FilePicker.withDefaultExtension(new File("mycert"), "p7b"));
    }

    @Test
    public void nullInputsAreHandled() {
        assertNull(FilePicker.withDefaultExtension(null, "p12"));
        File file = new File(DIR, "mycert");
        assertSame(file, FilePicker.withDefaultExtension(file, null));
        assertSame(file, FilePicker.withDefaultExtension(file, ""));
    }

    @Test
    public void suggestedFileNameReplacesUnsafeCharacters() {
        assertEquals("John_Smith.p12", FilePicker.suggestedFileName("John Smith", "p12"));
        assertEquals("CN_John_Smith_O_eScience.pem", FilePicker.suggestedFileName("CN=John Smith, O=eScience", "pem"));
    }

    @Test
    public void suggestedFileNameMatchesPortecleRules() {
        // Digits are not letters, so Portecle's rule replaces them too.
        assertEquals("user.p12", FilePicker.suggestedFileName("  user 123  ", "p12"));
        assertEquals("a-b_c.cer", FilePicker.suggestedFileName("__a-b___c__", "cer"));
        assertEquals("Zoë.pem", FilePicker.suggestedFileName("Zoë", "pem"));
    }

    @Test
    public void suggestedFileNameIsNullWhenNothingSensibleRemains() {
        assertNull(FilePicker.suggestedFileName(null, "p12"));
        assertNull(FilePicker.suggestedFileName("", "p12"));
        assertNull(FilePicker.suggestedFileName("1234 ..", "p12"));
    }

    @Test
    public void nativeDialogsOnlyOnMac() {
        assertTrue(FilePicker.useNativeDialogs("Mac OS X", null));
        assertFalse(FilePicker.useNativeDialogs("Windows 11", null));
        assertFalse(FilePicker.useNativeDialogs("Linux", null));
        assertFalse(FilePicker.useNativeDialogs(null, null));
    }

    @Test
    public void swingOverrideDisablesNativeDialogs() {
        assertFalse(FilePicker.useNativeDialogs("Mac OS X", "swing"));
        assertFalse(FilePicker.useNativeDialogs("Mac OS X", " Swing "));
        assertTrue(FilePicker.useNativeDialogs("Mac OS X", "something-else"));
        assertFalse(FilePicker.useNativeDialogs("Linux", "native"));
    }

    @Test
    public void overwriteIsNotConfirmedForUnrelatedFiles() {
        assertFalse(FilePicker.isOverwriteConfirmed(null));
        assertFalse(FilePicker.isOverwriteConfirmed(new File(DIR, "never-chosen.p12")));
    }
}
