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

import javax.swing.JFileChooser;
import javax.swing.LookAndFeel;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.FileDialog;
import java.awt.Frame;
import java.awt.Window;
import java.io.File;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * The one place CertWizard asks the user to pick a file or folder.
 * <p>
 * On macOS this shows the native open and save panels through
 * {@link FileDialog}. Elsewhere it shows a {@link JFileChooser} drawn with the
 * platform look and feel; the Windows {@code FileDialog} cannot pick folders
 * and ignores filename filters, so it is not used there. Start CertWizard with
 * {@code -Dcertwizard.filePicker=swing} to use the Swing chooser on macOS too.
 * <p>
 * Dialogs open in the directory chosen by {@link StartDirectoryPolicy}. The
 * directory of the last file picked is remembered for the rest of the session
 * only; nothing is persisted.
 * <p>
 * Call on the event dispatch thread.
 */
public final class FilePicker {

    /** System property that selects the Swing chooser on every platform when set to "swing". */
    static final String BACKEND_PROPERTY = "certwizard.filePicker";

    /** Makes the macOS {@link FileDialog} pick folders instead of files. */
    private static final String MAC_DIRECTORY_MODE = "apple.awt.fileDialogForDirectories";

    /** Runs of characters replaced when turning an alias into a file name (as Portecle's FileChooserFactory does). */
    private static final Pattern FILENAME_FILTER = Pattern.compile("[^\\p{L}_\\-]+");

    /** Directory of the last file picked in this session. */
    private static File sessionDirectory;

    /** File last returned by {@link #saveFile} whose replacement the native save panel already confirmed. */
    private static File overwriteConfirmed;

    private FilePicker() {
    }

    /**
     * Ask the user for an existing file to open.
     *
     * @param parent            component the dialog belongs to, may be null
     * @param title             dialog title
     * @param approveButtonText text for the approve button (Swing chooser only), or null for the default
     * @param filter            file types to offer (Swing chooser only; "All files" stays available)
     * @return the chosen file, or null if the user cancelled
     */
    public static File openFile(Component parent, String title, String approveButtonText,
            FileNameExtensionFilter filter) {
        overwriteConfirmed = null;
        File start = startDirectory(null);
        File chosen;
        if (useNativeDialogs()) {
            // The native panel gets no filter: AWT cannot offer an "All files"
            // choice there, and CertWizard's importers detect the format from the
            // contents, so filtering would block files that open fine (e.g. a PEM
            // bundle named *.key).
            chosen = showNativeDialog(parent, title, FileDialog.LOAD, start, null, null);
        } else {
            JFileChooser chooser = newChooser(start);
            chooser.setDialogType(JFileChooser.OPEN_DIALOG);
            configure(chooser, title, approveButtonText, filter);
            chosen = showChooser(chooser, parent);
        }
        rememberDirectoryOf(chosen);
        return chosen;
    }

    /**
     * Ask the user where to save a file. The first extension of the filter is
     * the default: it is part of the suggested name, and it is appended to the
     * chosen name if the user typed one without an extension.
     * <p>
     * The returned file may already exist. The macOS save panel asks before
     * returning an existing file, the Swing chooser does not, so callers that
     * confirm overwriting should first check {@link #isOverwriteConfirmed}.
     *
     * @param parent            component the dialog belongs to, may be null
     * @param title             dialog title
     * @param approveButtonText text for the approve button (Swing chooser only), or null for the default
     * @param filter            type of file being saved
     * @param suggestedBaseName name to suggest, without extension (e.g. a certificate alias), or null
     * @return the chosen file, or null if the user cancelled
     */
    public static File saveFile(Component parent, String title, String approveButtonText,
            FileNameExtensionFilter filter, String suggestedBaseName) {
        overwriteConfirmed = null;
        String extension = filter.getExtensions()[0];
        String suggestedName = suggestedFileName(suggestedBaseName, extension);
        File start = startDirectory(null);
        File chosen;
        boolean nativeDialog = useNativeDialogs();
        if (nativeDialog) {
            chosen = showNativeDialog(parent, title, FileDialog.SAVE, start, suggestedName, filter);
        } else {
            JFileChooser chooser = newChooser(start);
            chooser.setDialogType(JFileChooser.SAVE_DIALOG);
            configure(chooser, title, approveButtonText, filter);
            if (suggestedName != null) {
                chooser.setSelectedFile(new File(chooser.getCurrentDirectory(), suggestedName));
            }
            chosen = showChooser(chooser, parent);
        }
        if (chosen == null) {
            return null;
        }
        File result = withDefaultExtension(chosen, extension);
        // The native panel only asked about the name it returned, not one we extended.
        if (nativeDialog && result.equals(chosen)) {
            overwriteConfirmed = result;
        }
        rememberDirectoryOf(result);
        return result;
    }

    /**
     * Ask the user to pick a folder. Hidden folders are shown in the Swing
     * chooser so that data folders such as {@code ~/.ca} can be picked.
     * <p>
     * The choice does not change where later file dialogs open, so picking the
     * CertWizard data folder does not send exports into it.
     *
     * @param parent           component the dialog belongs to, may be null
     * @param title            dialog title
     * @param initialDirectory folder to start in if it exists, or null
     * @return the chosen folder, or null if the user cancelled
     */
    public static File chooseDirectory(Component parent, String title, File initialDirectory) {
        overwriteConfirmed = null;
        File start = startDirectory(initialDirectory);
        if (useNativeDialogs()) {
            String previous = System.getProperty(MAC_DIRECTORY_MODE);
            System.setProperty(MAC_DIRECTORY_MODE, "true");
            try {
                return showNativeDialog(parent, title, FileDialog.LOAD, start, null, null);
            } finally {
                if (previous == null) {
                    System.clearProperty(MAC_DIRECTORY_MODE);
                } else {
                    System.setProperty(MAC_DIRECTORY_MODE, previous);
                }
            }
        }
        JFileChooser chooser = newChooser(start);
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setFileHidingEnabled(false);
        chooser.setDialogTitle(title);
        chooser.setMultiSelectionEnabled(false);
        return chooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION ? chooser.getSelectedFile() : null;
    }

    /**
     * Whether the user already agreed to replace this file in the dialog that
     * chose it, so asking again would be a duplicate prompt.
     *
     * @param file a file returned by {@link #saveFile}
     * @return true if it came from the last save dialog, which confirmed overwriting it
     */
    public static boolean isOverwriteConfirmed(File file) {
        return file != null && file.equals(overwriteConfirmed);
    }

    /**
     * Whether to use the native AWT dialogs rather than the Swing chooser.
     *
     * @param osName          value of {@code os.name}
     * @param backendOverride value of {@link #BACKEND_PROPERTY}, or null
     * @return true on macOS unless the Swing chooser was requested
     */
    static boolean useNativeDialogs(String osName, String backendOverride) {
        if (backendOverride != null && backendOverride.trim().equalsIgnoreCase("swing")) {
            return false;
        }
        return osName != null && osName.toLowerCase(Locale.ROOT).startsWith("mac");
    }

    /**
     * Derive a file name from a base name such as a certificate alias, with
     * the same rules Portecle used: anything other than letters, '_' and '-'
     * becomes '_', repeated '_' collapse, and leading and trailing '_' go.
     *
     * @param baseName  base name without extension, may be null
     * @param extension extension without the dot
     * @return the file name, or null if nothing sensible is left
     */
    static String suggestedFileName(String baseName, String extension) {
        if (baseName == null) {
            return null;
        }
        String name = FILENAME_FILTER.matcher(baseName.trim()).replaceAll("_");
        name = name.replaceAll("_+", "_");
        name = name.replaceFirst("^_+", "");
        name = name.replaceFirst("_+$", "");
        return name.isEmpty() ? null : name + "." + extension;
    }

    /**
     * Append the extension if the file name has none. A name that already has
     * an extension, even a different one, is left as the user typed it.
     *
     * @param file      the chosen file
     * @param extension extension without the dot
     * @return the file, with ".extension" appended if it had no extension
     */
    static File withDefaultExtension(File file, String extension) {
        if (file == null || extension == null || extension.isEmpty()) {
            return file;
        }
        String name = file.getName();
        int dot = name.lastIndexOf('.');
        if (dot > 0 && dot < name.length() - 1) {
            return file;
        }
        String suffix = name.endsWith(".") ? extension : "." + extension;
        return new File(file.getParentFile(), name + suffix);
    }

    private static boolean useNativeDialogs() {
        return useNativeDialogs(System.getProperty("os.name"), System.getProperty(BACKEND_PROPERTY));
    }

    private static File startDirectory(File preferred) {
        return StartDirectoryPolicy.resolve(preferred, sessionDirectory,
                fileOrNull(System.getProperty("user.dir")),
                fileOrNull(System.getProperty("user.home")),
                StartDirectoryPolicy.installLocations(System::getProperty, System::getenv));
    }

    private static File fileOrNull(String path) {
        return path == null ? null : new File(path);
    }

    private static void rememberDirectoryOf(File chosen) {
        if (chosen != null) {
            File dir = chosen.getAbsoluteFile().getParentFile();
            if (dir != null) {
                sessionDirectory = dir;
            }
        }
    }

    /**
     * Show a native, modal {@link FileDialog}.
     *
     * @return the chosen file, or null if the user cancelled
     */
    private static File showNativeDialog(Component parent, String title, int mode, File start,
            String fileName, FileNameExtensionFilter filter) {
        Window owner = parent == null || parent instanceof Window
                ? (Window) parent : SwingUtilities.getWindowAncestor(parent);
        FileDialog dialog = owner instanceof Dialog
                ? new FileDialog((Dialog) owner, title, mode)
                : new FileDialog(owner instanceof Frame ? (Frame) owner : null, title, mode);
        dialog.setMultipleMode(false);
        if (start != null) {
            dialog.setDirectory(start.getAbsolutePath());
        }
        if (fileName != null) {
            dialog.setFile(fileName);
        }
        if (filter != null) {
            dialog.setFilenameFilter((dir, name) -> filter.accept(new File(dir, name)));
        }
        try {
            dialog.setVisible(true); // blocks until the user closes the dialog
            String file = dialog.getFile();
            if (file == null) {
                return null;
            }
            String directory = dialog.getDirectory();
            return directory == null ? new File(file) : new File(directory, file);
        } finally {
            dialog.dispose();
        }
    }

    private static void configure(JFileChooser chooser, String title, String approveButtonText,
            FileNameExtensionFilter filter) {
        chooser.setDialogTitle(title);
        chooser.setMultiSelectionEnabled(false);
        if (approveButtonText != null) {
            chooser.setApproveButtonText(approveButtonText);
        }
        if (filter != null) {
            chooser.addChoosableFileFilter(filter);
            chooser.setFileFilter(filter);
        }
    }

    private static File showChooser(JFileChooser chooser, Component parent) {
        // A null text keeps the dialog type (open or save) set by the caller.
        return chooser.showDialog(parent, null) == JFileChooser.APPROVE_OPTION ? chooser.getSelectedFile() : null;
    }

    /**
     * Create a chooser drawn with the platform look and feel (Windows, or GTK
     * on GNOME) while leaving the rest of the application's look and feel
     * alone. The chooser takes its UI delegate from the look and feel that is
     * active when it is constructed.
     */
    private static JFileChooser newChooser(File start) {
        LookAndFeel current = UIManager.getLookAndFeel();
        String system = UIManager.getSystemLookAndFeelClassName();
        if (current == null || current.getClass().getName().equals(system)) {
            return new JFileChooser(start);
        }
        try {
            UIManager.setLookAndFeel(system);
        } catch (ReflectiveOperationException | UnsupportedLookAndFeelException | RuntimeException e) {
            return new JFileChooser(start);
        }
        try {
            return new JFileChooser(start);
        } finally {
            try {
                UIManager.setLookAndFeel(current);
            } catch (UnsupportedLookAndFeelException e) {
                // Not possible: it was the active look and feel a moment ago.
            }
        }
    }
}
