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

import java.io.File;
import java.io.IOException;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;

/**
 * Decides which directory a file picker opens in. In order of preference:
 * <ol>
 * <li>a directory the caller asks for, e.g. the folder holding the current
 * selection;</li>
 * <li>the directory the user last picked a file from in this session;</li>
 * <li>the process working directory, but only when it is somewhere the user
 * plausibly chose (see {@link #isMeaningfulWorkingDirectory});</li>
 * <li>the user's home directory.</li>
 * </ol>
 * A candidate is skipped unless it is an existing, readable directory. If none
 * qualifies, {@code null} is returned and the dialog falls back to its own
 * default.
 * <p>
 * Nothing here reads global state; every input is a parameter so the policy
 * can be unit tested. {@link FilePicker} supplies the live values.
 */
final class StartDirectoryPolicy {

    /** Windows environment variables naming install or system locations. */
    private static final String[] WINDOWS_INSTALL_ENV_VARS
            = {"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "SystemRoot"};

    private StartDirectoryPolicy() {
    }

    /**
     * Choose the directory a picker should open in.
     *
     * @param preferred        directory requested by the caller, or null
     * @param lastUsed         directory last picked from in this session, or null
     * @param workingDir       the process working directory ({@code user.dir})
     * @param home             the user's home directory ({@code user.home})
     * @param installLocations directories the application is installed in; see
     *                         {@link #installLocations}
     * @return the start directory, or null to let the dialog decide
     */
    static File resolve(File preferred, File lastUsed, File workingDir, File home,
            Collection<File> installLocations) {
        if (isUsableDirectory(preferred)) {
            return preferred;
        }
        if (isUsableDirectory(lastUsed)) {
            return lastUsed;
        }
        if (isMeaningfulWorkingDirectory(workingDir, installLocations)) {
            return workingDir;
        }
        if (isUsableDirectory(home)) {
            return home;
        }
        return null;
    }

    /**
     * Whether the working directory is somewhere the user chose, such as the
     * directory a terminal was in when CertWizard was started. It is not when
     * the OS picked it for us: macOS starts apps launched from Finder in
     * {@code /}, and installed launchers often start in their own install
     * directory.
     *
     * @param dir              the working directory
     * @param installLocations directories the application is installed in
     * @return true if it is a readable directory that is not a filesystem root,
     * not inside a macOS {@code .app} bundle and not inside an install location
     */
    static boolean isMeaningfulWorkingDirectory(File dir, Collection<File> installLocations) {
        if (!isUsableDirectory(dir)) {
            return false;
        }
        Path path = normalise(dir);
        if (path == null || path.getParent() == null || isInsideAppBundle(path)) {
            return false;
        }
        for (File location : installLocations) {
            Path installPath = normalise(location);
            if (installPath != null && path.startsWith(installPath)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Work out where the application and its runtime are installed. A working
     * directory inside any of these was chosen by a launcher, not the user.
     *
     * @param systemProperty lookup for system properties, e.g. {@code System::getProperty}
     * @param environment    lookup for environment variables, e.g. {@code System::getenv}
     * @return install locations; never a filesystem root, the user's home
     * directory or one of its ancestors
     */
    static List<File> installLocations(Function<String, String> systemProperty,
            Function<String, String> environment) {
        List<File> candidates = new ArrayList<>();

        // The Java runtime itself. A runtime bundled with an installed app sits
        // in a "runtime" (jpackage) or "jre" (javapackager) folder of the app.
        File javaHome = toFile(systemProperty.apply("java.home"));
        if (javaHome != null) {
            candidates.add(javaHome);
            String name = javaHome.getName().toLowerCase(Locale.ROOT);
            if (name.equals("runtime") || name.equals("jre")) {
                candidates.add(javaHome.getParentFile());
            }
        }

        // jpackage launchers report their own path; on Linux they live in <app>/bin.
        File launcher = toFile(systemProperty.apply("jpackage.app-path"));
        if (launcher != null && launcher.getParentFile() != null) {
            File launcherDir = launcher.getParentFile();
            candidates.add(launcherDir);
            if (launcherDir.getName().equalsIgnoreCase("bin")) {
                candidates.add(launcherDir.getParentFile());
            }
        }

        for (String var : WINDOWS_INSTALL_ENV_VARS) {
            candidates.add(toFile(environment.apply(var)));
        }

        // Never let a broad location (a root, or home and its parents) rule out
        // every working directory.
        Path home = normalise(toFile(systemProperty.apply("user.home")));
        List<File> locations = new ArrayList<>();
        for (File candidate : candidates) {
            Path path = normalise(candidate);
            if (path == null || path.getParent() == null || (home != null && home.startsWith(path))) {
                continue;
            }
            locations.add(candidate);
        }
        return locations;
    }

    /**
     * @param path an absolute path
     * @return true if any element of the path is a macOS application bundle
     */
    static boolean isInsideAppBundle(Path path) {
        for (Path element : path) {
            if (element.toString().toLowerCase(Locale.ROOT).endsWith(".app")) {
                return true;
            }
        }
        return false;
    }

    private static boolean isUsableDirectory(File dir) {
        return dir != null && dir.isDirectory() && dir.canRead();
    }

    private static File toFile(String path) {
        return path == null || path.trim().isEmpty() ? null : new File(path);
    }

    /**
     * Resolve symlinks where possible so that, for example, macOS
     * {@code /var} and {@code /private/var} compare equal.
     */
    private static Path normalise(File file) {
        if (file == null) {
            return null;
        }
        try {
            return file.toPath().toRealPath();
        } catch (IOException | InvalidPathException | SecurityException e) {
            try {
                return file.toPath().toAbsolutePath().normalize();
            } catch (InvalidPathException | SecurityException e2) {
                return null;
            }
        }
    }
}
