package uk.ngs.certwizard.gui;

import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests for {@link StartDirectoryPolicy}. Uses real temporary directories, no GUI.
 */
public class StartDirectoryPolicyTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private File home;
    private File cwd;
    private File last;
    private File missing;

    @Before
    public void setUp() throws IOException {
        home = tmp.newFolder("home");
        cwd = tmp.newFolder("work");
        last = tmp.newFolder("last");
        missing = new File(tmp.getRoot(), "does-not-exist");
    }

    private static List<File> none() {
        return Collections.emptyList();
    }

    @Test
    public void preferredDirectoryWinsWhenItExists() throws IOException {
        File preferred = tmp.newFolder("preferred");
        assertEquals(preferred, StartDirectoryPolicy.resolve(preferred, last, cwd, home, none()));
    }

    @Test
    public void missingPreferredDirectoryIsSkipped() {
        assertEquals(last, StartDirectoryPolicy.resolve(missing, last, cwd, home, none()));
    }

    @Test
    public void lastUsedDirectoryBeatsWorkingDirectoryAndHome() {
        assertEquals(last, StartDirectoryPolicy.resolve(null, last, cwd, home, none()));
    }

    @Test
    public void lastUsedDirectoryThatNoLongerExistsFallsBackToWorkingDirectory() {
        assertTrue(last.delete());
        assertEquals(cwd, StartDirectoryPolicy.resolve(null, last, cwd, home, none()));
    }

    @Test
    public void meaningfulWorkingDirectoryBeatsHome() {
        assertEquals(cwd, StartDirectoryPolicy.resolve(null, null, cwd, home, none()));
    }

    @Test
    public void filesystemRootWorkingDirectoryFallsBackToHome() {
        // macOS starts apps launched from Finder with a working directory of "/"
        File root = File.listRoots()[0];
        assertFalse(StartDirectoryPolicy.isMeaningfulWorkingDirectory(root, none()));
        assertEquals(home, StartDirectoryPolicy.resolve(null, null, root, home, none()));
    }

    @Test
    public void workingDirectoryInsideAppBundleFallsBackToHome() throws IOException {
        File macOsDir = tmp.newFolder("Applications", "CertWizard.app", "Contents", "MacOS");
        assertFalse(StartDirectoryPolicy.isMeaningfulWorkingDirectory(macOsDir, none()));
        assertEquals(home, StartDirectoryPolicy.resolve(null, null, macOsDir, home, none()));
    }

    @Test
    public void appBundleSuffixIsCaseInsensitive() throws IOException {
        File bundle = tmp.newFolder("CertWizard.APP");
        assertFalse(StartDirectoryPolicy.isMeaningfulWorkingDirectory(bundle, none()));
    }

    @Test
    public void workingDirectoryInsideInstallLocationFallsBackToHome() throws IOException {
        File install = tmp.newFolder("Program Files", "CertWizard");
        File inside = tmp.newFolder("Program Files", "CertWizard", "app");
        List<File> installs = Collections.singletonList(install);
        assertFalse(StartDirectoryPolicy.isMeaningfulWorkingDirectory(install, installs));
        assertFalse(StartDirectoryPolicy.isMeaningfulWorkingDirectory(inside, installs));
        assertEquals(home, StartDirectoryPolicy.resolve(null, null, inside, home, installs));
    }

    @Test
    public void siblingWithInstallLocationAsNamePrefixIsStillMeaningful() throws IOException {
        File install = tmp.newFolder("CertWizard");
        File sibling = tmp.newFolder("CertWizard-exports");
        assertTrue(StartDirectoryPolicy.isMeaningfulWorkingDirectory(sibling,
                Collections.singletonList(install)));
    }

    @Test
    public void missingWorkingDirectoryFallsBackToHome() {
        assertEquals(home, StartDirectoryPolicy.resolve(null, null, missing, home, none()));
    }

    @Test
    public void workingDirectoryThatIsAFileFallsBackToHome() throws IOException {
        File file = tmp.newFile("not-a-dir.txt");
        assertEquals(home, StartDirectoryPolicy.resolve(null, null, file, home, none()));
    }

    @Test
    public void unreadableWorkingDirectoryFallsBackToHome() {
        Assume.assumeTrue(cwd.setReadable(false));
        try {
            Assume.assumeFalse("running with privileges that ignore permissions", cwd.canRead());
            assertEquals(home, StartDirectoryPolicy.resolve(null, null, cwd, home, none()));
        } finally {
            cwd.setReadable(true);
        }
    }

    @Test
    public void nothingUsableGivesNull() {
        assertNull(StartDirectoryPolicy.resolve(null, null, File.listRoots()[0], missing, none()));
        assertNull(StartDirectoryPolicy.resolve(null, null, null, null, none()));
    }

    @Test
    public void installLocationsIncludeJavaHome() throws IOException {
        File javaHome = tmp.newFolder("jdk");
        Map<String, String> props = props(javaHome, null);
        List<File> locations = StartDirectoryPolicy.installLocations(props::get, noEnv());
        assertEquals(Collections.singletonList(javaHome), locations);
    }

    @Test
    public void bundledRuntimeMakesItsAppFolderAnInstallLocation() throws IOException {
        File app = tmp.newFolder("CertWizard");
        File jre = tmp.newFolder("CertWizard", "jre");
        List<File> locations = StartDirectoryPolicy.installLocations(props(jre, null)::get, noEnv());
        assertTrue(locations.contains(app));

        File inApp = tmp.newFolder("CertWizard", "logs");
        assertFalse(StartDirectoryPolicy.isMeaningfulWorkingDirectory(inApp, locations));
    }

    @Test
    public void jpackageLinuxLauncherMakesAppRootAnInstallLocation() throws IOException {
        File appRoot = tmp.newFolder("opt", "certwizard");
        File bin = tmp.newFolder("opt", "certwizard", "bin");
        Map<String, String> props = props(null, new File(bin, "CertWizard"));
        List<File> locations = StartDirectoryPolicy.installLocations(props::get, noEnv());
        assertTrue(locations.contains(bin));
        assertTrue(locations.contains(appRoot));
    }

    @Test
    public void windowsInstallEnvironmentVariablesAreInstallLocations() throws IOException {
        File programFiles = tmp.newFolder("Program Files");
        File windows = tmp.newFolder("Windows");
        Map<String, String> env = new HashMap<>();
        env.put("ProgramFiles", programFiles.getPath());
        env.put("SystemRoot", windows.getPath());
        List<File> locations = StartDirectoryPolicy.installLocations(props(null, null)::get, env::get);
        assertTrue(locations.contains(programFiles));
        assertTrue(locations.contains(windows));
    }

    @Test
    public void rootsHomeAndHomeAncestorsAreNeverInstallLocations() {
        // e.g. a JDK unpacked straight into the home directory with a "jre" folder
        File jreInHome = new File(home, "jre");
        Map<String, String> env = new HashMap<>();
        env.put("ProgramFiles", File.listRoots()[0].getPath());
        env.put("SystemRoot", tmp.getRoot().getPath()); // an ancestor of home
        env.put("ProgramW6432", "  ");
        List<File> locations = StartDirectoryPolicy.installLocations(props(jreInHome, null)::get, env::get);
        assertEquals(Collections.singletonList(jreInHome), locations);
        assertTrue(StartDirectoryPolicy.isMeaningfulWorkingDirectory(cwd, locations));
    }

    private Map<String, String> props(File javaHome, File jpackageLauncher) {
        Map<String, String> props = new HashMap<>();
        props.put("user.home", home.getPath());
        if (javaHome != null) {
            props.put("java.home", javaHome.getPath());
        }
        if (jpackageLauncher != null) {
            props.put("jpackage.app-path", jpackageLauncher.getPath());
        }
        return props;
    }

    private static java.util.function.Function<String, String> noEnv() {
        return name -> null;
    }
}
