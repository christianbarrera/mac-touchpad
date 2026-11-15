/* Mac Touchpad.app main executable.
 *
 * Embeds the bundled Python (Contents/Frameworks/libpython3.13.dylib) and runs
 * the `menubar` module. The process stays this signed binary, so macOS ties the
 * Accessibility permission and Keychain access to the app, not to a Python.
 *
 * Python runs fully isolated: PYTHON* environment variables, the user site
 * directory, the current directory and command-line interpreter options are all
 * ignored, and sys.path holds only folders inside the bundle. (DYLD_* variables
 * are ignored too, because the app is signed with the hardened runtime.)
 *
 * Built by tools/build_app.sh.
 */
#include <Python.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *msg) {
    fprintf(stderr, "Mac Touchpad: %s\n", msg);
    exit(70);
}

static void check(PyStatus st, PyConfig *config) {
    if (PyStatus_Exception(st)) {
        if (config) PyConfig_Clear(config);
        Py_ExitStatusException(st);
    }
}

/* Appends <contents>/<rel> to the module search path. */
static void add_path(PyConfig *config, const char *contents, const char *rel) {
    char buf[PATH_MAX];
    if (snprintf(buf, sizeof buf, "%s/%s", contents, rel) >= (int)sizeof buf) die("path too long");
    wchar_t *w = Py_DecodeLocale(buf, NULL);
    if (!w) die("cannot decode path");
    check(PyWideStringList_Append(&config->module_search_paths, w), config);
    PyMem_RawFree(w);
}

int main(int argc, char **argv) {
    char raw[PATH_MAX], exe[PATH_MAX], contents[PATH_MAX], home[PATH_MAX];
    uint32_t size = sizeof raw;
    if (_NSGetExecutablePath(raw, &size) != 0 || !realpath(raw, exe)) die("cannot find own executable");

    /* exe = .../Mac Touchpad.app/Contents/MacOS/Mac Touchpad  ->  contents = .../Contents */
    strlcpy(contents, exe, sizeof contents);
    for (int i = 0; i < 2; i++) {
        char *slash = strrchr(contents, '/');
        if (!slash) die("unexpected bundle layout");
        *slash = '\0';
    }
    snprintf(home, sizeof home, "%s/Resources/python", contents);

    PyPreConfig pre;
    PyPreConfig_InitIsolatedConfig(&pre);
    pre.utf8_mode = 1;
    check(Py_PreInitialize(&pre), NULL);

    PyConfig config;
    PyConfig_InitIsolatedConfig(&config);   /* isolated, use_environment=0, safe_path=1, no user site */
    config.parse_argv = 0;                   /* our argv is the app's, never interpreter options */
    config.write_bytecode = 0;               /* the bundle is read-only; .pyc files are precompiled */
    config.site_import = 0;                  /* no site.py, so no .pth files */
    config.install_signal_handlers = 1;
    check(PyConfig_SetBytesString(&config, &config.program_name, exe), &config);
    check(PyConfig_SetBytesString(&config, &config.home, home), &config);
    check(PyConfig_SetBytesArgv(&config, argc, argv), &config);
    check(PyConfig_SetString(&config, &config.run_module, L"menubar"), &config);

    config.module_search_paths_set = 1;
    add_path(&config, contents, "Resources/app/server");
    add_path(&config, contents, "Resources/python/lib/python3.13");
    add_path(&config, contents, "Resources/python/lib/python3.13/lib-dynload");
    add_path(&config, contents, "Resources/site-packages");

    check(Py_InitializeFromConfig(&config), &config);
    PyConfig_Clear(&config);
    return Py_RunMain();
}
