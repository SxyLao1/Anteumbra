# -*- coding: utf-8 -*-
"""What ``action=kill`` does, step by step, and what it is allowed to claim.

The live finding behind this file: on Tomcat 7.0.108 the filter was disabled
(its URL answered 404) but the component was still enumerated, so the probe
honestly reported ``removed=false``.  The cause is in Tomcat itself —
``StandardContext.removeFilterDef()`` only drops the entry from its private
``filterDefs`` map and never touches ``filterConfigs``, so the
``ApplicationFilterConfig`` (and the live filter instance behind it) stays
registered forever (verified with ``javap`` against 7.0.108 and 9.0.96 bytecode;
c0ny1's scanner leaves exactly this behind).

Two levels of testing:

* static assertions on the template: the four cleanup steps exist, in order, with
  the right arguments;
* a Java harness, compiled and executed at test time (skipped when no JDK is
  present), that runs the real ``removeFilter`` / ``removeServlet`` /
  ``removeListener`` code against fake ``StandardContext`` objects which record
  every reflected call, in three outcome shapes: success, partial success and
  refusal.

No container, no network, no files outside ``tmp_path``.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from anteumbra.infrastructure.memory_shell.probe_deployer import load_probe_template

JSP_TEMPLATE = load_probe_template()


def _method_body(name: str) -> str:
    """The source of one ``private static`` method from the probe template."""
    start = JSP_TEMPLATE.index(f"private static {name}")
    # method bodies end at the first line that closes at the declaration indent
    end = JSP_TEMPLATE.index("\n    }\n", start)
    return JSP_TEMPLATE[start : end + len("\n    }\n")]


# ── static: the four cleanup steps, in order, with the right arguments ──────


def test_filter_removal_does_the_four_steps_in_order():
    body = _method_body("String removeFilter(Object standardContext, String name)")

    steps = {
        "map": body.index('callWithArg(standardContext, "removeFilterMap"'),
        "def": body.index("findFilterDef(standardContext, name)"),
        "remove_def": body.index("removeFilterDef(standardContext, filterDef)"),
        "configs": body.index("dropFilterConfig(filterConfigs, name)"),
        "verify": body.index("if (filterRegistered(standardContext, name))"),
        "restart": body.index('call(standardContext, "filterStart")'),
    }
    assert (
        steps["map"] < steps["remove_def"] < steps["configs"] < steps["verify"] < steps["restart"]
    ), f"cleanup order changed: {steps}"
    # the mappings are collected before any is removed (the array shifts under us)
    assert body.index("doomed.add(maps[i])") < steps["map"]


def test_filter_removal_drops_the_application_filter_config():
    """The step Tomcat itself does not do, and the reason the live run failed."""
    drop = _method_body("boolean dropFilterConfig(Map filterConfigs, String name)")
    assert "filterConfigs.remove(name)" in drop
    assert 'call(removed, "release")' in drop, "release() is best effort, but it is attempted"
    # removing the entry must not depend on release() succeeding
    assert drop.index("filterConfigs.remove(name)") < drop.index('call(removed, "release")')


def test_filter_def_lookup_uses_the_public_api_then_the_field():
    find = _method_body("Object findFilterDef(Object standardContext, String name)")
    assert 'callForValue(standardContext, "findFilterDef", name, String.class, errorOut)' in find
    assert 'field(standardContext, "filterDefs")' in find
    assert find.index("callForValue") < find.index('field(standardContext, "filterDefs")')
    # "not found" and "cannot be asked" are distinguished
    assert "errorOut[0] == null && found != null" in find


def test_remove_filter_def_tries_the_instance_class_and_both_package_names():
    body = _method_body("String removeFilterDef(Object standardContext, Object filterDef)")
    assert "candidates.add(filterDef.getClass())" in body, "the instance in hand is always right"
    assert "org.apache.tomcat.util.descriptor.web.FilterDef" in body, "Tomcat 8/9"
    assert "org.apache.catalina.deploy.FilterDef" in body, "Tomcat 7"
    assert "candidates.add(null)" in body, "last resort: any single-argument overload"
    # a method that exists but throws is a failure, not something to retry away
    assert 'if (error.indexOf("method_not_found") == 0)' in body
    assert "return \"remove_filter_def_failed: \" + error;" in body


def test_filter_verification_checks_all_three_places_a_name_can_survive():
    body = _method_body("boolean filterRegistered(Object standardContext, String name)")
    assert "filterConfigMap(standardContext)" in body
    assert "findFilterDef(standardContext, name) != null" in body
    assert "filterMapsOf(standardContext)" in body


def test_the_restart_is_only_attempted_when_the_component_is_still_there():
    body = _method_body("String removeFilter(Object standardContext, String name)")
    assert 'hasMethod(standardContext, "filterStop", 0)' in body
    assert 'hasMethod(standardContext, "filterStart", 0)' in body
    assert "filter_still_registered_after_cleanup" in body
    restart = body.index('call(standardContext, "filterStop")')
    assert restart > body.index("if (filterRegistered(standardContext, name))")


def test_servlet_removal_maps_first_then_child_and_verifies():
    body = _method_body("String removeServlet(Object standardContext, String name)")
    mapping = body.index('callWithArg(standardContext, "removeServletMapping"')
    child = body.index('callWithArg(standardContext, "removeChild"')
    verify = body.index("if (servletRegistered(standardContext, name))")
    assert mapping < child < verify
    assert "servlet_still_registered_after_cleanup" in body
    registered = _method_body("boolean servletRegistered(Object standardContext, String name)")
    assert 'field(standardContext, "children")' in registered
    assert 'field(standardContext, "servletMappings")' in registered


def test_listener_removal_handles_both_storage_shapes_and_verifies():
    body = _method_body("String removeListener(Object standardContext, Object listener)")
    # Tomcat 8/9: a List behind the public API
    assert 'field(standardContext, "applicationEventListenersList")' in body
    assert "((Collection) list).remove(listener)" in body
    # Tomcat 6/7: an Object[] behind the same public API, and the array field
    assert 'call(standardContext, "getApplicationEventListeners")' in body
    assert 'callWithArg(standardContext, "setApplicationEventListeners"' in body
    assert 'field(standardContext, "applicationEventListenersObjects")' in body
    assert "setField(standardContext, \"applicationEventListenersObjects\", trimmed)" in body
    assert "listener_still_registered_after_cleanup" in body
    assert "trimListener(" in body


def test_listeners_are_enumerated_the_way_tomcat_7_actually_stores_them():
    """Tomcat 7 has no applicationEventListenersList: reading only it hid every
    listener, which also made the listener removal path unreachable there."""
    collect = _method_body("void collectListeners(Snapshot snapshot)")
    assert "eventListeners(snapshot.standardContext)" in collect
    locate = _method_body("Component locateListener(Snapshot snapshot, String name)")
    assert "eventListeners(snapshot.standardContext)" in locate
    helper = _method_body("List<Object> eventListeners(Object standardContext)")
    assert 'call(standardContext, "getApplicationEventListeners")' in helper
    assert 'field(standardContext, "applicationEventListenersList")' in helper
    assert 'field(standardContext, "applicationEventListenersObjects")' in helper


def test_the_probe_template_stays_ascii_only():
    """It is written into a foreign web root and compiled by that container's
    Jasper: a non-ASCII byte is one encoding mishap away from a JSP that will
    not compile, for no benefit."""
    assert JSP_TEMPLATE.isascii()


def test_java6_guards_survive_the_removal_rewrite():
    assert "<>" not in JSP_TEMPLATE
    assert "try (" not in JSP_TEMPLATE
    assert "-> {" not in JSP_TEMPLATE
    assert "Object config = " not in JSP_TEMPLATE
    assert "String config = " not in JSP_TEMPLATE


# ── the compiled harness: what the code really does ─────────────────────────

SERVLET_CONTEXT_STUB = """
package javax.servlet;
import java.util.Map;
public interface ServletContext {
    String getServerInfo();
    Map getFilterRegistrations();
}
"""

HTTP_SESSION_STUB = """
package javax.servlet.http;
import javax.servlet.ServletContext;
public interface HttpSession {
    ServletContext getServletContext();
}
"""

HTTP_REQUEST_STUB = """
package javax.servlet.http;
import javax.servlet.ServletContext;
public interface HttpServletRequest {
    HttpSession getSession(boolean create);
    ServletContext getServletContext();
    String getParameter(String name);
    String getContextPath();
    StringBuffer getRequestURL();
}
"""

HARNESS_SOURCE = r"""
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Runs the probe's real removal code against fake StandardContext objects. */
public class KillHarness {

    public static final List<String> CALLS = new ArrayList<String>();

    static void record(String entry) { CALLS.add(entry); }

    // ── the shapes Tomcat actually uses ────────────────────────────────
    public static class FakeFilterDef {
        private String filterName;
        public FakeFilterDef(String name) { this.filterName = name; }
        public String getFilterName() { return filterName; }
    }

    public static class FakeFilterMap {
        private String filterName;
        private String[] urlPatterns;
        public FakeFilterMap(String name, String[] urls) {
            this.filterName = name; this.urlPatterns = urls;
        }
        public String getFilterName() { return filterName; }
        public String[] getURLPatterns() { return urlPatterns; }
    }

    public static class FakeFilterMaps {
        public Object[] array;
        public FakeFilterMaps(Object[] array) { this.array = array; }
    }

    public static class FakeFilter {
        public String toString() { return "FakeFilter"; }
    }

    public static class FakeFilterConfig {
        private Object filter;
        private Object filterDef;
        public FakeFilterConfig(Object filter, Object def) {
            this.filter = filter; this.filterDef = def;
        }
        void release() { record("release"); }
    }

    /** Faithful to Tomcat 7.0.108 / 9.0.96: removeFilterDef leaves filterConfigs alone. */
    public static class FakeContext {
        private Map<String, Object> filterConfigs = new HashMap<String, Object>();
        private Map<String, Object> filterDefs = new HashMap<String, Object>();
        private FakeFilterMaps filterMaps = new FakeFilterMaps(new Object[0]);
        public boolean ignoreRemoveFilterDef = false;

        public void addFilter(String name) {
            FakeFilterDef def = new FakeFilterDef(name);
            filterDefs.put(name, def);
            filterConfigs.put(name, new FakeFilterConfig(new FakeFilter(), def));
        }
        public void addFilterMap(String name) {
            Object[] current = filterMaps.array;
            Object[] next = new Object[current.length + 1];
            for (int i = 0; i < current.length; i++) { next[i] = current[i]; }
            next[current.length] = new FakeFilterMap(name, new String[] { "/*" });
            filterMaps.array = next;
        }
        public void removeFilterMap(FakeFilterMap map) {
            record("removeFilterMap:" + map.getFilterName());
            Object[] current = filterMaps.array;
            Object[] next = new Object[current.length];
            int kept = 0;
            for (int i = 0; i < current.length; i++) {
                if (current[i] != map) { next[kept] = current[i]; kept++; }
            }
            Object[] trimmed = new Object[kept];
            for (int i = 0; i < kept; i++) { trimmed[i] = next[i]; }
            filterMaps.array = trimmed;
        }
        public void removeFilterDef(FakeFilterDef def) {
            record("removeFilterDef:" + def.getFilterName());
            if (ignoreRemoveFilterDef) { return; }
            filterDefs.remove(def.getFilterName());
            // filterConfigs is NOT touched here: this is the Tomcat behaviour the
            // probe has to compensate for.
        }
        public FakeFilterDef findFilterDef(String name) {
            record("findFilterDef:" + name);
            return (FakeFilterDef) filterDefs.get(name);
        }
        public boolean filterStop() {
            record("filterStop");
            filterConfigs.clear();
            return true;
        }
        /** Tomcat rebuilds filterConfigs from the definitions that are left. */
        public boolean filterStart() {
            record("filterStart");
            filterConfigs.clear();
            for (Map.Entry<String, Object> entry : filterDefs.entrySet()) {
                filterConfigs.put(entry.getKey(),
                        new FakeFilterConfig(new FakeFilter(), entry.getValue()));
            }
            return true;
        }
        public boolean hasFilterConfig(String name) { return filterConfigs.get(name) != null; }
        public boolean hasFilterDef(String name) { return filterDefs.get(name) != null; }
        public int mapCount() { return filterMaps.array.length; }
        public String state() {
            return "configs=" + (filterConfigs == null ? "unavailable" : "" + filterConfigs.size())
                    + ",defs=" + filterDefs.size()
                    + ",maps=" + filterMaps.array.length;
        }
    }

    public static class FakeWrapper {
        private String name;
        public FakeWrapper(String name) { this.name = name; }
        public String getName() { return name; }
    }

    public static class FakeServletContext {
        private Map<String, Object> children = new HashMap<String, Object>();
        private Map<String, String> servletMappings = new HashMap<String, String>();
        public boolean stubborn = false;

        public void addServlet(String name, String pattern) {
            children.put(name, new FakeWrapper(name));
            servletMappings.put(pattern, name);
        }
        public void removeServletMapping(String pattern) {
            record("removeServletMapping:" + pattern);
            servletMappings.remove(pattern);
        }
        public void removeChild(Object child) {
            record("removeChild:" + ((FakeWrapper) child).getName());
            if (!stubborn) { children.remove(((FakeWrapper) child).getName()); }
        }
        public String state() {
            return "children=" + children.size() + ",mappings=" + servletMappings.size();
        }
    }

    public static class FakeListener {
        public String toString() { return "FakeListener"; }
    }

    /** Tomcat 6/7: an Object[] behind get/setApplicationEventListeners. */
    public static class FakeArrayListenerContext {
        private Object[] applicationEventListenersObjects = new Object[0];
        public void add(Object listener) {
            Object[] next = new Object[applicationEventListenersObjects.length + 1];
            for (int i = 0; i < applicationEventListenersObjects.length; i++) {
                next[i] = applicationEventListenersObjects[i];
            }
            next[applicationEventListenersObjects.length] = listener;
            applicationEventListenersObjects = next;
        }
        public Object[] getApplicationEventListeners() {
            record("getApplicationEventListeners");
            return applicationEventListenersObjects;
        }
        public void setApplicationEventListeners(Object[] listeners) {
            record("setApplicationEventListeners:" + listeners.length);
            applicationEventListenersObjects = listeners;
        }
        public boolean has(Object listener) {
            for (int i = 0; i < applicationEventListenersObjects.length; i++) {
                if (applicationEventListenersObjects[i] == listener) { return true; }
            }
            return false;
        }
    }

    /** Tomcat 8/9: a List behind the same public pair. */
    public static class FakeListListenerContext {
        private List<Object> applicationEventListenersList = new ArrayList<Object>();
        public void add(Object listener) { applicationEventListenersList.add(listener); }
        public Object[] getApplicationEventListeners() {
            record("getApplicationEventListeners");
            return applicationEventListenersList.toArray(new Object[applicationEventListenersList.size()]);
        }
        public boolean has(Object listener) { return applicationEventListenersList.contains(listener); }
    }

    public static Object call(String method, Class[] types, Object[] args) throws Exception {
        Method m = ProbeCheck.class.getDeclaredMethod(method, types);
        m.setAccessible(true);
        return m.invoke(null, args);
    }

    static void emit(String scenario, Object error, String state) {
        StringBuilder calls = new StringBuilder();
        for (int i = 0; i < CALLS.size(); i++) {
            if (i > 0) { calls.append(','); }
            calls.append(CALLS.get(i));
        }
        System.out.println("RESULT|" + scenario + "|" + (error == null ? "null" : error.toString())
                + "|" + calls.toString() + "|" + state);
        CALLS.clear();
    }

    public static void main(String[] args) throws Exception {
        String name = "dshMemShellFilter";

        // 1) success: the whole filter triple really goes away
        FakeContext context = new FakeContext();
        context.addFilter(name);
        context.addFilterMap(name);
        Object error = call("removeFilter", new Class[] { Object.class, String.class },
                new Object[] { context, name });
        emit("filter_success", error, context.state()
                + ",config_present=" + context.hasFilterConfig(name)
                + ",def_present=" + context.hasFilterDef(name));

        // 2) a container that refuses to let go of the definition: filterStart()
        //    then rebuilds the configs from it, and the probe must say so
        FakeContext stubborn = new FakeContext();
        stubborn.ignoreRemoveFilterDef = true;
        stubborn.addFilter(name);
        stubborn.addFilterMap(name);
        Object stubbornError = call("removeFilter", new Class[] { Object.class, String.class },
                new Object[] { stubborn, name });
        emit("filter_stubborn", stubbornError, stubborn.state()
                + ",config_present=" + stubborn.hasFilterConfig(name)
                + ",def_present=" + stubborn.hasFilterDef(name));

        // 3) the configs map is unreachable: nothing may be claimed
        FakeContext headless = new FakeContext();
        headless.addFilter(name);
        headless.addFilterMap(name);
        java.lang.reflect.Field configsField =
                FakeContext.class.getDeclaredField("filterConfigs");
        configsField.setAccessible(true);
        configsField.set(headless, null);
        Object headlessError = call("removeFilter", new Class[] { Object.class, String.class },
                new Object[] { headless, name });
        emit("filter_configs_unavailable", headlessError, headless.state());

        // 4) servlet: mapping then child, verified
        FakeServletContext servletContext = new FakeServletContext();
        servletContext.addServlet("dshServlet", "/dshlab/shell");
        Object servletError = call("removeServlet", new Class[] { Object.class, String.class },
                new Object[] { servletContext, "dshServlet" });
        emit("servlet_success", servletError, servletContext.state());

        FakeServletContext sticky = new FakeServletContext();
        sticky.addServlet("dshServlet", "/dshlab/shell");
        sticky.stubborn = true;
        Object stickyError = call("removeServlet", new Class[] { Object.class, String.class },
                new Object[] { sticky, "dshServlet" });
        emit("servlet_stubborn", stickyError, sticky.state());

        // 5) listener, Tomcat 7 array form
        FakeArrayListenerContext arrayContext = new FakeArrayListenerContext();
        FakeListener arrayListener = new FakeListener();
        arrayContext.add(arrayListener);
        Object arrayError = call("removeListener", new Class[] { Object.class, Object.class },
                new Object[] { arrayContext, arrayListener });
        emit("listener_array", arrayError, "present=" + arrayContext.has(arrayListener));

        // 6) listener, Tomcat 8/9 list form
        FakeListListenerContext listContext = new FakeListListenerContext();
        FakeListener listListener = new FakeListener();
        listContext.add(listListener);
        Object listError = call("removeListener", new Class[] { Object.class, Object.class },
                new Object[] { listContext, listListener });
        emit("listener_list", listError, "present=" + listContext.has(listListener));
    }
}
"""


def _javac() -> str | None:
    candidate = os.environ.get("ANTEUMBRA_TEST_JAVAC")
    if candidate and Path(candidate).is_file():
        return candidate
    found = shutil.which("javac")
    if found:
        return found
    home = os.environ.get("JAVA_HOME")
    if home:
        binary = Path(home) / "bin" / ("javac.exe" if os.name == "nt" else "javac")
        if binary.is_file():
            return str(binary)
    return None


def _java() -> str | None:
    candidate = os.environ.get("ANTEUMBRA_TEST_JAVA")
    if candidate and Path(candidate).is_file():
        return candidate
    found = shutil.which("java")
    if found:
        return found
    home = os.environ.get("JAVA_HOME")
    if home:
        binary = Path(home) / "bin" / ("java.exe" if os.name == "nt" else "java")
        if binary.is_file():
            return str(binary)
    return None


def _run(command: list[str], cwd: Path) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(  # noqa: S603 - fixed argument list, no shell
            command,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover - environment
        pytest.skip(f"cannot execute the JDK here: {exc}")


@pytest.fixture(scope="module")
def kill_harness(tmp_path_factory) -> dict[str, dict[str, str]]:
    """Compile and run the real removal code; return one entry per scenario."""
    javac = _javac()
    java = _java()
    if not javac or not java:
        pytest.skip("no JDK available to run the compiled removal harness")

    work = tmp_path_factory.mktemp("kill-harness")
    jsp = Path(__file__).resolve().parents[2] / (
        "src/anteumbra/infrastructure/memory_shell/assets/probe.jsp"
    )
    template = jsp.read_text(encoding="utf-8")
    declarations = re.search(r"(?s)<%!(.*?)%>", template).group(1)
    # A JSP container auto-imports these two packages; the harness has to.
    headers = ["import javax.servlet.*;", "import javax.servlet.http.*;"]
    headers += [
        f"import {name};"
        for name in re.findall(r'(?m)^<%@ page import="([^"]+)" %>', template)
    ]

    sources = {
        "javax/servlet/ServletContext.java": SERVLET_CONTEXT_STUB,
        "javax/servlet/http/HttpSession.java": HTTP_SESSION_STUB,
        "javax/servlet/http/HttpServletRequest.java": HTTP_REQUEST_STUB,
        "ProbeCheck.java": "\n".join(headers)
        + "\npublic class ProbeCheck {\n"
        + declarations
        + "\n}\n",
        "KillHarness.java": HARNESS_SOURCE,
    }
    for relative, source in sources.items():
        path = work / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source.lstrip("\n"), encoding="utf-8")

    compiled = _run(
        [javac, "-nowarn", "-encoding", "UTF-8", "-d", "classes"]
        + [str(work / name) for name in sources],
        cwd=work,
    )
    if compiled.returncode != 0:
        pytest.fail(f"the probe's Java declarations do not compile:\n{compiled.stderr}")

    executed = _run([java, "-cp", "classes", "KillHarness"], cwd=work)
    if executed.returncode != 0:
        pytest.fail(f"the removal harness failed to run:\n{executed.stdout}\n{executed.stderr}")

    results: dict[str, dict[str, str]] = {}
    for line in executed.stdout.splitlines():
        if not line.startswith("RESULT|"):
            continue
        _, scenario, error, calls, state = line.split("|")
        results[scenario] = {
            "error": "" if error == "null" else error,
            "calls": calls.split(",") if calls else [],
            "state": state,
        }
    assert results, f"the harness printed no result:\n{executed.stdout}"
    return results


def test_a_filter_that_really_goes_away_is_reported_as_removed(kill_harness):
    scenario = kill_harness["filter_success"]

    assert scenario["error"] == "", "a complete cleanup must not report a reason"
    assert scenario["calls"][:2] == [
        "removeFilterMap:dshMemShellFilter",
        "removeFilterDef:dshMemShellFilter",
    ], "mappings first, then the definition"
    assert "release" in scenario["calls"], "the ApplicationFilterConfig is released"
    assert scenario["state"].endswith("config_present=false,def_present=false")
    assert scenario["state"].startswith("configs=0,defs=0,maps=0")


def test_the_filter_config_is_what_makes_the_component_disappear(kill_harness):
    """Without step 3 the component survives: this is the live bug, reproduced.

    The fake context is faithful to Tomcat (removeFilterDef leaves filterConfigs
    alone), so the assertions above only pass because the probe removes the
    ApplicationFilterConfig explicitly.
    """
    calls = kill_harness["filter_success"]["calls"]
    assert "findFilterDef:dshMemShellFilter" in calls
    assert calls.index("removeFilterDef:dshMemShellFilter") < calls.index("findFilterDef:dshMemShellFilter")
    # and it never needed the heavier filterStop/filterStart repair
    assert "filterStart" not in calls


def test_a_container_that_keeps_the_filter_is_reported_honestly(kill_harness):
    scenario = kill_harness["filter_stubborn"]

    assert scenario["error"], "a surviving component must never be reported as removed"
    assert "filter_still_registered_after_cleanup" in scenario["error"]
    assert "filterStop" in scenario["calls"] and "filterStart" in scenario["calls"]
    assert scenario["state"].endswith("config_present=true,def_present=true"), (
        "the state says exactly what is left, and the definition is what kept it alive"
    )


def test_an_unreadable_configs_map_stops_the_removal_before_it_starts(kill_harness):
    scenario = kill_harness["filter_configs_unavailable"]

    assert scenario["error"] == "filter_configs_unavailable"
    assert scenario["calls"] == [], "an unverifiable removal touches nothing"
    assert scenario["state"] == "configs=unavailable,defs=1,maps=1"
    assert not scenario["calls"], "not even the FilterMap may be touched"


def test_servlet_removal_maps_then_removes_the_child(kill_harness):
    success = kill_harness["servlet_success"]
    assert success["error"] == ""
    assert success["calls"] == ["removeServletMapping:/dshlab/shell", "removeChild:dshServlet"]
    assert success["state"] == "children=0,mappings=0"

    stubborn = kill_harness["servlet_stubborn"]
    assert "servlet_still_registered_after_cleanup" in stubborn["error"]
    assert stubborn["state"] == "children=1,mappings=0"


def test_listener_removal_works_in_both_tomcat_shapes(kill_harness):
    array_form = kill_harness["listener_array"]
    assert array_form["error"] == ""
    assert "setApplicationEventListeners:0" in array_form["calls"], "Tomcat 7 array field"
    assert array_form["state"] == "present=false"

    list_form = kill_harness["listener_list"]
    assert list_form["error"] == ""
    assert list_form["state"] == "present=false"
    assert not any(
        call.startswith("setApplicationEventListeners") for call in list_form["calls"]
    ), "the List path needs no array rewrite"


def test_the_harness_actually_exercised_the_probe_code():
    """A guard against the harness silently testing its own stubs."""
    for method in (
        "removeFilter",
        "removeFilterDef",
        "dropFilterConfig",
        "filterRegistered",
        "removeServlet",
        "servletRegistered",
        "removeListener",
        "trimListener",
    ):
        assert f" {method}(" in JSP_TEMPLATE
