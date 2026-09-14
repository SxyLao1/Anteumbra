<%--
  Anteumbra memory-shell probe  (marker: ANTEUMBRA-MEMORY-SHELL-PROBE)

  Deployed temporarily by Anteumbra itself into a watched web root, requested
  over HTTP, then removed together with its directory.

  Contract with the caller:
    * GET request, query parameter "t" must equal the per-run token, otherwise
      this page answers 404 and reveals nothing.  The token gate is checked
      before anything else and applies to every action.
    * Response body is a single JSON object (no HTML, no dependencies).

  Three actions, selected with the "action" parameter:

    action=probe (default)  read-only report: filters / servlets / listeners /
                            session-held classes currently registered.
    action=dump             forensics for ONE component (kind + name): a
                            manifest of everything the JVM can be asked about
                            it, the class bytes when the class can really be
                            resolved to a classloader resource, and an optional
                            heap dump written to an absolute path supplied by
                            the caller.
    action=kill             remediation: unregister exactly one component,
                            refused unless the component is still the class the
                            caller recorded and is not a deployed file on disk
                            (unless force=1 was passed explicitly).  A filter is
                            removed in four steps - FilterMaps, FilterDef, the
                            ApplicationFilterConfig left behind in the private
                            filterConfigs map, then filterStop/filterStart when
                            the name is somehow still registered - because
                            removeFilterDef() alone only drops the definition
                            (verified against Tomcat 7.0.108 and 9.0.96 bytecode)
                            and would leave the live filter instance registered
                            forever.  Servlets and listeners are verified the same
                            way.  Success is only reported when a fresh
                            enumeration no longer finds the component.

  Honesty rules this file follows, because a probe that guesses is worse than a
  probe that says "unknown":
    * class bytes are only ever the real resource found through the component's
      own classloader.  A class defined at runtime with defineClass has no such
      resource, and no JSP can recover its bytecode from a running JVM; the
      response then carries class_bytes_unavailable_reason and no bytes.
    * a heap dump failure is reported as heap_error while the manifest is still
      returned; the two are never coupled.
    * kill never deletes a file, never edits web.xml, and never touches anything
      beyond the single component it was asked about.
    * a removal that cannot be verified is never reported as done: the caller
      gets removed=false and the concrete reason.

  Written in Java 6 compatible syntax on purpose: Tomcat 7's Jasper still
  compiles JSPs at source level 1.6, so no diamond operator, no try-with-
  resources, no lambdas, no strings in switch, and no Base64 helper from the
  newer JDK (this file carries its own tiny encoder).

  Technique follows c0ny1's tomcat-memshell-scanner: walk the Tomcat
  StandardContext through reflection, compare what is registered in memory with
  what actually exists on disk, and remove a registration through the same
  reflected removeFilterDef/removeFilterMap/removeServletMapping/removeChild
  calls that tool uses - plus the filterConfigs cleanup that tool leaves out
  (its own comment records the leftover as a known, unfixed problem).
--%>
<%@ page contentType="application/json;charset=UTF-8" pageEncoding="UTF-8" session="false" %>
<%@ page import="java.io.ByteArrayOutputStream" %>
<%@ page import="java.io.File" %>
<%@ page import="java.io.FileInputStream" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.lang.management.ManagementFactory" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="java.lang.reflect.Method" %>
<%@ page import="java.net.URL" %>
<%@ page import="java.security.CodeSource" %>
<%@ page import="java.security.MessageDigest" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.Collection" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.Map" %>
<%@ page import="javax.management.MBeanServer" %>
<%@ page import="javax.management.ObjectName" %>
<%!
    private static final String PROBE_MARKER = "ANTEUMBRA-MEMORY-SHELL-PROBE";
    private static final String PROBE_VERSION = "1.1.0";
    private static final String PROBE_TOKEN = "{{PROBE_TOKEN}}";

    private static final String ACTION_PROBE = "probe";
    private static final String ACTION_DUMP = "dump";
    private static final String ACTION_KILL = "kill";

    private static final String KIND_FILTER = "filter";
    private static final String KIND_SERVLET = "servlet";
    private static final String KIND_LISTENER = "listener";
    private static final String KIND_SESSION = "session";

    /** Sessions can hold a lot of attributes; the probe stays bounded. */
    private static final int MAX_SESSION_ATTRIBUTES = 400;

    /** Members and free text are bounded: a hostile class can be enormous. */
    private static final int MAX_MEMBERS = 200;
    private static final int MAX_TEXT = 512;

    /** Bigger than any real servlet class; a cap keeps the response sane. */
    private static final int MAX_CLASS_BYTES = 8 * 1024 * 1024;

    private static final String CLASS_BYTES_RUNTIME_DEFINED =
            "class_defined_at_runtime_without_bytecode_resource";

    private static final String BASE64_CHARS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    private static final String[] SUSPICIOUS_NAMES = {
        "behinder", "godzilla", "antsword", "memshell", "mem-shell",
        "memoryshell", "shell", "webshell", "inject", "payload",
        "cmd", "exec", "proxy", "socks",
    };

    private static String jsonEscape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"') {
                sb.append("\\\"");
            } else if (c == '\\') {
                sb.append("\\\\");
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else if (c < 0x20 || c > 0x7e) {
                String hex = Integer.toHexString(c);
                sb.append("\\u");
                for (int pad = hex.length(); pad < 4; pad++) {
                    sb.append('0');
                }
                sb.append(hex);
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String quote(String value) {
        return value == null ? "null" : "\"" + jsonEscape(value) + "\"";
    }

    private static String quoteList(Collection<String> values) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        if (values != null) {
            for (String value : values) {
                if (!first) {
                    sb.append(',');
                }
                sb.append(quote(value));
                first = false;
            }
        }
        return sb.append(']').toString();
    }

    /** Bound one untrusted string so a hostile class cannot flood the response. */
    private static String truncate(String value, int limit) {
        if (value == null) {
            return null;
        }
        if (value.length() <= limit) {
            return value;
        }
        return value.substring(0, limit) + "...[+" + (value.length() - limit) + " chars]";
    }

    private static boolean truthy(String value) {
        if (value == null) {
            return false;
        }
        String lower = value.trim().toLowerCase(java.util.Locale.ENGLISH);
        return "1".equals(lower) || "true".equals(lower) || "yes".equals(lower)
                || "on".equals(lower);
    }

    // ---- encoding helpers (hand rolled: the JDK encoder is Java 8) -------

    private static String base64(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder(((data.length + 2) / 3) * 4);
        int index = 0;
        while (index + 2 < data.length) {
            int chunk = ((data[index] & 0xff) << 16) | ((data[index + 1] & 0xff) << 8)
                    | (data[index + 2] & 0xff);
            sb.append(BASE64_CHARS.charAt((chunk >> 18) & 0x3f));
            sb.append(BASE64_CHARS.charAt((chunk >> 12) & 0x3f));
            sb.append(BASE64_CHARS.charAt((chunk >> 6) & 0x3f));
            sb.append(BASE64_CHARS.charAt(chunk & 0x3f));
            index += 3;
        }
        int remaining = data.length - index;
        if (remaining == 1) {
            int chunk = (data[index] & 0xff) << 16;
            sb.append(BASE64_CHARS.charAt((chunk >> 18) & 0x3f));
            sb.append(BASE64_CHARS.charAt((chunk >> 12) & 0x3f));
            sb.append("==");
        } else if (remaining == 2) {
            int chunk = ((data[index] & 0xff) << 16) | ((data[index + 1] & 0xff) << 8);
            sb.append(BASE64_CHARS.charAt((chunk >> 18) & 0x3f));
            sb.append(BASE64_CHARS.charAt((chunk >> 12) & 0x3f));
            sb.append(BASE64_CHARS.charAt((chunk >> 6) & 0x3f));
            sb.append('=');
        }
        return sb.toString();
    }

    private static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (int i = 0; i < data.length; i++) {
            int value = data[i] & 0xff;
            if (value < 16) {
                sb.append('0');
            }
            sb.append(Integer.toHexString(value));
        }
        return sb.toString();
    }

    private static String sha256Hex(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return hex(digest.digest(data));
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static String sha256Hex(File file) {
        FileInputStream stream = null;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            stream = new FileInputStream(file);
            byte[] buffer = new byte[64 * 1024];
            int read = stream.read(buffer);
            while (read > 0) {
                digest.update(buffer, 0, read);
                read = stream.read(buffer);
            }
            return hex(digest.digest());
        } catch (Throwable ignored) {
            return "";
        } finally {
            if (stream != null) {
                try {
                    stream.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    // ---- reflection helpers --------------------------------------------

    /** Read a field by name, walking up the class hierarchy. */
    private static Object field(Object target, String name) {
        Class type = target.getClass();
        while (type != null) {
            try {
                Field f = type.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(target);
            } catch (NoSuchFieldException missing) {
                type = type.getSuperclass();
            } catch (Throwable ignored) {
                return null;
            }
        }
        return null;
    }

    /** Invoke a no-argument method by name. */
    private static Object call(Object target, String name) {
        if (target == null) {
            return null;
        }
        Class type = target.getClass();
        while (type != null) {
            try {
                Method m = type.getDeclaredMethod(name);
                m.setAccessible(true);
                return m.invoke(target);
            } catch (NoSuchMethodException missing) {
                type = type.getSuperclass();
            } catch (Throwable ignored) {
                return null;
            }
        }
        return null;
    }

    /**
     * Invoke a one-argument method found by name and by argument compatibility,
     * without importing any container class.  Returns null on success, or a
     * short reason string, because the caller has to report refusals.
     */
    private static String callWithArg(Object target, String name, Object argument,
            Class declaredType) {
        if (target == null) {
            return "target_null";
        }
        Class type = target.getClass();
        while (type != null) {
            Method[] methods;
            try {
                methods = type.getDeclaredMethods();
            } catch (Throwable ignored) {
                return "method_list_unavailable";
            }
            for (int i = 0; i < methods.length; i++) {
                if (!name.equals(methods[i].getName())) {
                    continue;
                }
                Class[] parameters = methods[i].getParameterTypes();
                if (parameters.length != 1) {
                    continue;
                }
                if (declaredType != null && !parameters[0].equals(declaredType)) {
                    continue;
                }
                if (!matchesArgument(parameters[0], argument)) {
                    continue;
                }
                try {
                    methods[i].setAccessible(true);
                    methods[i].invoke(target, new Object[] { argument });
                    return null;
                } catch (Throwable failure) {
                    return failure.getClass().getName() + ": " + failure.getMessage();
                }
            }
            type = type.getSuperclass();
        }
        return "method_not_found:" + name;
    }

    private static boolean matchesArgument(Class parameterType, Object argument) {
        if (argument == null) {
            return !parameterType.isPrimitive();
        }
        if (parameterType.isPrimitive()) {
            return false;
        }
        return parameterType.isInstance(argument);
    }

    /**
     * Invoke a one-argument method and read what it returned.
     *
     * ``errorOut[0]`` is set to a reason on failure and left null on success, so
     * the caller can tell "the method returned null" from "the method is not
     * there" - which is the difference between "nothing is registered" and "this
     * container cannot answer the question".
     */
    private static Object callForValue(Object target, String name, Object argument,
            Class declaredType, String[] errorOut) {
        errorOut[0] = null;
        if (target == null) {
            errorOut[0] = "target_null";
            return null;
        }
        Class type = target.getClass();
        while (type != null) {
            Method[] methods;
            try {
                methods = type.getDeclaredMethods();
            } catch (Throwable ignored) {
                errorOut[0] = "method_list_unavailable";
                return null;
            }
            for (int i = 0; i < methods.length; i++) {
                if (!name.equals(methods[i].getName())) {
                    continue;
                }
                Class[] parameters = methods[i].getParameterTypes();
                if (parameters.length != 1) {
                    continue;
                }
                if (declaredType != null && !parameters[0].equals(declaredType)) {
                    continue;
                }
                if (!matchesArgument(parameters[0], argument)) {
                    continue;
                }
                try {
                    methods[i].setAccessible(true);
                    return methods[i].invoke(target, new Object[] { argument });
                } catch (Throwable failure) {
                    errorOut[0] = failure.getClass().getName() + ": " + failure.getMessage();
                    return null;
                }
            }
            type = type.getSuperclass();
        }
        errorOut[0] = "method_not_found:" + name;
        return null;
    }

    /** True when this container offers that method with that arity. */
    private static boolean hasMethod(Object target, String name, int parameterCount) {
        Class type = target == null ? null : target.getClass();
        while (type != null) {
            Method[] methods;
            try {
                methods = type.getDeclaredMethods();
            } catch (Throwable ignored) {
                return false;
            }
            for (int i = 0; i < methods.length; i++) {
                if (name.equals(methods[i].getName())
                        && methods[i].getParameterTypes().length == parameterCount) {
                    return true;
                }
            }
            type = type.getSuperclass();
        }
        return false;
    }

    private static Class forNameQuietly(String name) {
        try {
            return Class.forName(name);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static Object standardContext(HttpServletRequest request) {
        try {
            Object servletContext = request.getSession(false) != null
                    ? request.getSession(false).getServletContext()
                    : request.getServletContext();
            Object appContext = field(servletContext, "context");
            return appContext == null ? null : field(appContext, "context");
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static ServletContext servletContextOf(HttpServletRequest request) {
        try {
            if (request.getSession(false) != null) {
                return request.getSession(false).getServletContext();
            }
            return request.getServletContext();
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static Object[] filterMapsOf(Object standardContext) {
        Object filterMaps = field(standardContext, "filterMaps");
        if (filterMaps == null) {
            return null;
        }
        Object array = field(filterMaps, "array");   // tomcat 7/8/9
        if (array instanceof Object[]) {
            return (Object[]) array;
        }
        if (filterMaps instanceof Object[]) {        // tomcat 6
            return (Object[]) filterMaps;
        }
        return null;
    }

    private static Map filterConfigMap(Object standardContext) {
        Object rawConfigs = field(standardContext, "filterConfigs");
        return rawConfigs instanceof Map ? (Map) rawConfigs : null;
    }

    private static boolean looksSuspiciousName(String value) {
        if (value == null) {
            return false;
        }
        String lower = value.toLowerCase(java.util.Locale.ENGLISH);
        for (int i = 0; i < SUSPICIOUS_NAMES.length; i++) {
            if (lower.indexOf(SUSPICIOUS_NAMES[i]) >= 0) {
                return true;
            }
        }
        return false;
    }

    /** Short random-looking names are what droppers usually generate. */
    private static boolean looksRandom(String value) {
        if (value == null || value.length() < 6 || value.length() > 16) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '$';
            if (!allowed) {
                return false;
            }
        }
        boolean hasDigit = false;
        boolean hasLower = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c >= '0' && c <= '9') {
                hasDigit = true;
            } else if (c >= 'a' && c <= 'z') {
                hasLower = true;
            }
        }
        return hasDigit && hasLower;
    }

    /** Behinder/Godzilla payload classes carry recognisable members. */
    private static List<String> toolFingerprints(Class type) {
        List<String> reasons = new ArrayList<String>();
        try {
            Method[] methods = type.getDeclaredMethods();
            for (int i = 0; i < methods.length; i++) {
                String name = methods[i].getName();
                if ("getMagic".equals(name)) {
                    reasons.add("method:getMagic");
                } else if ("fillContext".equals(name)) {
                    reasons.add("method:fillContext");
                } else if ("getBasicsInfo".equals(name)) {
                    reasons.add("method:getBasicsInfo");
                } else if ("equals".equals(name)
                        && methods[i].getParameterTypes().length == 1
                        && methods[i].getParameterTypes()[0] == Object.class
                        && methods[i].getReturnType() == Boolean.TYPE) {
                    reasons.add("method:equals(Object)->boolean");
                }
            }
            Field[] fields = type.getDeclaredFields();
            for (int i = 0; i < fields.length; i++) {
                String name = fields[i].getName();
                if ("whatever".equals(name) || "shellCode".equals(name)
                        || "decryptClassStr".equals(name) || "classBody".equals(name)) {
                    reasons.add("field:" + name);
                }
            }
        } catch (Throwable ignored) {
            // a hostile class can throw from reflection; the probe must survive
        }
        return reasons;
    }

    private static String classLoaderName(Class type) {
        try {
            ClassLoader loader = type.getClassLoader();
            return loader == null ? "bootstrap" : loader.getClass().getName();
        } catch (Throwable ignored) {
            return null;
        }
    }

    /** A loader identity that survives being written to disk and read back. */
    private static String classLoaderIdentity(Class type) {
        try {
            ClassLoader loader = type.getClassLoader();
            if (loader == null) {
                return "bootstrap";
            }
            return String.valueOf(loader) + "@@"
                    + Integer.toHexString(System.identityHashCode(loader));
        } catch (Throwable ignored) {
            return null;
        }
    }

    /** Where the class came from: a JAR/directory on disk, or nowhere. */
    private static String codeSource(Class type) {
        try {
            CodeSource source = type.getProtectionDomain().getCodeSource();
            if (source == null || source.getLocation() == null) {
                return null;
            }
            return source.getLocation().toString();
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String protectionDomain(Class type) {
        try {
            return truncate(String.valueOf(type.getProtectionDomain()), MAX_TEXT);
        } catch (Throwable ignored) {
            return null;
        }
    }

    /** The raw classloader resource URL for a class, or null when there is none. */
    private static String classResourceUrl(Class type) {
        try {
            String path = type.getName().replace('.', '/') + ".class";
            ClassLoader loader = type.getClassLoader();
            URL url = loader == null ? ClassLoader.getSystemResource(path) : loader.getResource(path);
            return url == null ? null : url.toString();
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String resourcePath(Class type) {
        String text = classResourceUrl(type);
        if (text == null) {
            return null;
        }
        if (text.startsWith("jar:")) {
            int end = text.indexOf("!/");
            return end > 0 ? text.substring(4, end) : text;
        }
        if (text.startsWith("file:")) {
            return text.substring(5);
        }
        return text;
    }

    /** The filesystem path behind a class resource, when there is one. */
    private static String onDiskPath(Class type) {
        String text = classResourceUrl(type);
        if (text == null) {
            return null;
        }
        if (text.startsWith("jar:file:")) {
            int end = text.indexOf("!/");
            return end > 0 ? text.substring(9, end) : null;
        }
        if (text.startsWith("file:")) {
            return text.substring(5);
        }
        return null;
    }

    private static byte[] readAll(InputStream stream, int limit) throws java.io.IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(8192);
        byte[] chunk = new byte[8192];
        int read = stream.read(chunk);
        while (read > 0) {
            buffer.write(chunk, 0, read);
            if (buffer.size() > limit) {
                return null;
            }
            read = stream.read(chunk);
        }
        return buffer.toByteArray();
    }

    /**
     * The class bytes, or the honest reason there are none.
     *
     * Returns a String[] of {base64, sha256, length, reason, source}.  Only a
     * real classloader resource counts: a class defined at runtime has none,
     * and a JVM offers no supported way to read the bytecode back out of a
     * loaded Class.
     */
    private static String[] classBytesState(Class type) {
        if (type == null) {
            return new String[] { null, null, "0", "class_unavailable", null };
        }
        String source = classResourceUrl(type);
        if (source == null) {
            return new String[] { null, null, "0", CLASS_BYTES_RUNTIME_DEFINED, null };
        }
        InputStream stream = null;
        try {
            String path = type.getName().replace('.', '/') + ".class";
            ClassLoader loader = type.getClassLoader();
            stream = loader == null
                    ? ClassLoader.getSystemResourceAsStream(path)
                    : loader.getResourceAsStream(path);
            if (stream == null) {
                return new String[] { null, null, "0",
                        "class_resource_unreadable: " + source, source };
            }
            byte[] bytes = readAll(stream, MAX_CLASS_BYTES);
            if (bytes == null) {
                return new String[] { null, null, "0",
                        "class_bytes_too_large: more than " + MAX_CLASS_BYTES + " bytes", source };
            }
            if (bytes.length == 0) {
                return new String[] { null, null, "0", "class_resource_empty: " + source, source };
            }
            return new String[] { base64(bytes), sha256Hex(bytes),
                    String.valueOf(bytes.length), null, source };
        } catch (Throwable failure) {
            return new String[] { null, null, "0",
                    "class_resource_read_failed: " + failure.getClass().getName() + ": "
                            + failure.getMessage(), source };
        } finally {
            if (stream != null) {
                try {
                    stream.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private static String memberSignature(Method method) {
        StringBuilder sb = new StringBuilder();
        sb.append(method.getName()).append('(');
        Class[] parameters = method.getParameterTypes();
        for (int i = 0; i < parameters.length; i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(parameters[i].getName());
        }
        sb.append(")->").append(method.getReturnType().getName());
        return truncate(sb.toString(), MAX_TEXT);
    }

    private static List<String> declaredMembers(Class type, boolean methods) {
        List<String> out = new ArrayList<String>();
        if (type == null) {
            return out;
        }
        try {
            if (methods) {
                Method[] found = type.getDeclaredMethods();
                for (int i = 0; i < found.length && i < MAX_MEMBERS; i++) {
                    out.add(memberSignature(found[i]));
                }
            } else {
                Field[] found = type.getDeclaredFields();
                for (int i = 0; i < found.length && i < MAX_MEMBERS; i++) {
                    out.add(truncate(found[i].getName() + ":" + found[i].getType().getName(),
                            MAX_TEXT));
                }
            }
        } catch (Throwable ignored) {
            // a hostile class can throw from reflection
        }
        return out;
    }

    // ---- container observation -----------------------------------------

    /** One shared shape for "what the container looks like right now". */
    private static final class Snapshot {
        String contextPath = null;
        String error = null;
        Object standardContext = null;
        ServletContext servletContext = null;
        final List<String> container = new ArrayList<String>();
        final List<String> entries = new ArrayList<String>();
    }

    private static String entryJson(String type, String name, String urls, Class clazz) {
        List<String> reasons = new ArrayList<String>();
        String resource = clazz == null ? null : resourcePath(clazz);
        String code = clazz == null ? null : codeSource(clazz);
        String loader = clazz == null ? null : classLoaderName(clazz);
        String className = clazz == null ? null : clazz.getName();
        String simpleName = clazz == null ? null : clazz.getSimpleName();

        if (clazz != null && resource == null) {
            reasons.add("class_not_on_disk");
        }
        if (className != null && looksSuspiciousName(className)) {
            reasons.add("class_name_match");
        }
        if (name != null && looksSuspiciousName(name)) {
            reasons.add("registered_name_match");
        }
        if (simpleName != null && looksRandom(simpleName)) {
            reasons.add("random_class_name");
        }
        if (loader != null && (loader.indexOf('$') >= 0
                || "java.lang.ClassLoader".equals(loader))) {
            reasons.add("anonymous_classloader");
        }
        if (code == null && clazz != null) {
            reasons.add("no_code_source");
        }
        if (clazz != null) {
            reasons.addAll(toolFingerprints(clazz));
        }

        StringBuilder sb = new StringBuilder(256);
        sb.append('{')
          .append("\"type\":").append(quote(type)).append(',')
          .append("\"name\":").append(quote(name)).append(',')
          .append("\"urls\":").append(urls == null ? "[]" : urls).append(',')
          .append("\"class\":").append(quote(className)).append(',')
          .append("\"class_loader\":").append(quote(loader)).append(',')
          .append("\"resource\":").append(quote(resource)).append(',')
          .append("\"code_source\":").append(quote(code)).append(',')
          .append("\"suspect\":").append(reasons.isEmpty() ? "false" : "true").append(',')
          .append("\"reasons\":").append(quoteList(reasons))
          .append('}');
        return sb.toString();
    }

    private static List<String> stringArray(Object value) {
        List<String> out = new ArrayList<String>();
        if (value instanceof String[]) {
            String[] items = (String[]) value;
            for (int i = 0; i < items.length; i++) {
                out.add(items[i]);
            }
        } else if (value instanceof Collection) {
            for (Object item : (Collection) value) {
                out.add(String.valueOf(item));
            }
        }
        return out;
    }

    private static void observe(Snapshot snapshot, HttpServletRequest request) {
        try {
            snapshot.contextPath = request.getContextPath();
            snapshot.servletContext = servletContextOf(request);
            snapshot.standardContext = standardContext(request);
            if (snapshot.standardContext == null) {
                snapshot.error = "standard_context_unavailable";
                return;
            }
            snapshot.container.add("context_class:"
                    + snapshot.standardContext.getClass().getName());
            String serverInfo = "";
            try {
                serverInfo = snapshot.servletContext == null
                        ? "" : snapshot.servletContext.getServerInfo();
            } catch (Throwable ignored) {
                serverInfo = "unavailable";
            }
            snapshot.container.add("server_info:" + serverInfo);

            // Instrumentation hint. An agent or retransform based memory shell
            // modifies classes in place, registers nothing, and is therefore
            // invisible to every enumeration below; the only trace a JSP can
            // legitimately read is the JVM's own launch arguments and the
            // self-attach flag.
            String jvmArgs = "";
            try {
                java.lang.management.RuntimeMXBean runtime =
                        java.lang.management.ManagementFactory.getRuntimeMXBean();
                jvmArgs = String.valueOf(runtime.getInputArguments());
            } catch (Throwable ignored) {
                jvmArgs = "unavailable";
            }
            snapshot.container.add("jvm_input_arguments:" + jvmArgs);
            snapshot.container.add("javaagent:"
                    + (jvmArgs.indexOf("-javaagent") >= 0 ? "present" : "none"));
            snapshot.container.add("attach_self:"
                    + System.getProperty("jdk.attach.allowAttachSelf", "unset"));

            collectFilters(snapshot);
            collectServlets(snapshot);
            collectListeners(snapshot);
            collectSessions(snapshot);
        } catch (Throwable failure) {
            snapshot.error = failure.getClass().getName() + ": " + failure.getMessage();
        }
    }

    private static void collectFilters(Snapshot snapshot) {
        Map filterConfigs = filterConfigMap(snapshot.standardContext);
        Object[] maps = filterMapsOf(snapshot.standardContext);
        List<String> seenFilters = new ArrayList<String>();
        if (maps != null) {
            for (int i = 0; i < maps.length; i++) {
                String filterName = (String) call(maps[i], "getFilterName");
                List<String> patterns = stringArray(call(maps[i], "getURLPatterns"));
                Class filterClass = null;
                // NOTE: "config" is a JSP implicit object, so this local
                // variable must use another name.
                Object filterConfig = filterConfigs == null ? null : filterConfigs.get(filterName);
                if (filterConfig != null) {
                    Object filter = field(filterConfig, "filter");
                    if (filter != null) {
                        filterClass = filter.getClass();
                    }
                }
                if (filterName != null) {
                    seenFilters.add(filterName);
                }
                snapshot.entries.add(entryJson(KIND_FILTER, filterName,
                        quoteList(patterns), filterClass));
            }
        }

        // Servlet 3.0 filter registrations: on containers where the internal
        // filterConfigs map is not reachable this is the only public way to see
        // a registered filter instance. Names already reported above are skipped.
        try {
            Map registrations = snapshot.servletContext == null
                    ? null : snapshot.servletContext.getFilterRegistrations();
            for (Object key : registrations.keySet()) {
                Object registration = registrations.get(key);
                if (registration == null) {
                    continue;
                }
                String registeredName = String.valueOf(call(registration, "getName"));
                if (registeredName == null || "null".equals(registeredName)
                        || seenFilters.contains(registeredName)) {
                    continue;
                }
                Class registeredClass = null;
                Object instance = call(registration, "getFilter");
                if (instance != null) {
                    registeredClass = instance.getClass();
                }
                seenFilters.add(registeredName);
                List<String> patterns = stringArray(call(registration, "getURLPatterns"));
                snapshot.entries.add(entryJson(KIND_FILTER, registeredName,
                        quoteList(patterns), registeredClass));
            }
        } catch (Throwable ignored) {
            // Servlet 2.5 containers have no registrations API
        }
    }

    private static void collectServlets(Snapshot snapshot) {
        Object servletMappings = field(snapshot.standardContext, "servletMappings");
        Object children = field(snapshot.standardContext, "children");
        if (servletMappings instanceof Map) {
            Map rawMappings = (Map) servletMappings;
            for (Object key : rawMappings.keySet()) {
                String pattern = String.valueOf(key);
                String servletName = String.valueOf(rawMappings.get(key));
                Class servletClass = null;
                if (children instanceof Map) {
                    Object wrapper = ((Map) children).get(servletName);
                    if (wrapper != null) {
                        Object servlet = call(wrapper, "getServlet");
                        if (servlet != null) {
                            servletClass = servlet.getClass();
                        } else {
                            try {
                                String className = (String) call(wrapper, "getServletClass");
                                if (className != null) {
                                    servletClass = Class.forName(className, false,
                                            snapshot.standardContext.getClass().getClassLoader());
                                }
                            } catch (Throwable ignored) {
                                // wrapper not started yet
                            }
                        }
                    }
                }
                List<String> patterns = new ArrayList<String>();
                patterns.add(pattern);
                snapshot.entries.add(entryJson(KIND_SERVLET, servletName,
                        quoteList(patterns), servletClass));
            }
        }
    }

    private static void collectListeners(Snapshot snapshot) {
        // Tomcat 8/9 keep application event listeners in a List, Tomcat 6/7 in an
        // Object[]; reading only the List made every listener invisible on
        // Tomcat 7, which is exactly the container this probe runs against in
        // the lab.  The public getApplicationEventListeners() covers both.
        List<Object> listeners = eventListeners(snapshot.standardContext);
        for (int i = 0; i < listeners.size(); i++) {
            Object listener = listeners.get(i);
            if (listener != null) {
                snapshot.entries.add(entryJson(KIND_LISTENER,
                        listener.getClass().getName(), "[]", listener.getClass()));
            }
        }
    }

    private static void collectSessions(Snapshot snapshot) {
        // Godzilla and similar clients park a dynamically defined payload
        // class inside the HttpSession, so the session table is the one
        // place their "no file on disk" class is visible. Only attributes
        // that are Class objects, or whose value class cannot be resolved
        // to a file, are reported: ordinary session data is noise.
        Object manager = field(snapshot.standardContext, "manager");
        Object sessions = manager == null ? null : field(manager, "sessions");
        if (!(sessions instanceof Map)) {
            return;
        }
        Map sessionMap = (Map) sessions;
        int inspected = 0;
        for (Object sessionKey : sessionMap.keySet()) {
            if (inspected++ > MAX_SESSION_ATTRIBUTES) {
                break;
            }
            Object session = sessionMap.get(sessionKey);
            Object attributes = session == null ? null : field(session, "attributes");
            if (!(attributes instanceof Map)) {
                continue;
            }
            Map attributeMap = (Map) attributes;
            for (Object attributeKey : attributeMap.keySet()) {
                if (inspected++ > MAX_SESSION_ATTRIBUTES) {
                    break;
                }
                Object value = attributeMap.get(attributeKey);
                if (value == null) {
                    continue;
                }
                Class valueClass = (value instanceof Class) ? (Class) value : value.getClass();
                boolean holdsClass = value instanceof Class;
                // JDK classes are never payloads; skipping them keeps
                // ordinary session state (String.class, enums, ...) quiet.
                if (valueClass.getClassLoader() == null) {
                    continue;
                }
                if (!holdsClass && resourcePath(valueClass) != null) {
                    continue;
                }
                String holder = String.valueOf(attributeKey) + "@" + String.valueOf(sessionKey);
                snapshot.entries.add(entryJson(KIND_SESSION, holder, "[]", valueClass));
            }
        }
    }

    // ---- component lookup (shared by dump and kill) ---------------------

    private static final class Component {
        String kind = null;
        String name = null;
        Class clazz = null;
        Object holder = null;
        final List<String> urls = new ArrayList<String>();
    }

    private static Component locate(Snapshot snapshot, String kind, String name) {
        if (snapshot.standardContext == null || kind == null || name == null
                || name.length() == 0) {
            return null;
        }
        if (KIND_FILTER.equals(kind)) {
            return locateFilter(snapshot, name);
        }
        if (KIND_SERVLET.equals(kind)) {
            return locateServlet(snapshot, name);
        }
        if (KIND_LISTENER.equals(kind)) {
            return locateListener(snapshot, name);
        }
        return null;
    }

    private static Component locateFilter(Snapshot snapshot, String name) {
        Component component = new Component();
        component.kind = KIND_FILTER;
        component.name = name;
        Object[] maps = filterMapsOf(snapshot.standardContext);
        if (maps != null) {
            for (int i = 0; i < maps.length; i++) {
                String filterName = (String) call(maps[i], "getFilterName");
                if (name.equals(filterName)) {
                    List<String> patterns = stringArray(call(maps[i], "getURLPatterns"));
                    for (int p = 0; p < patterns.size(); p++) {
                        component.urls.add(patterns.get(p));
                    }
                }
            }
        }
        Map filterConfigs = filterConfigMap(snapshot.standardContext);
        Object filterConfig = filterConfigs == null ? null : filterConfigs.get(name);
        if (filterConfig != null) {
            component.holder = filterConfig;
            Object filter = field(filterConfig, "filter");
            if (filter != null) {
                component.clazz = filter.getClass();
            }
        }
        if (component.clazz == null) {
            try {
                Map registrations = snapshot.servletContext == null
                        ? null : snapshot.servletContext.getFilterRegistrations();
                Object registration = registrations == null ? null : registrations.get(name);
                if (registration != null) {
                    Object instance = call(registration, "getFilter");
                    if (instance != null) {
                        component.clazz = instance.getClass();
                    }
                }
            } catch (Throwable ignored) {
                // no registrations API on this container
            }
        }        if (component.clazz == null && component.urls.isEmpty()) {
            return null;
        }
        return component;
    }

    private static Component locateServlet(Snapshot snapshot, String name) {
        Object children = field(snapshot.standardContext, "children");
        Object wrapper = children instanceof Map ? ((Map) children).get(name) : null;
        if (wrapper == null) {
            return null;
        }
        Component component = new Component();
        component.kind = KIND_SERVLET;
        component.name = name;
        component.holder = wrapper;
        Object servletMappings = field(snapshot.standardContext, "servletMappings");
        if (servletMappings instanceof Map) {
            Map mappings = (Map) servletMappings;
            for (Object key : mappings.keySet()) {
                if (name.equals(String.valueOf(mappings.get(key)))) {
                    component.urls.add(String.valueOf(key));
                }
            }
        }
        Object servlet = call(wrapper, "getServlet");
        if (servlet != null) {
            component.clazz = servlet.getClass();
        } else {
            try {
                String className = (String) call(wrapper, "getServletClass");
                if (className != null) {
                    component.clazz = Class.forName(className, false,
                            snapshot.standardContext.getClass().getClassLoader());
                }
            } catch (Throwable ignored) {
                // wrapper not started yet
            }
        }
        return component;
    }

    private static Component locateListener(Snapshot snapshot, String name) {
        List<Object> listeners = eventListeners(snapshot.standardContext);
        for (int i = 0; i < listeners.size(); i++) {
            Object listener = listeners.get(i);
            if (listener != null && name.equals(listener.getClass().getName())) {
                Component component = new Component();
                component.kind = KIND_LISTENER;
                component.name = name;
                component.clazz = listener.getClass();
                component.holder = listener;
                return component;
            }
        }
        return null;
    }

    private static boolean onDisk(Class type) {
        return type != null && (resourcePath(type) != null || codeSource(type) != null);
    }

    // ---- action: dump ---------------------------------------------------

    private static String manifestJson(HttpServletRequest request, Snapshot snapshot,
            Component component) {
        Class type = component.clazz;
        String resource = type == null ? null : resourcePath(type);
        String code = type == null ? null : codeSource(type);
        boolean disk = type != null && (resource != null || code != null);
        List<String> jvmArguments = new ArrayList<String>();
        try {
            java.lang.management.RuntimeMXBean runtime =
                    java.lang.management.ManagementFactory.getRuntimeMXBean();
            List<String> arguments = runtime.getInputArguments();
            if (arguments != null) {
                for (int i = 0; i < arguments.size(); i++) {
                    jvmArguments.add(arguments.get(i));
                }
            }
        } catch (Throwable ignored) {
            jvmArguments.add("unavailable");
        }
        String serverInfo = "";
        try {
            serverInfo = snapshot.servletContext == null
                    ? "" : snapshot.servletContext.getServerInfo();
        } catch (Throwable ignored) {
            serverInfo = "";
        }

        StringBuilder sb = new StringBuilder(2048);
        sb.append('{')
          .append("\"kind\":").append(quote(component.kind)).append(',')
          .append("\"name\":").append(quote(component.name)).append(',')
          .append("\"urls\":").append(quoteList(component.urls)).append(',')
          .append("\"class_name\":").append(quote(type == null ? null : type.getName())).append(',')
          .append("\"class_loader\":").append(quote(type == null ? null
                  : classLoaderName(type))).append(',')
          .append("\"class_loader_identity\":").append(quote(type == null ? null
                  : classLoaderIdentity(type))).append(',')
          .append("\"code_source\":").append(quote(code)).append(',')
          .append("\"resource\":").append(quote(resource)).append(',')
          .append("\"on_disk\":").append(disk ? "true" : "false").append(',')
          .append("\"on_disk_path\":").append(quote(type == null ? null
                  : onDiskPath(type))).append(',')
          .append("\"methods\":").append(quoteList(declaredMembers(type, true))).append(',')
          .append("\"fields\":").append(quoteList(declaredMembers(type, false))).append(',')
          .append("\"protection_domain\":").append(quote(type == null ? null
                  : protectionDomain(type))).append(',')
          .append("\"container\":").append(quoteList(snapshot.container)).append(',')
          .append("\"container_server_info\":").append(quote(serverInfo)).append(',')
          .append("\"context_path\":").append(quote(snapshot.contextPath)).append(',')
          .append("\"probe_url\":").append(quote(probeUrl(request))).append(',')
          .append("\"jvm_input_arguments\":").append(quoteList(jvmArguments)).append(',')
          .append("\"attach_self\":").append(quote(
                  System.getProperty("jdk.attach.allowAttachSelf", "unset"))).append(',')
          .append("\"captured_at\":").append(System.currentTimeMillis())
          .append('}');
        return sb.toString();
    }

    /**
     * The URL the probe itself was reached at, without the query string: the
     * per-run token must never be written into an artifact on disk.
     */
    private static String probeUrl(HttpServletRequest request) {
        try {
            return request.getRequestURL().toString();
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static final class HeapState {
        String path = null;
        long bytes = 0;
        String sha256 = null;
        String error = null;
        boolean live = false;
        boolean requested = false;
    }

    /**
     * Ask the HotSpot diagnostic MXBean for a heap dump.
     *
     * The path is absolute and comes from the caller; the size pre-check only
     * refuses when the free space is clearly below what a dump of this JVM
     * could need, and any failure is reported as a string so the manifest is
     * still returned.  A dump is never attempted without a path.
     */
    private static HeapState heapDump(String path, boolean live, long maxMb) {
        HeapState state = new HeapState();
        state.path = path;
        state.live = live;
        state.requested = path != null && path.length() > 0;
        if (!state.requested) {
            state.error = "heap_path_missing";
            return state;
        }
        try {
            File target = new File(path);
            File parent = target.getParentFile();
            if (parent != null && !parent.isDirectory()) {
                state.error = "heap_directory_missing: " + parent.getAbsolutePath();
                return state;
            }
            if (maxMb > 0) {
                long bound = maxMb * 1024L * 1024L;
                long maxHeap = Runtime.getRuntime().maxMemory();
                if (maxHeap > 0 && maxHeap < bound) {
                    bound = maxHeap;
                }
                long usable = -1;
                try {
                    usable = parent == null ? target.getUsableSpace() : parent.getUsableSpace();
                } catch (Throwable ignored) {
                    usable = -1;
                }
                if (usable >= 0 && usable < bound) {
                    state.error = "insufficient_free_space: " + usable
                            + " bytes free where " + bound + " bytes could be needed";
                    return state;
                }
            }
            MBeanServer server = ManagementFactory.getPlatformMBeanServer();
            ObjectName diagnostic = new ObjectName("com.sun.management:type=HotSpotDiagnostic");
            if (server == null || !server.isRegistered(diagnostic)) {
                state.error = "hotspot_diagnostic_mbean_unavailable";
                return state;
            }
            server.invoke(diagnostic, "dumpHeap",
                    new Object[] { path, Boolean.valueOf(live) },
                    new String[] { "java.lang.String", "boolean" });
            File written = new File(path);
            if (!written.isFile()) {
                state.error = "heap_file_not_created: " + path;
                return state;
            }
            state.bytes = written.length();
            state.sha256 = sha256Hex(written);
            return state;
        } catch (Throwable failure) {
            state.error = "heap_dump_failed: " + failure.getClass().getName() + ": "
                    + failure.getMessage();
            return state;
        }
    }

    private static String heapJson(HeapState state) {
        if (state == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(256);
        sb.append('{')
          .append("\"heap_requested\":").append(state.requested ? "true" : "false").append(',')
          .append("\"heap_path\":").append(quote(state.path)).append(',')
          .append("\"heap_bytes\":").append(state.bytes).append(',')
          .append("\"heap_sha256\":").append(quote(state.sha256)).append(',')
          .append("\"heap_live\":").append(state.live ? "true" : "false").append(',')
          .append("\"heap_error\":").append(quote(state.error))
          .append('}');
        return sb.toString();
    }

    private static String refusal(String action, String kind, String name, Snapshot snapshot,
            String reason, long started) {
        return actionEnvelope(action, snapshot, started)
                .append(",\"removed\":false,\"refused\":true,\"reason\":").append(quote(reason))
                .append(",\"kind\":").append(quote(kind))
                .append(",\"name\":").append(quote(name))
                .append('}').toString();
    }

    private static StringBuilder actionEnvelope(String action, Snapshot snapshot, long started) {
        StringBuilder sb = new StringBuilder(4096);
        sb.append('{')
          .append("\"probe\":").append(quote(PROBE_MARKER)).append(',')
          .append("\"version\":").append(quote(PROBE_VERSION)).append(',')
          .append("\"action\":").append(quote(action)).append(',')
          .append("\"context_path\":").append(quote(snapshot.contextPath)).append(',')
          .append("\"container\":").append(quoteList(snapshot.container)).append(',')
          .append("\"error\":").append(quote(snapshot.error)).append(',')
          .append("\"entry_count\":").append(snapshot.entries.size()).append(',')
          .append("\"duration_ms\":").append(System.currentTimeMillis() - started).append(',')
          .append("\"entries\":").append(entryArray(snapshot));
        return sb;
    }

    private static String entryArray(Snapshot snapshot) {
        StringBuilder entries = new StringBuilder(512);
        entries.append('[');
        for (int i = 0; i < snapshot.entries.size(); i++) {
            if (i > 0) {
                entries.append(',');
            }
            entries.append(snapshot.entries.get(i));
        }
        return entries.append(']').toString();
    }

    private static String probeResponse(Snapshot snapshot, long started) {
        return actionEnvelope(ACTION_PROBE, snapshot, started).append('}').toString();
    }

    private static String dumpResponse(HttpServletRequest request, Snapshot snapshot,
            long started) {
        String kind = request.getParameter("kind");
        String name = request.getParameter("name");
        if (kind == null || (!KIND_FILTER.equals(kind) && !KIND_SERVLET.equals(kind)
                && !KIND_LISTENER.equals(kind))) {
            return refusal(ACTION_DUMP, kind, name, snapshot, "unknown_kind", started);
        }
        if (name == null || name.length() == 0) {
            return refusal(ACTION_DUMP, kind, name, snapshot, "invalid_component", started);
        }
        Component component = locate(snapshot, kind, name);
        if (component == null || component.clazz == null) {
            return refusal(ACTION_DUMP, kind, name, snapshot, "component_not_found", started);
        }

        String[] classBytes = classBytesState(component.clazz);
        HeapState heap = heapDump(request.getParameter("heap_path"),
                truthy(request.getParameter("heap_live")),
                longParameter(request, "heap_max_mb"));

        StringBuilder sb = actionEnvelope(ACTION_DUMP, snapshot, started);
        sb.append(",\"removed\":false,\"refused\":false,\"reason\":null")
          .append(",\"kind\":").append(quote(component.kind))
          .append(",\"name\":").append(quote(component.name))
          .append(",\"class_name\":").append(quote(component.clazz.getName()))
          .append(",\"manifest\":").append(manifestJson(request, snapshot, component))
          .append(",\"class_bytes_b64\":").append(quote(classBytes[0]))
          .append(",\"class_bytes_len\":").append(classBytes[2])
          .append(",\"class_bytes_sha256\":").append(quote(classBytes[1]))
          .append(",\"class_bytes_source\":").append(quote(classBytes[4]))
          .append(",\"class_bytes_unavailable_reason\":").append(quote(classBytes[3]))
          .append(",\"heap\":").append(heapJson(heap))
          .append(",\"heap_error\":").append(quote(heap == null ? null : heap.error))
          .append('}');
        return sb.toString();
    }

    private static long longParameter(HttpServletRequest request, String name) {
        try {
            String value = request.getParameter(name);
            if (value == null || value.length() == 0) {
                return 0L;
            }
            return Long.parseLong(value.trim());
        } catch (Throwable ignored) {
            return 0L;
        }
    }

    // ---- action: kill ---------------------------------------------------

    /**
     * Remove one filter, and only report success when it is really gone.
     *
     * Four steps, in this order, because a filter name lives in three separate
     * places inside StandardContext and a container does not clean all of them:
     *
     *   1. every FilterMap of that name  - the filter stops being applied on the
     *      very next request, even if a later step fails;
     *   2. the FilterDef                - removeFilterDef(FilterDef);
     *   3. the ApplicationFilterConfig  - removed from the private filterConfigs
     *      map explicitly.  Verified against Tomcat 7.0.108 and 9.0.96 bytecode:
     *      removeFilterDef() only drops the entry from filterDefs and never
     *      touches filterConfigs, so the live filter instance stays registered
     *      and keeps showing up in every enumeration.  c0ny1's tool leaves
     *      exactly this behind (its own comment records that the leftover
     *      filterConfig entries are a known, unfixed problem).
     *   4. verification               - and only if the name is still registered,
     *      filterStop() + filterStart() so the container rebuilds its runtime
     *      filter state from the definitions that are left.
     */
    private static String removeFilter(Object standardContext, String name) {
        Map filterConfigs = filterConfigMap(standardContext);
        if (filterConfigs == null) {
            // Without the configs map the removal cannot be verified, and an
            // unverifiable removal is not something this probe will claim.
            return "filter_configs_unavailable";
        }
        Object appFilterConfig = null;
        try {
            appFilterConfig = filterConfigs.get(name);
        } catch (Throwable ignored) {
            appFilterConfig = null;
        }

        // 1) mappings first: the filter is disabled immediately.
        Object[] maps = filterMapsOf(standardContext);
        List<Object> doomed = new ArrayList<Object>();
        if (maps != null) {
            for (int i = 0; i < maps.length; i++) {
                if (name.equals(call(maps[i], "getFilterName"))) {
                    doomed.add(maps[i]);
                }
            }
        }
        for (int i = 0; i < doomed.size(); i++) {
            String mapError = callWithArg(standardContext, "removeFilterMap", doomed.get(i), null);
            if (mapError != null) {
                return "remove_filter_map_failed: " + mapError;
            }
        }

        // 2) the definition.
        Object filterDef = appFilterConfig == null ? null : field(appFilterConfig, "filterDef");
        if (filterDef == null) {
            filterDef = findFilterDef(standardContext, name);
        }
        if (filterDef == null) {
            return "filter_def_unavailable";
        }
        String defError = removeFilterDef(standardContext, filterDef);
        if (defError != null) {
            return defError;
        }

        // 3) the runtime config, which the container leaves behind.
        dropFilterConfig(filterConfigs, name);

        // 4) verify, and rebuild the container's filter state only if needed.
        String stopStartNote = "";
        if (filterRegistered(standardContext, name)) {
            if (hasMethod(standardContext, "filterStop", 0)
                    && hasMethod(standardContext, "filterStart", 0)) {
                call(standardContext, "filterStop");
                Object restarted = call(standardContext, "filterStart");
                if (Boolean.FALSE.equals(restarted)) {
                    stopStartNote = " (filterStart returned false)";
                }
            }
            if (filterRegistered(standardContext, name)) {
                return "filter_still_registered_after_cleanup" + stopStartNote;
            }
        }
        return null;
    }

    /** True when the container still knows this filter name anywhere. */
    private static boolean filterRegistered(Object standardContext, String name) {
        Map configs = filterConfigMap(standardContext);
        if (configs != null) {
            try {
                if (configs.get(name) != null) {
                    return true;
                }
            } catch (Throwable ignored) {
                // an unreadable configs map is not evidence of removal
            }
        }
        if (findFilterDef(standardContext, name) != null) {
            return true;
        }
        Object[] maps = filterMapsOf(standardContext);
        if (maps != null) {
            for (int i = 0; i < maps.length; i++) {
                if (name.equals(call(maps[i], "getFilterName"))) {
                    return true;
                }
            }
        }
        return false;
    }

    /** The FilterDef registered under this name, by public API or by field. */
    private static Object findFilterDef(Object standardContext, String name) {
        String[] errorOut = new String[1];
        Object found = callForValue(standardContext, "findFilterDef", name, String.class, errorOut);
        if (errorOut[0] == null && found != null) {
            return found;
        }
        Object defs = field(standardContext, "filterDefs");
        if (defs instanceof Map) {
            try {
                Object byField = ((Map) defs).get(name);
                if (byField != null) {
                    return byField;
                }
            } catch (Throwable ignored) {
                // unreadable registry
            }
        }
        return null;
    }

    /**
     * removeFilterDef(FilterDef), trying the descriptor class of this very
     * instance first: Tomcat 9 moved FilterDef to
     * org.apache.tomcat.util.descriptor.web, Tomcat 7 keeps it in
     * org.apache.catalina.deploy, and the instance in hand is always right.
     */
    private static String removeFilterDef(Object standardContext, Object filterDef) {
        List<Class> candidates = new ArrayList<Class>();
        if (filterDef != null) {
            candidates.add(filterDef.getClass());
        }
        Class tomcat8 = forNameQuietly("org.apache.tomcat.util.descriptor.web.FilterDef");
        if (tomcat8 != null) {
            candidates.add(tomcat8);
        }
        Class tomcat7 = forNameQuietly("org.apache.catalina.deploy.FilterDef");
        if (tomcat7 != null) {
            candidates.add(tomcat7);
        }
        candidates.add(null);
        String lastError = null;
        for (int i = 0; i < candidates.size(); i++) {
            String error = callWithArg(standardContext, "removeFilterDef", filterDef,
                    candidates.get(i));
            if (error == null) {
                return null;
            }
            if (error.indexOf("method_not_found") == 0) {
                lastError = error;
                continue;
            }
            // the method exists and threw: that is a real failure
            return "remove_filter_def_failed: " + error;
        }
        return "remove_filter_def_failed: " + (lastError == null ? "method_not_found" : lastError);
    }

    /**
     * Drop one name from the container's private filterConfigs map.
     *
     * ApplicationFilterConfig.release() is package-private on Tomcat 7/9, so it
     * is a best-effort call: releasing keeps the container's own bookkeeping
     * consistent, but the entry is removed either way, because a filter that
     * cannot be released must still not stay registered.
     */
    private static boolean dropFilterConfig(Map filterConfigs, String name) {
        if (filterConfigs == null) {
            return false;
        }
        Object removed = null;
        try {
            removed = filterConfigs.remove(name);
        } catch (Throwable ignored) {
            return false;
        }
        if (removed != null) {
            call(removed, "release");
            return true;
        }
        return false;
    }

    /** Result of one servlet removal: the mapping goes, then the wrapper. */
    private static String removeServlet(Object standardContext, String name) {
        Object children = field(standardContext, "children");
        Object wrapper = children instanceof Map ? ((Map) children).get(name) : null;
        if (wrapper == null) {
            return "servlet_wrapper_unavailable";
        }
        Object servletMappings = field(standardContext, "servletMappings");
        List<String> patterns = new ArrayList<String>();
        if (servletMappings instanceof Map) {
            Map mappings = (Map) servletMappings;
            List<String> keys = new ArrayList<String>();
            for (Object key : mappings.keySet()) {
                keys.add(String.valueOf(key));
            }
            for (int i = 0; i < keys.size(); i++) {
                if (name.equals(String.valueOf(mappings.get(keys.get(i))))) {
                    patterns.add(keys.get(i));
                }
            }
        }
        if (patterns.isEmpty()) {
            return "servlet_mapping_unavailable";
        }
        for (int i = 0; i < patterns.size(); i++) {
            String error = callWithArg(standardContext, "removeServletMapping",
                    patterns.get(i), String.class);
            if (error != null) {
                return "remove_servlet_mapping_failed: " + error;
            }
        }
        // Tomcat 6 needs removeChild as well; on 7+ it also drops the wrapper's
        // remaining mappings.
        String childError = callWithArg(standardContext, "removeChild", wrapper, null);
        if (childError != null && childError.indexOf("method_not_found") != 0) {
            return "remove_child_failed: " + childError;
        }
        if (servletRegistered(standardContext, name)) {
            return "servlet_still_registered_after_cleanup";
        }
        return null;
    }

    /** True when the container still has this servlet name mapped or as a child. */
    private static boolean servletRegistered(Object standardContext, String name) {
        Object children = field(standardContext, "children");
        if (children instanceof Map) {
            try {
                if (((Map) children).get(name) != null) {
                    return true;
                }
            } catch (Throwable ignored) {
                // unreadable children map
            }
        }
        Object servletMappings = field(standardContext, "servletMappings");
        if (servletMappings instanceof Map) {
            try {
                for (Object value : ((Map) servletMappings).values()) {
                    if (name.equals(String.valueOf(value))) {
                        return true;
                    }
                }
            } catch (Throwable ignored) {
                // unreadable mappings
            }
        }
        return false;
    }

    /**
     * Remove one listener instance, from wherever this container keeps it.
     *
     * Tomcat 8/9 hold a List behind getApplicationEventListeners()/setApplicationEventListeners();
     * Tomcat 6/7 hold an Object[] behind the very same public pair, and only the
     * array field exists there.  Both shapes are handled, and the result is
     * verified by reading the container back.
     */
    private static String removeListener(Object standardContext, Object listener) {
        boolean known = false;
        Object list = field(standardContext, "applicationEventListenersList");
        if (list instanceof Collection) {
            known = true;
            try {
                ((Collection) list).remove(listener);
            } catch (Throwable failure) {
                return "listener_remove_failed: " + failure.getClass().getName() + ": "
                        + failure.getMessage();
            }
        }
        // The public array view: after the List removal above it no longer holds
        // the instance on Tomcat 8/9, and on Tomcat 7 it is the only storage.
        Object fromApi = call(standardContext, "getApplicationEventListeners");
        if (fromApi instanceof Object[]) {
            known = true;
            Object[] trimmed = trimListener((Object[]) fromApi, listener);
            if (trimmed != null) {
                String setError = callWithArg(standardContext, "setApplicationEventListeners",
                        trimmed, Object[].class);
                if (setError != null) {
                    setField(standardContext, "applicationEventListenersObjects", trimmed);
                }
            }
        } else {
            Object objects = field(standardContext, "applicationEventListenersObjects");
            if (objects instanceof Object[]) {
                known = true;
                Object[] trimmed = trimListener((Object[]) objects, listener);
                if (trimmed != null) {
                    setField(standardContext, "applicationEventListenersObjects", trimmed);
                }
            }
        }
        if (!known) {
            return "listener_list_unavailable";
        }
        // Tomcat 9 has addApplicationEventListener but no remove counterpart:
        // call it when a container does provide one, ignore it when none exists.
        callWithArg(standardContext, "removeApplicationEventListener", listener, null);
        if (listenerRegistered(standardContext, listener)) {
            return "listener_still_registered_after_cleanup";
        }
        return null;
    }

    /** The same array without this instance, or null when it was not in it. */
    private static Object[] trimListener(Object[] listeners, Object listener) {
        List<Object> kept = new ArrayList<Object>();
        boolean dropped = false;
        for (int i = 0; i < listeners.length; i++) {
            if (listeners[i] == listener) {
                dropped = true;
                continue;
            }
            kept.add(listeners[i]);
        }
        if (!dropped) {
            return null;
        }
        return kept.toArray(new Object[kept.size()]);
    }

    /** Every application event listener this container currently holds. */
    private static List<Object> eventListeners(Object standardContext) {
        List<Object> out = new ArrayList<Object>();
        if (standardContext == null) {
            return out;
        }
        Object fromApi = call(standardContext, "getApplicationEventListeners");
        if (fromApi instanceof Object[]) {
            Object[] items = (Object[]) fromApi;
            for (int i = 0; i < items.length; i++) {
                if (items[i] != null) {
                    out.add(items[i]);
                }
            }
            return out;
        }
        Object list = field(standardContext, "applicationEventListenersList");
        if (list instanceof Collection) {
            for (Object item : (Collection) list) {
                if (item != null) {
                    out.add(item);
                }
            }
            return out;
        }
        Object objects = field(standardContext, "applicationEventListenersObjects");
        if (objects instanceof Object[]) {
            Object[] items = (Object[]) objects;
            for (int i = 0; i < items.length; i++) {
                if (items[i] != null) {
                    out.add(items[i]);
                }
            }
        }
        return out;
    }

    private static boolean listenerRegistered(Object standardContext, Object listener) {
        List<Object> listeners = eventListeners(standardContext);
        for (int i = 0; i < listeners.size(); i++) {
            if (listeners.get(i) == listener) {
                return true;
            }
        }
        return false;
    }

    private static void setField(Object target, String name, Object value) {
        Class type = target == null ? null : target.getClass();
        while (type != null) {
            try {
                Field f = type.getDeclaredField(name);
                f.setAccessible(true);
                f.set(target, value);
                return;
            } catch (NoSuchFieldException missing) {
                type = type.getSuperclass();
            } catch (Throwable ignored) {
                return;
            }
        }
    }

    private static String killResponse(HttpServletRequest request, Snapshot snapshot,
            long started) {
        String kind = request.getParameter("kind");
        String name = request.getParameter("name");
        String expectClass = request.getParameter("expect_class");
        boolean force = truthy(request.getParameter("force"));

        if (kind == null || (!KIND_FILTER.equals(kind) && !KIND_SERVLET.equals(kind)
                && !KIND_LISTENER.equals(kind))) {
            return refusal(ACTION_KILL, kind, name, snapshot, "unknown_kind", started);
        }
        if (name == null || name.length() == 0) {
            return refusal(ACTION_KILL, kind, name, snapshot, "invalid_component", started);
        }
        Component component = locate(snapshot, kind, name);
        if (component == null || component.clazz == null) {
            return refusal(ACTION_KILL, kind, name, snapshot, "component_not_found", started);
        }
        String actualClass = component.clazz.getName();
        if (expectClass == null || expectClass.length() == 0) {
            return refusal(ACTION_KILL, kind, name, snapshot, "expect_class_required", started);
        }
        if (!expectClass.equals(actualClass)) {
            return refusal(ACTION_KILL, kind, name, snapshot,
                    "class_name_mismatch: expected " + expectClass + " but found " + actualClass,
                    started);
        }
        if (onDisk(component.clazz) && !force) {
            return refusal(ACTION_KILL, kind, name, snapshot,
                    "class_on_disk: " + actualClass + " resolves to "
                            + resourcePath(component.clazz)
                            + " (pass force=1 to remove a deployed component)",
                    started);
        }

        // Captured before the removal so the caller sees the state the decision
        // was made on, not the state it produced.
        String beforeJson = beforeComponentJson(component);

        String error = null;
        if (KIND_FILTER.equals(kind)) {
            error = removeFilter(snapshot.standardContext, name);
        } else if (KIND_SERVLET.equals(kind)) {
            error = removeServlet(snapshot.standardContext, name);
        } else {
            error = removeListener(snapshot.standardContext, component.holder);
        }

        Snapshot after = new Snapshot();
        after.contextPath = snapshot.contextPath;
        observe(after, request);
        // "removed" is only true when the component is really gone after the
        // removal: an enumeration that still finds it is the honest answer.
        Component remaining = locate(after, kind, name);
        boolean removed = error == null && remaining == null;

        StringBuilder sb = actionEnvelope(ACTION_KILL, after, started);
        sb.append(",\"removed\":").append(removed ? "true" : "false")
          .append(",\"refused\":false")
          .append(",\"reason\":").append(quote(error))
          .append(",\"kind\":").append(quote(kind))
          .append(",\"name\":").append(quote(name))
          .append(",\"expect_class\":").append(quote(expectClass))
          .append(",\"force\":").append(force ? "true" : "false")
          .append(",\"removal_error\":").append(quote(error))
          .append(",\"still_present\":").append(remaining == null ? "false" : "true")
          .append(",\"before_component\":").append(beforeJson)
          .append(",\"after_component\":").append(remaining == null ? "null"
                  : beforeComponentJson(remaining))
          .append('}');
        return sb.toString();
    }

    private static String beforeComponentJson(Component component) {
        StringBuilder sb = new StringBuilder(256);
        sb.append('{')
          .append("\"kind\":").append(quote(component.kind)).append(',')
          .append("\"name\":").append(quote(component.name)).append(',')
          .append("\"class_name\":").append(quote(component.clazz == null
                  ? null : component.clazz.getName())).append(',')
          .append("\"urls\":").append(quoteList(component.urls))
          .append('}');
        return sb.toString();
    }
%>
<%
    String probeToken = request.getParameter("t");
    if (probeToken == null || !PROBE_TOKEN.equals(probeToken)) {
        response.setStatus(404);
        return;
    }

    String probeAction = request.getParameter("action");
    if (probeAction == null || probeAction.length() == 0) {
        probeAction = ACTION_PROBE;
    }

    long probeStarted = System.currentTimeMillis();
    Snapshot probeSnapshot = new Snapshot();
    observe(probeSnapshot, request);

    String probeBody;
    if (ACTION_DUMP.equals(probeAction)) {
        probeBody = dumpResponse(request, probeSnapshot, probeStarted);
    } else if (ACTION_KILL.equals(probeAction)) {
        probeBody = killResponse(request, probeSnapshot, probeStarted);
    } else {
        probeBody = probeResponse(probeSnapshot, probeStarted);
    }
    out.print(probeBody);
%>
