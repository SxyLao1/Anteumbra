<%--
  Anteumbra memory-shell probe  (marker: ANTEUMBRA-MEMORY-SHELL-PROBE)

  Deployed temporarily by Anteumbra itself into a watched web root, requested
  once over HTTP, then removed together with its directory.

  Contract with the caller:
    * GET request, query parameter "t" must equal the per-run token,
      otherwise this page answers 404 and reveals nothing.
    * Response body is a single JSON object (no HTML, no dependencies).
    * READ ONLY: the probe never registers, removes or modifies anything.

  Written in Java 6 compatible syntax on purpose: Tomcat 7's Jasper still
  compiles JSPs at source level 1.6, so no diamond operator, no try-with-
  resources, no lambdas, no strings in switch.

  Technique follows c0ny1's tomcat-memshell-scanner: walk the Tomcat
  StandardContext through reflection and compare what is registered in memory
  with what actually exists on disk.
--%>
<%@ page contentType="application/json;charset=UTF-8" pageEncoding="UTF-8" session="false" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="java.lang.reflect.Method" %>
<%@ page import="java.net.URL" %>
<%@ page import="java.security.CodeSource" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.Collection" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.Map" %>
<%!
    private static final String PROBE_MARKER = "ANTEUMBRA-MEMORY-SHELL-PROBE";
    private static final String PROBE_TOKEN = "{{PROBE_TOKEN}}";

    /** Sessions can hold a lot of attributes; the probe stays bounded. */
    private static final int MAX_SESSION_ATTRIBUTES = 400;

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

    private static String resourcePath(Class type) {
        try {
            String path = type.getName().replace('.', '/') + ".class";
            ClassLoader loader = type.getClassLoader();
            URL url = loader == null ? ClassLoader.getSystemResource(path) : loader.getResource(path);
            if (url == null) {
                return null;
            }
            String text = url.toString();
            if (text.startsWith("jar:")) {
                int end = text.indexOf("!/");
                return end > 0 ? text.substring(4, end) : text;
            }
            if (text.startsWith("file:")) {
                return text.substring(5);
            }
            return text;
        } catch (Throwable ignored) {
            return null;
        }
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
%>
<%
    String token = request.getParameter("t");
    if (token == null || !PROBE_TOKEN.equals(token)) {
        response.setStatus(404);
        return;
    }

    long started = System.currentTimeMillis();
    List<String> allEntries = new ArrayList<String>();
    String contextPath = null;
    String error = null;
    List<String> containerInfo = new ArrayList<String>();

    try {
        contextPath = request.getContextPath();
        Object standardContext = standardContext(request);
        if (standardContext == null) {
            error = "standard_context_unavailable";
        } else {
            containerInfo.add("context_class:" + standardContext.getClass().getName());
            containerInfo.add("server_info:" + getServletContext().getServerInfo());

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
            containerInfo.add("jvm_input_arguments:" + jvmArgs);
            containerInfo.add("javaagent:" + (jvmArgs.indexOf("-javaagent") >= 0 ? "present" : "none"));
            containerInfo.add("attach_self:" + System.getProperty("jdk.attach.allowAttachSelf", "unset"));

            // ---- filters: names, url patterns, filter instances --------------
            Map<String, Object> filterConfigs = new HashMap<String, Object>();
            Object rawConfigs = field(standardContext, "filterConfigs");
            if (rawConfigs instanceof Map) {
                Map rawMap = (Map) rawConfigs;
                for (Object key : rawMap.keySet()) {
                    filterConfigs.put(String.valueOf(key), rawMap.get(key));
                }
            }

            Object filterMaps = field(standardContext, "filterMaps");
            Object[] maps = null;
            if (filterMaps != null) {
                Object array = field(filterMaps, "array");   // tomcat 7/8/9
                if (array instanceof Object[]) {
                    maps = (Object[]) array;
                } else if (filterMaps instanceof Object[]) {  // tomcat 6
                    maps = (Object[]) filterMaps;
                }
            }
            List<String> seenFilters = new ArrayList<String>();
            if (maps != null) {
                for (int i = 0; i < maps.length; i++) {
                    String filterName = (String) call(maps[i], "getFilterName");
                    List<String> patterns = stringArray(call(maps[i], "getURLPatterns"));
                    Class filterClass = null;
                    // NOTE: "config" is a JSP implicit object, so this local
                    // variable must use another name.
                    Object filterConfig = filterConfigs.get(filterName);
                    if (filterConfig != null) {
                        Object filter = field(filterConfig, "filter");
                        if (filter != null) {
                            filterClass = filter.getClass();
                        }
                    }
                    if (filterName != null) {
                        seenFilters.add(filterName);
                    }
                    allEntries.add(entryJson("filter", filterName,
                            quoteList(patterns), filterClass));
                }
            }

            // Servlet 3.0 filter registrations: on containers where the
            // internal filterConfigs map is not reachable this is the only
            // public way to see a registered filter instance. Names already
            // reported above are skipped.
            try {
                Map registrations = getServletContext().getFilterRegistrations();
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
                    allEntries.add(entryJson("filter", registeredName,
                            quoteList(patterns), registeredClass));
                }
            } catch (Throwable ignored) {
                // Servlet 2.5 containers have no registrations API
            }

            // ---- servlets: mapping -> wrapper -> servlet class ---------------
            Object servletMappings = field(standardContext, "servletMappings");
            Object children = field(standardContext, "children");
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
                                                standardContext.getClass().getClassLoader());
                                    }
                                } catch (Throwable ignored) {
                                    // wrapper not started yet
                                }
                            }
                        }
                    }
                    List<String> patterns = new ArrayList<String>();
                    patterns.add(pattern);
                    allEntries.add(entryJson("servlet", servletName,
                            quoteList(patterns), servletClass));
                }
            }

            // ---- listeners ---------------------------------------------------
            Object listeners = field(standardContext, "applicationEventListenersList");
            if (listeners instanceof Collection) {
                for (Object listener : (Collection) listeners) {
                    if (listener != null) {
                        allEntries.add(entryJson("listener",
                                listener.getClass().getName(), "[]", listener.getClass()));
                    }
                }
            }

            // ---- sessions ----------------------------------------------------
            // Godzilla and similar clients park a dynamically defined payload
            // class inside the HttpSession, so the session table is the one
            // place their "no file on disk" class is visible. Only attributes
            // that are Class objects, or whose value class cannot be resolved
            // to a file, are reported: ordinary session data is noise.
            Object manager = field(standardContext, "manager");
            Object sessions = manager == null ? null : field(manager, "sessions");
            if (sessions instanceof Map) {
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
                        allEntries.add(entryJson("session", holder, "[]", valueClass));
                    }
                }
            }
        }
    } catch (Throwable failure) {
        error = failure.getClass().getName() + ": " + failure.getMessage();
    }

    StringBuilder entries = new StringBuilder();
    for (int i = 0; i < allEntries.size(); i++) {
        if (i > 0) {
            entries.append(',');
        }
        entries.append(allEntries.get(i));
    }

    StringBuilder body = new StringBuilder(1024);
    body.append('{')
        .append("\"probe\":").append(quote(PROBE_MARKER)).append(',')
        .append("\"version\":\"1.0.0\",")
        .append("\"context_path\":").append(quote(contextPath)).append(',')
        .append("\"container\":").append(quoteList(containerInfo)).append(',')
        .append("\"error\":").append(quote(error)).append(',')
        .append("\"entry_count\":").append(allEntries.size()).append(',')
        .append("\"duration_ms\":").append(System.currentTimeMillis() - started).append(',')
        .append("\"entries\":[").append(entries).append(']')
        .append('}');
    out.print(body);
%>
