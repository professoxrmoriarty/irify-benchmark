from __future__ import annotations

from typing import Any


FAMILY_PROFILES: dict[str, dict[str, Any]] = {
    "sql_injection": {
        "rule_type": "SQL Injection",
        "aliases": [
            "SQL注入",
            "SQL Injection",
            "检测 Java SQL 语句拼接漏洞",
            "检测Java SQL注入漏洞",
            "检测 Java MyBatis/iBatis XML Mapper 不安全(${...})参数",
            "代码注入：SQL注入",
        ],
        "rule_selectors": ["cwe-89-sql-injection", "sql注入", "sql injection", "mybatis"],
        "sink_patterns": ["executeQuery(", "executeUpdate(", "prepareStatement(", "createQuery(", "nativeQuery", "queryFor"],
        "supported": True,
    },
    "command_injection": {
        "rule_type": "Command Injection",
        "aliases": [
            "命令注入",
            "Command Injection",
            "检测Java Servlet和SpringMVC中的命令注入漏洞",
            "代码注入：命令注入",
        ],
        "rule_selectors": ["cwe-77-command-injection", "命令注入", "command injection"],
        "sink_patterns": ["Runtime.getRuntime().exec", "ProcessBuilder", "exec(", ".start()", "Method method = clazz.getDeclaredMethod"],
        "supported": True,
    },
    "path_traversal": {
        "rule_type": "Path Traversal",
        "aliases": [
            "路径穿越",
            "Path Traversal",
            "Path Manipulation",
            "检测Java路径穿越漏洞",
            "检测Java路径遍历漏洞",
            "输入验证：路径遍历",
            "检测到Java Springboot文件下载路径遍历漏洞",
        ],
        "rule_selectors": ["cwe-22-path-travel", "cwe-73-unfiltered-file-or-path", "路径穿越", "路径遍历", "file download", "file deletion"],
        "sink_patterns": ["new File(", "Paths.get(", "Files.readAllBytes(", "Files.lines(", "delete(", "FileSystemResource(", "transferTo("],
        "supported": True,
    },
    "file_upload": {
        "rule_type": "Unrestricted File Upload",
        "aliases": [
            "任意文件上传",
            "Unrestricted File Upload",
            "检测Spring MVC任意文件上传漏洞",
            "文件上传",
        ],
        "rule_selectors": ["cwe-434-unrestricted-upload-file", "upload", "文件上传"],
        "sink_patterns": ["MultipartFile", "transferTo(", "UploadUtil", "file.getInputStream()"],
        "supported": True,
    },
    "file_delete": {
        "rule_type": "Arbitrary File Deletion",
        "aliases": [
            "任意文件删除",
            "Arbitrary File Deletion",
            "检测 Java Spring Boot 任意文件删除",
        ],
        "rule_selectors": ["java-spring-arbitrary-file-deletion", "文件删除", "arbitrary file deletion"],
        "sink_patterns": ["delete()", "new File(", "Files.delete(", "file.delete("],
        "supported": True,
    },
    "xml_decoder": {
        "rule_type": "XMLDecoder Injection",
        "aliases": [
            "XMLDecoder Injection",
            "代码注入：XMLDecoder注入",
            "检测Java XMLDecoder反序列化漏洞",
        ],
        "rule_selectors": ["java-xml-decoder-unserialization", "xmldecoder", "XMLDecoder"],
        "sink_patterns": ["new java.beans.XMLDecoder", "new XMLDecoder(", ".readObject()"],
        "supported": True,
    },
    "java_deserialization": {
        "rule_type": "Unsafe Deserialization",
        "aliases": [
            "Unsafe Deserialization",
            "不安全的反序列化",
            "检测Java原生反序列化漏洞",
            "检测Java SnakeYAML反序列化漏洞",
            "检测Java FastJson依赖漏洞",
        ],
        "rule_selectors": ["cwe-502-untrusted-unserialization", "反序列化", "unserialization", "deserialization", "fastjson", "jackson", "xstream", "snakeyaml"],
        "sink_patterns": ["readObject()", "new ObjectInputStream(", "Yaml", "Fastjson", "ObjectMapper", "XStream", "JndiLookup"],
        "supported": True,
    },
    "xxe": {
        "rule_type": "XXE",
        "aliases": [
            "XXE",
            "XML External Entity Injection",
            "XML Entity Expansion Injection",
            "XML外部实体注入",
        ],
        "rule_selectors": ["cwe-611-xxe", "xxe", "xmlreader", "saxparser", "xml input factory", "saxreader"],
        "sink_patterns": ["XMLReaderFactory", "SAXParserFactory", "XMLInputFactory", "DocumentBuilderFactory", "Unmarshaller", "parse(new InputSource", "createXMLReader()"],
        "supported": True,
    },
    "xss": {
        "rule_type": "XSS",
        "aliases": [
            "XSS",
            "反射型XSS",
            "存储型XSS",
            "检测Java SpringBoot RestController XSS漏洞",
            "检测Java Servlet XSS漏洞",
            "检测Spring控制器中未调用的SSTI漏洞",
        ],
        "rule_selectors": ["cwe-79-xss", "xss", "response body xss", "template xss", "servlet xss"],
        "sink_patterns": ["return ", "R.ok(", "response.getWriter()", "model.addAttribute(", "setHeader("],
        "supported": True,
    },
    "ssti": {
        "rule_type": "SSTI",
        "aliases": [
            "SSTI",
            "模板注入",
            "Server-Side Template Injection",
        ],
        "rule_selectors": ["cwe-1336-ssti", "ssti", "template"],
        "sink_patterns": ["return \"vul/ssti/\" +", "return \"vul/ssti", "Model model"],
        "supported": True,
    },
    "spel": {
        "rule_type": "SpEL Injection",
        "aliases": [
            "SpEL Injection",
            "EL表达式注入：Spring",
            "检测Java Spring EL使用",
        ],
        "rule_selectors": ["cwe-94-code-injection", "spel", "spring el", "spring-spel-parser"],
        "sink_patterns": ["parseExpression(", "ExpressionParser", "SpelExpressionParser"],
        "supported": True,
    },
    "ssrf": {
        "rule_type": "SSRF",
        "aliases": [
            "SSRF",
            "服务端请求伪造",
            "检测Java SSRF漏洞",
        ],
        "rule_selectors": ["cwe-918-ssrf", "ssrf"],
        "sink_patterns": ["new URL(", "openConnection(", "URLConnection", "HttpURLConnection"],
        "supported": True,
    },
    "open_redirect": {
        "rule_type": "Open Redirect",
        "aliases": [
            "Open Redirect",
            "URL重定向",
            "检测Java URL重定向漏洞",
        ],
        "rule_selectors": ["cwe-601-url-redirect", "redirect", "url redirection"],
        "sink_patterns": ["sendRedirect(", "setHeader(\"Location", "ResponseEntity.status(", "location("],
        "supported": True,
    },
    "xpath_injection": {
        "rule_type": "XPath Injection",
        "aliases": [
            "XPath Injection",
            "XPath注入",
            "检测Java XPath注入漏洞",
        ],
        "rule_selectors": ["cwe-643-xpath-injection", "xpath"],
        "sink_patterns": ["evaluate(", "XPathExpression", "XPathFactory"],
        "supported": True,
    },
    "cors": {
        "rule_type": "Overly Permissive CORS",
        "aliases": [
            "过于宽松的CORS策略",
            "Overly Permissive CORS",
            "检测Java Spring Framework跨域白名单过于宽松",
        ],
        "rule_selectors": ["cwe-942-overly-permissive-cross-domain-whitelist", "cors", "cross-domain whitelist"],
        "sink_patterns": ["@CrossOrigin(", "setHeader(\"Access-Control-Allow-Origin", "allowedOrigins"],
        "supported": True,
    },
    "csrf": {
        "rule_type": "CSRF",
        "aliases": [
            "Cross-Site Request Forgery",
            "CSRF",
            "跨站请求伪造",
        ],
        "rule_selectors": ["cwe-352-csrf", "csrf"],
        "sink_patterns": ["csrf", "transfer", "change", "session"],
        "supported": True,
    },
    "fake_ip": {
        "rule_type": "Fake IP / XFF Forgery",
        "aliases": [
            "Fake IP",
            "XFF伪造",
            "检测Java中通过不可信请求头导致的IP伪造漏洞",
        ],
        "rule_selectors": ["cwe-807-reliance-on-untrusted-inputs-in-a-security-decision", "fake ip", "xff"],
        "sink_patterns": ["getHeader(", "X-Forwarded-For", "xff"],
        "supported": True,
    },
    "dos": {
        "rule_type": "DoS",
        "aliases": [
            "Denial of Service",
            "DoS",
            "检测Java StringBuilder 拒绝服务漏洞",
        ],
        "rule_selectors": ["cwe-400-uncontrolled-resource-consumption", "dos", "string-builder"],
        "sink_patterns": ["new BufferedImage(", "StringBuilder", "wait(", "readAllBytes("],
        "supported": True,
    },
    "credential_management": {
        "rule_type": "Credential Management",
        "aliases": [
            "硬编码密码",
            "Hardcoded Password",
            "检测通用硬编码凭据",
            "检测Java硬编码弱密码漏洞",
        ],
        "rule_selectors": ["cwe-259-use-of-hard-coded-password", "hardcoded", "credential"],
        "sink_patterns": ["password", "Admin123", "credential", "secret", "token"],
        "supported": True,
    },
    "unsupported": {
        "rule_type": "Unsupported / Out of Scope",
        "aliases": [],
        "rule_selectors": [],
        "sink_patterns": [],
        "supported": False,
    },
}


def get_family_profile(family_key: str) -> dict[str, Any]:
    for key, profile in FAMILY_PROFILES.items():
        if family_key == key or family_key.startswith(key + "."):
            return profile
    return FAMILY_PROFILES["unsupported"]


def recommended_expectation(family_key: str, route: str, safe_guards: list[dict], description: str = "") -> tuple[str, list[str], str]:
    route_text = route.lower()
    desc_text = (description or "").lower()
    if "/safe" not in route_text:
        return "must_alert", ["high", "critical"], "hard_vulnerability"
    strong_guard_types = {"allowlist", "path-check", "xml-feature", "entity-disable", "prepared"}
    weak_guard_types = {"denylist", "validation", "sql-escaping", "csp-header", "deser-autotype-off"}
    guard_types = {item.get("type") for item in safe_guards}
    if family_key == "java_deserialization":
        if "deser-safe-constructor" in guard_types or "deser-safe-mode" in guard_types:
            return "must_not_alert", [], "safe_strong_guard"
        if "deser-autotype-off" in guard_types:
            return "should_warn", ["low", "medium"], "autotype_disabled_but_still_parse"
    if family_key in {"sql_injection", "path_traversal", "command_injection", "xml_decoder", "xxe", "ssrf", "open_redirect", "xpath_injection", "spel", "ssti"}:
        if guard_types & strong_guard_types:
            return "must_not_alert", [], "safe_strong_guard"
        if guard_types & weak_guard_types or "黑名单" in desc_text or "绕过" in desc_text:
            return "should_warn", ["low", "medium"], "guard_present_but_warnable"
        return "must_not_alert", [], "safe_default"
    if family_key in {"java_deserialization", "file_upload", "file_delete", "csrf", "fake_ip", "xss"}:
        if family_key == "xss" and "csp-header" in guard_types:
            return "should_warn", ["low", "medium"], "browser_side_csp_only"
        if guard_types & strong_guard_types:
            return "must_not_alert", [], "safe_strong_guard"
        if guard_types & weak_guard_types:
            return "should_warn", ["low", "medium"], "guard_present_but_warnable"
        return "must_not_alert", [], "safe_default"
    return "must_not_alert", [], "safe_default"


def classify_family(module: str, controller_name: str, title: str, description: str, route: str) -> str:
    text = " ".join([module, controller_name, title, description, route]).lower()
    if module == "sqli":
        return "sql_injection"
    if "sqli" in text or "sql注入" in text:
        return "sql_injection"
    if module == "rce" and "command" in controller_name.lower():
        return "command_injection"
    if "command" in text or "runtime" in text or "processbuilder" in text or "processimpl" in text or "groovy" in text:
        return "command_injection"
    if module == "file":
        if "upload" in controller_name.lower():
            return "file_upload"
        if "delete" in controller_name.lower():
            return "file_delete"
        return "path_traversal"
    if "traversal" in text or "download" in text or "read" in text:
        return "path_traversal"
    if "upload" in text:
        return "file_upload"
    if module == "infoleak" and "dirtraversal" in controller_name.lower():
        return "path_traversal"
    if module == "deserialize":
        if "xmldecoder" in text:
            return "xml_decoder"
        return "java_deserialization"
    if "deserialization" in text or "snakeyaml" in text or "xstream" in text or "fastjson" in text or "jackson" in text or "jndi" in text or "readobject" in text:
        if "xmldecoder" in text:
            return "xml_decoder"
        return "java_deserialization"
    if module == "components":
        if any(name in text for name in ["fastjson", "jackson", "xstream", "shiro", "log4j"]):
            return "java_deserialization"
    if module == "xxe":
        return "xxe"
    if "xxe" in text or "xmlreader" in text or "saxparser" in text or "saxreader" in text or "documentbuilder" in text or "unmarshaller" in text:
        return "xxe"
    if module == "xss":
        return "xss"
    if "xss" in text or "reflect" in text or "stored" in text or "safesave" in text or "whitelist" in text or "owaspencoder" in text or "esapi" in text:
        return "xss"
    if module == "ssti":
        return "ssti"
    if "ssti" in text or "thymeleaf" in text or "freemarker" in text or "velocity" in text:
        return "ssti"
    if module == "spel":
        return "spel"
    if "spel" in text:
        return "spel"
    if module == "ssrf":
        return "ssrf"
    if "ssrf" in text or "urlconnection" in text or "httpurlconnection" in text:
        return "ssrf"
    if module == "csrf":
        return "csrf"
    if "csrf" in text or "transfer" in text:
        return "csrf"
    if module == "crossorigin":
        return "cors"
    if "cors" in text or "crossorigin" in text:
        return "cors"
    if module == "other":
        if "xpath" in text:
            return "xpath_injection"
        if "redirect" in text:
            return "open_redirect"
        if "xff" in text:
            return "fake_ip"
        if "dos" in text:
            return "dos"
        return "other"
    if module == "logic":
        if "horizontal" in text:
            return "logic.idor.horizontal"
        if "vertical" in text:
            return "logic.idor.vertical"
        if "graphic" in text:
            return "logic.captcha.graphic"
        if "sms" in text:
            return "logic.captcha.sms"
        if "pay" in text:
            return "logic.pay"
        return "logic"
    if module == "loginconfront":
        return "loginconfront"
    if module == "springboot":
        return "springboot"
    if module == "infoleak":
        return "infoleak"
    if module == "funny":
        return "funny"
    if module == "system":
        return "system"
    if module == "test":
        return "test"
    if "credential" in text or "密码" in text:
        return "credential_management"
    if "xpath" in text:
        return "xpath_injection"
    if "redirect" in text:
        return "open_redirect"
    if "idor" in text:
        return "unsupported"
    return "unsupported"
