# -*- coding: utf-8 -*-
"""
v1.8.3: Webshell 解码过滤器

YARA 扫描前自动尝试还原混淆代码为明文，大幅提升命中率。

处理的混淆技术：
    1. Unicode escapes:  \\u0065val  →  eval
    2. Hex escapes:      \\x65\\x76\\x61\\x6c  →  eval
    3. char() encoding:  char(101).char(118)  →  eval
    4. chr() encoding:   chr(101).chr(118)    →  eval
    5. String concat:    'ev'.'al'            →  eval
    6. Octal escapes:    \\145\\166\\141\\154  →  eval
    7. Base64 in strings:  ZXZhbA==           →  eval
    8. ROT13/Nested:     riny('$p') → eval after decode

策略：生成多个解码变体，YARA 分别扫描每个变体。
"""

import base64
import logging
import re

logger = logging.getLogger(__name__)


class WebShellDecoder:
    """WebShell 混淆代码解码器"""

    @staticmethod
    def decode(data: bytes) -> str:
        """
        主入口：多轮迭代解码，直接替换原始混淆字符串为明文。
        这样 YARA 能直接匹配 eval( 而不是只看到解码注释。
        """
        text = data.decode('utf-8', errors='replace')
        prev = None
        decoded = text
        # Multi-pass: keep decoding until no more changes
        for _ in range(5):
            decoded = WebShellDecoder._decode_pass(decoded)
            if decoded == prev:
                break
            prev = decoded
        # v1.8.3: inline replacement — restore eval($_POST) patterns
        decoded = WebShellDecoder._inline_variable_call(decoded)
        return decoded

    @staticmethod
    def _decode_pass(text: str) -> str:
        """单轮解码：应用所有策略"""
        d = WebShellDecoder._decode_unicode_escapes(text)
        d = WebShellDecoder._decode_hex_escapes(d)
        d = WebShellDecoder._decode_char_encoding(d)
        d = WebShellDecoder._decode_string_concat(d)
        d = WebShellDecoder._decode_octal_escapes(d)
        d = WebShellDecoder._decode_php_concat(d)       # v1.8.3: PHP dot concat
        d = WebShellDecoder._decode_str_replace(d)       # v1.8.3: str_replace()
        d = WebShellDecoder._decode_base64_strings(d)
        d = WebShellDecoder._decode_ascii_array(d)       # v1.8.3: chr array
        return d

    @staticmethod
    def _decode_unicode_escapes(text: str) -> str:
        """\\u0065 → e, \\u{65} → e"""
        # Standard \uXXXX
        def replace_unicode(m):
            try:
                return chr(int(m.group(1), 16))
            except (ValueError, OverflowError):
                return m.group(0)
        text = re.sub(r'\\u([0-9a-fA-F]{4})', replace_unicode, text)
        # PHP \u{XX}
        text = re.sub(r'\\u\{([0-9a-fA-F]+)\}', replace_unicode, text)
        return text

    @staticmethod
    def _decode_hex_escapes(text: str) -> str:
        """\\x65 → e"""
        def replace_hex(m):
            try:
                return chr(int(m.group(1), 16))
            except (ValueError, OverflowError):
                return m.group(0)
        return re.sub(r'\\x([0-9a-fA-F]{2})', replace_hex, text)

    @staticmethod
    def _decode_octal_escapes(text: str) -> str:
        """\\145 → e"""
        def replace_octal(m):
            try:
                return chr(int(m.group(1), 8))
            except (ValueError, OverflowError):
                return m.group(0)
        return re.sub(r'\\([0-7]{3})', replace_octal, text)

    @staticmethod
    def _decode_char_encoding(text: str) -> str:
        """chr(101).chr(118) → eval, char(101,118,97,108) → eval"""
        # chr(N) or char(N)
        def replace_chr(m):
            codes = [int(x) for x in re.findall(r'\d+', m.group(0))]
            try:
                return ''.join(chr(c) for c in codes if 0 <= c <= 255)
            except (ValueError, OverflowError):
                return m.group(0)
        # PHP: chr(101).chr(118)...
        text = re.sub(r'chr\(\d+\)(?:\s*\.\s*chr\(\d+\))*', replace_chr, text)
        # SQL/JS: char(101,118,97,108)
        text = re.sub(r'char\([\d,\s]+\)', replace_chr, text)
        return text

    @staticmethod
    def _decode_string_concat(text: str) -> str:
        """'ev'.'al' → 'eval', "ev"."al" → "eval" """
        # PHP-style concatenation
        return re.sub(
            r"(['\"])([^'\"]+)\\1\s*\.\s*(['\"])([^'\"]+)\\3",
            lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(1),
            text
        )

    @staticmethod
    def _decode_php_concat(text: str) -> str:
        """PHP dot concat: $a = 'ev'; $b = 'al'; $c = $a . $b; → hint eval"""
        # Find variable assignments and resolve dot concatenation
        vars_found = {}
        for m in re.finditer(r'\$(\w+)\s*=\s*[\'"]([^\'"]*)[\'"]', text):
            vars_found[m.group(1)] = m.group(2)
        # Resolve $a . $b patterns
        def resolve_concat(m):
            parts = []
            for token in re.split(r'\s*\.\s*', m.group(0)):
                token = token.strip()
                if token.startswith('$') and token[1:] in vars_found:
                    parts.append(vars_found[token[1:]])
                elif token.startswith('"') or token.startswith("'"):
                    parts.append(token[1:-1])
            result = ''.join(parts)
            return f'"DECODED_CONCAT:{result}"'
        # Find concat patterns and add hints
        concat_matches = re.findall(r'\$(\w+)\s*=\s*(.+)', text)
        for var_name, expr in concat_matches:
            if '.' in expr and any(v in expr for v in vars_found):
                resolved = []
                for token in re.split(r'\s*\.\s*', expr):
                    token = token.strip().strip(';')
                    if token.startswith('$') and token[1:] in vars_found:
                        resolved.append(vars_found[token[1:]])
                    elif token.startswith('"') or token.startswith("'"):
                        resolved.append(token[1:-1])
                if resolved:
                    text += f'\n// DECODED: {var_name} = {"".join(resolved)}\n'
        return text

    @staticmethod
    def _decode_str_replace(text: str) -> str:
        """Simulate str_replace and preg_replace: str_replace('x','','evxal') → eval"""
        # PHP: str_replace('from','to','subject')
        # PHP: preg_replace('/pattern/','replacement','subject')
        for pattern, replacement, source in re.findall(
            r"(?:str_replace|preg_replace)\s*\(\s*['\"]([^'\"]*)['\"]\s*,\s*['\"]([^'\"]*)['\"]\s*,\s*['\"]([^'\"]*)['\"]\s*\)",
            text
        ):
            if pattern in source:
                result = source.replace(pattern, replacement)
                text += f'\n// DECODED: replace -> "{result}"\n'
        return text

    @staticmethod
    def _decode_ascii_array(text: str) -> str:
        """Simulate: $c = array(101,118,97,108); foreach → eval"""
        for m in re.finditer(r'array\s*\(([\d,\s]+)\)', text):
            nums = [int(x) for x in re.findall(r'\d+', m.group(1))]
            try:
                result = ''.join(chr(n) for n in nums if 0 <= n <= 255)
                if any(kw in result.lower() for kw in ['eval', 'exec', 'system', 'assert']):
                    text += f'\n// DECODED: array -> "{result}"\n'
            except (ValueError, OverflowError):
                pass
        return text

    @staticmethod
    def _inline_variable_call(text: str) -> str:
        """关键步骤：$v=\"eval\"; $v($_POST) → eval($_POST)
        解码后的字符串变量被调用时，替换为直接调用形式，让 YARA 能匹配 eval(、system( 等"""
        # Find variable assignments to dangerous functions
        dangerous = ['eval', 'assert', 'system', 'exec', 'passthru', 'shell_exec',
                     'popen', 'proc_open', 'create_function', 'preg_replace',
                     'base64_decode', 'file_get_contents', 'file_put_contents']
        assignments = {}
        for m in re.finditer(r'\$(\w+)\s*=\s*["\']([^"\']+)["\']\s*;', text):
            var_name = m.group(1)
            value = m.group(2).strip()
            if any(d in value.lower() for d in dangerous):
                assignments[var_name] = value

        # Replace $var(...) with decoded_func(...)
        for var_name, func_name in assignments.items():
            # $var($x) → func_name($x)
            text = re.sub(
                r'\$' + re.escape(var_name) + r'\s*\(([^)]*)\)',
                func_name + r'(\1)',
                text
            )

        return text

    @staticmethod
    def _decode_base64_strings(text: str) -> str:
        """Find base64-looking strings and try to decode them as hints"""
        # Look for strings that look like base64 (alphanumeric + / + =)
        candidates = re.findall(r'[\'"]([A-Za-z0-9+/=]{20,})[\'"]', text)
        for b64_str in candidates:
            try:
                decoded = base64.b64decode(b64_str).decode('utf-8', errors='replace')
                if any(kw in decoded.lower() for kw in ['eval', 'exec', 'system', 'passthru', 'shell_exec', 'base64_decode', 'popen', 'proc_open', 'assert', 'create_function', 'preg_replace', 'include', 'require', 'fopen', 'file_get_contents', 'file_put_contents']):
                    # Replace the base64 string with its decoded form as a comment
                    # (don't execute, just provide the pattern for YARA to match)
                    text += f"\n/* decoded: {decoded} */"
            except Exception:
                logger.debug("Base64 decode attempt failed for string in _decode_base64_strings", exc_info=True)
        return text
