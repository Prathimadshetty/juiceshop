rules:
  - id: tainted-code-injection-from-http-request
    message: Passing unsanitized user input to a Script Engine or other means of
      dynamic code evaluation is unsafe. This could lead to code injection with
      data leakage or arbitrary code execution as a result. Avoid this, or use
      proper sandboxing if user code evaluation is intended.
    severity: ERROR
    metadata:
      likelihood: HIGH
      impact: HIGH
      confidence: MEDIUM
      category: security
      subcategory:
        - vuln
      cwe:
        - "CWE-95: Improper Neutralization of Directives in Dynamically
          Evaluated Code ('Eval Injection')"
      owasp:
        - A03:2021 - Injection
      references:
        - https://cwe.mitre.org/data/definitions/95.html
      technology:
        - java
        - servlets
      license: Copyright 2023 Semgrep, Inc.
      vulnerability_class:
        - Code Injection
    languages:
      - java
    mode: taint
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: (HttpServletRequest $REQ).$REQFUNC(...)
              - pattern: |
                  (ServletRequest $REQ).$REQFUNC(...) 
              - patterns:
                  - pattern-inside: >
                      (javax.servlet.http.Cookie[] $COOKIES) =
                      (HttpServletRequest $REQ).getCookies(...);

                      ...

                      for (javax.servlet.http.Cookie $COOKIE: $COOKIES) {
                        ...
                      }
                  - pattern: |
                      $COOKIE.getValue(...)
              - patterns:
                  - pattern-inside: |
                      $TYPE[] $VALS = (HttpServletRequest $REQ).$GETFUNC(...);
                      ...
                  - pattern: |
                      $PARAM = $VALS[$INDEX];
          - pattern-not: |
              $REQ.getUserPrincipal() 
          - pattern-not: |
              $REQ.getSession(...) 
          - pattern-not: |
              $REQ.getAuthType(...) 
          - pattern-not: |
              $REQ.getMethod(...) 
          - pattern-not: |
              $REQ.getLocales(...) 
          - pattern-not: |
              $REQ.getLocale(...) 
          - pattern-not: |
              $REQ.isUserinRole(...) 
          - pattern-not: |
              $REQ.isRequestdSessionIdValid(...) 
          - pattern-not: |
              $REQ.isRequestedSessionIdFromUrl(...) 
          - pattern-not: |
              $REQ.getIntHeader(...) 
          - pattern-not: |
              $REQ.getDateHeader(...) 
          - pattern-not: |
              $REQ.authenticate(...) 
          - pattern-not: |
              $REQ.isUserInRole(...) 
          - pattern-not: |
              $REQ.getAttribute(...)
          - pattern-not: |
              $REQ.getAttributeNames(...)
          - pattern-not: |
              $REQ.getAuthType(...)
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: |
                  (ScriptEngine $ENGINE).eval(...)
              - pattern: |
                  (ExpressionFactory $FACTORY).createMethodExpression(...)
              - pattern: |
                  (ExpressionFactory $FACTORY).createValueExpression(...)
