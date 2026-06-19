"""API Fuzzer Agent stub.
Handles REST and GraphQL attack surfaces discovered during recon.

GraphQL-specific flow:
1. Run introspection query to get full schema
2. Identify mutation fields (write ops - higher risk)
3. Test each field for injection (SQLi, NoSQLi, SSTI)
4. Test authorization: unauthenticated user calling auth-required mutations?
5. Field-level access control (user A reading user B private fields?)

REST API flow:
1. Map endpoints from ffuf/httpx output
2. Identify parameterized paths (/api/user/{id} -> IDOR candidate)
3. SSRF via URL parameters (webhook, callback, redirect fields)
"""

GRAPHQL_INTROSPECTION = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind } }
        type { name kind }
      }
    }
  }
}
"""
