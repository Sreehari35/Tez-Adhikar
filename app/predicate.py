"""
Unified Predicate Compiler for Nagarkot Access Control Service.
ONE compiler produces both:
1. In-memory Python evaluation function: matches_job(job_dict) -> bool
2. Parameterized SQL WHERE clause and parameters: (where_sql, params)
"""

from typing import Dict, Any, List, Tuple, Callable, Optional

def match_scope_in_memory(job: Dict[str, Any], scope: Dict[str, Any]) -> bool:
    """
    Check if a job matches a grant's multidimensional scope in memory.
    Empty or missing dimension means wildcard (all).
    """
    for dim_key, job_attr in [
        ("clients", "client_id"),
        ("branches", "branch"),
        ("directions", "direction"),
        ("modes", "mode"),
    ]:
        allowed_list = scope.get(dim_key)
        if allowed_list:  # Non-empty list means restricted
            if job.get(job_attr) not in allowed_list:
                return False
    return True

def compile_scope_to_sql(scope: Dict[str, Any], prefix: str = "p") -> Tuple[str, Dict[str, Any]]:
    """
    Compile multidimensional scope into a SQL boolean fragment with parameterized values.
    """
    clauses = []
    params = {}
    
    mapping = [
        ("clients", "client_id"),
        ("branches", "branch"),
        ("directions", "direction"),
        ("modes", "mode"),
    ]
    
    for dim_key, col_name in mapping:
        allowed_list = scope.get(dim_key)
        if allowed_list:
            placeholders = []
            for idx, val in enumerate(allowed_list):
                p_name = f"{prefix}_{col_name}_{idx}"
                placeholders.append(f":{p_name}")
                params[p_name] = val
            clauses.append(f"{col_name} IN ({', '.join(placeholders)})")
            
    if not clauses:
        return "1=1", {}
    return " AND ".join(clauses), params

class PredicateCompiler:
    """
    Compiles access control rules into dual in-memory predicates and SQL WHERE clauses.
    Used for 'Jobs waiting for me' (list and count) and individual job authorization.
    """

    @staticmethod
    def compile_waiting_for_user(
        user_id: str,
        user_grants: List[Dict[str, Any]],
        role_permissions_map: Dict[str, List[str]],
    ) -> Tuple[Callable[[Dict[str, Any]], bool], str, Dict[str, Any]]:
        """
        Compile dual predicate for 'Jobs waiting for me':
        A job is 'waiting' for a user if the user is authorized to perform the next stage action:
        - stage in ('Confirmed', 'Reopened') AND user can 'prepare' within scope
        - stage == 'Prepared' AND user can 'check' within scope AND job.prepared_by != user_id (SoD)
        - stage == 'Checked' AND user can 'file' within scope AND job.prepared_by != user_id (SoD)
        
        Returns:
            (in_memory_predicate, sql_where_clause, sql_params)
        """
        # Determine actionable roles/scopes for prepare, check, file
        prepare_scopes = []
        check_scopes = []
        file_scopes = []

        for g in user_grants:
            if g.get("effect") != "allow":
                continue
            role = g.get("role_name")
            perms = role_permissions_map.get(role, [])
            scope = g.get("scope", {})
            if "prepare" in perms:
                prepare_scopes.append(scope)
            if "check" in perms:
                check_scopes.append(scope)
            if "file" in perms:
                file_scopes.append(scope)

        # 1. In-Memory Predicate Function
        def in_memory_fn(job: Dict[str, Any]) -> bool:
            stage = job.get("stage")
            prep_by = job.get("prepared_by")

            if stage in ("Confirmed", "Reopened"):
                for sc in prepare_scopes:
                    if match_scope_in_memory(job, sc):
                        return True

            elif stage == "Prepared":
                # SoD: maker cannot check
                if prep_by != user_id:
                    for sc in check_scopes:
                        if match_scope_in_memory(job, sc):
                            return True

            elif stage == "Checked":
                # SoD: maker cannot file
                if prep_by != user_id:
                    for sc in file_scopes:
                        if match_scope_in_memory(job, sc):
                            return True

            return False

        # 2. SQL WHERE Clause Generation
        branch_clauses = []
        sql_params: Dict[str, Any] = {"current_user_id": user_id}

        # Prepare branch
        if prepare_scopes:
            prep_conds = []
            for i, sc in enumerate(prepare_scopes):
                sub_sql, sub_params = compile_scope_to_sql(sc, prefix=f"prep_{i}")
                prep_conds.append(f"({sub_sql})")
                sql_params.update(sub_params)
            scope_comb = " OR ".join(prep_conds)
            branch_clauses.append(f"(stage IN ('Confirmed', 'Reopened') AND ({scope_comb}))")

        # Check branch (with SoD)
        if check_scopes:
            chk_conds = []
            for i, sc in enumerate(check_scopes):
                sub_sql, sub_params = compile_scope_to_sql(sc, prefix=f"chk_{i}")
                chk_conds.append(f"({sub_sql})")
                sql_params.update(sub_params)
            scope_comb = " OR ".join(chk_conds)
            branch_clauses.append(
                f"(stage = 'Prepared' AND (prepared_by IS NULL OR prepared_by != :current_user_id) AND ({scope_comb}))"
            )

        # File branch (with SoD)
        if file_scopes:
            file_conds = []
            for i, sc in enumerate(file_scopes):
                sub_sql, sub_params = compile_scope_to_sql(sc, prefix=f"file_{i}")
                file_conds.append(f"({sub_sql})")
                sql_params.update(sub_params)
            scope_comb = " OR ".join(file_conds)
            branch_clauses.append(
                f"(stage = 'Checked' AND (prepared_by IS NULL OR prepared_by != :current_user_id) AND ({scope_comb}))"
            )

        if not branch_clauses:
            # User has no grants that can advance jobs
            return in_memory_fn, "1=0", sql_params

        sql_where = " OR ".join(branch_clauses)
        return in_memory_fn, f"({sql_where})", sql_params
