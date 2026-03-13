# Source: Real Dify plugin — sawyer-shi/smart_excel_kit
# Risk: exec() on LLM-generated code (code injection via prompt)
# Category: backdoor (exec with tainted input)
# Expected: malicious

import re
import pandas as pd
import numpy as np

class ExcelManipulator:
    """Tool that uses LLM to generate and execute Python code for Excel manipulation."""

    def process_with_ai(self, df, user_request):
        llm_response = self.llm.invoke(
            prompt=f"Write a Python function process_data(df) to: {user_request}",
        )

        code_match = re.search(r'```python(.*?)```', llm_response, re.DOTALL)
        code_to_run = code_match.group(1).strip() if code_match else llm_response.replace('```', '')

        local_scope = {}
        global_scope = {'pd': pd, 'np': np}

        # DANGER: exec() on LLM-generated code — attacker-controlled via prompt injection
        exec(code_to_run, global_scope, local_scope)

        if 'process_data' not in local_scope:
            raise ValueError("AI did not define 'process_data(df)' function.")

        process_func = local_scope['process_data']
        return process_func(df.copy())
