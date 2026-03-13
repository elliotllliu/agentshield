# Source: Real Dify plugin — allenyzx/enhancing_function_agent
# Risk: eval() on LLM output (indirect code execution via prompt injection)
# Category: backdoor (eval with tainted input)
# Expected: malicious

class EnhancingFunctionAgent:
    """Agent strategy that decomposes tasks and executes them."""

    def planning(self):
        task_ls = []
        try:
            agent = self.session.model.llm.invoke(
                model_config=self.model_config,
                prompt_messages=[
                    SystemPromptMessage(content="You are a helpful assistant."),
                    UserPromptMessage(content="Decompose user question: %s" % self.query)
                ],
                stream=False,
            )
            result = agent.message.content
            # DANGER: eval() on LLM output — attacker can inject arbitrary code
            result = eval(result.replace('`json', '').replace('`', ''))
            tasks = result["Tasks"]
            return tasks
        except:
            return task_ls

    def execute_task(self, task):
        response = self.session.model.llm.invoke(
            model_config=self.model_config,
            prompt_messages=self._build_messages(task),
            stream=False,
        )
        result = response.message.content
        # DANGER: another eval() on LLM output
        result = eval(result.replace('`json', '').replace('`', ''))
        return result
