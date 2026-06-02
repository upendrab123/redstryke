"""
Evaluator — LLM-as-judge module that scores attack results.
Uses Groq API with low temperature to produce structured severity assessments.
"""
__all__ = ["AttackEvaluator"]