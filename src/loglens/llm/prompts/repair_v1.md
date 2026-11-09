Your previous assessment failed JSON validation with the following error:
<validation_error>
{error}
</validation_error>

Here is the original cluster data you analyzed:
{cluster_data}

Please re-generate the assessment. You MUST respond with ONLY a valid, parseable JSON object matching the exact schema:
```json
{
  "summary": "string",
  "attack_type": "string | null",
  "severity": "info | low | medium | high | critical",
  "confidence": 0.0 - 1.0,
  "evidence": ["string"],
  "recommended_actions": ["string"],
  "false_positive_likelihood": "low | medium | high"
}
```
No explanations, markdown text, or other wrappers. Just the JSON object.

