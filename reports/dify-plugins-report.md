# 🛡️ AgentShield — Dify Plugins Security Report

> Automated security scan of the [langgenius/dify-plugins](https://github.com/langgenius/dify-plugins) repository.

**Scanned**: 493 plugins | 11833 files | 1,556,184 lines
**Duration**: 125.6s
**Average Score**: 90/100
**Scanner**: [AgentShield](https://github.com/elliotllliu/agentshield) v0.3.0
**Date**: 2026-03-13

## Summary

| Category | Count | % |
|----------|-------|---|
| 🔴 Plugins with High Risk findings | 10 | 2.0% |
| 🟡 Plugins with Medium Risk only | 101 | 20.5% |
| 🟢 Clean plugins (Low/None) | 382 | 77.5% |

**Total findings**: 3868 (🔴 72 high, 🟡 2745 medium, 🟢 1051 low)

## Score Distribution

| Score Range | Count |
|-------------|-------|
| 90-100 (Low Risk) | 396 |
| 70-89 (Moderate Risk) | 50 |
| 40-69 (High Risk) | 25 |
| 0-39 (Critical Risk) | 22 |

## 🔴 High Risk Plugins

| Plugin | Score | 🔴 High | 🟡 Med | 🟢 Low | Top Finding |
|--------|-------|---------|--------|--------|-------------|
| LogicOber/better-e2b-sandbox/Better-E2B-Sandbox | 0 | 3 | 10 | 12 | Reads sensitive data (line 100,101,103,104) and sends HTTP r |
| allenyzx/enhancing_function_agent/enhancing_function_agent | 0 | 4 | 4 | 1 | eval() with dynamic input |
| bowenliang123/md_exporter/md_exporter | 0 | 6 | 11 | 2 | Python exec() with dynamic input |
| xiaobao_plugin/yinxiangnote/yingxiangnote | 0 | 51 | 2364 | 68 | Reads sensitive data (line 568,595,597) and sends HTTP reque |
| beersoccer/mem0ai/mem0ai-0.2.9 | 31 | 1 | 5 | 2 | Reads sensitive data (line 56,57) and sends HTTP request (li |
| lfenghx/mini_claw/mini_claw-1.0.0 | 35 | 1 | 4 | 4 | Reads sensitive data (line 442) and sends HTTP request (line |
| qin2dim/table_cooking/table-cooking-0.0.3 | 40 | 2 | 1 | 1 | Reads sensitive data (line 94) and sends HTTP request (line  |
| stvlynn/sftp/sftp-0.0.1 | 48 | 2 | 0 | 1 | Reads sensitive data (line 148) and sends HTTP request (line |
| sawyer-shi/smart_excel_kit/smart_excel_kit-0.0.1 | 57 | 1 | 2 | 1 | Python exec() with dynamic input |
| Euraxluo/dingtalk-assistant-caller/dingtalk-assistant-caller-0.0.2 | 63 | 1 | 1 | 2 | Reads sensitive data (line 24) and sends HTTP request (line  |

### High Risk Details

#### LogicOber/better-e2b-sandbox/Better-E2B-Sandbox (Score: 0)

- **HIGH** `tools/_claude_permissions.py:106`: Reads sensitive data (line 100,101,103,104) and sends HTTP request (line 106,184,185,186,187,188,189) — possible exfiltration
- **HIGH** `tools/create-nextjs-bun-sandbox.py:134`: pipe-to-shell: downloads and executes remote code
- **HIGH** `tools/install-packages.py:18`: pipe-to-shell: downloads and executes remote code
- **MEDIUM** `tools/create-nextjs-bun-sandbox.py:158`: /dev/tcp reverse shell
- **MEDIUM** `tools/create-nextjs-sandbox.py:153`: /dev/tcp reverse shell

#### allenyzx/enhancing_function_agent/enhancing_function_agent (Score: 0)

- **HIGH** `strategies/enhancing_function_agent.py:73`: eval() with dynamic input
- **HIGH** `strategies/enhancing_function_agent.py:103`: eval() with dynamic input
- **HIGH** `strategies/enhancing_function_agent.py:158`: eval() with dynamic input
- **HIGH** `strategies/enhancing_function_agent.py:200`: eval() with dynamic input
- **MEDIUM** `strategies/enhancing_function_agent.py:73`: [code-exec] eval() with non-literal input

#### bowenliang123/md_exporter/md_exporter (Score: 0)

- **HIGH** `tools/md_to_pptx/md2pptx-5.4.3/md2pptx.py:5127`: Python exec() with dynamic input
- **HIGH** `tools/md_to_pptx/md2pptx-5.4.3/md2pptx.py:6321`: Python exec() with dynamic input
- **HIGH** `tools/md_to_pptx/md2pptx-5.4.3/md2pptx.py:6328`: Python exec() with dynamic input
- **HIGH** `tools/md_to_pptx/md2pptx-5.4.3/md2pptx.py:6343`: Python exec() with dynamic input
- **HIGH** `tools/md_to_pptx/md2pptx-5.4.3/runPython.py:34`: Python exec() with dynamic input

#### xiaobao_plugin/yinxiangnote/yingxiangnote (Score: 0)

- **HIGH** `difyevnote2/Lib/site-packages/click/_termui_impl.py:675`: Reads sensitive data (line 568,595,597) and sends HTTP request (line 675) — possible exfiltration
- **HIGH** `difyevnote2/Lib/site-packages/flask/app.py:12`: Reads sensitive data (line 553,562) and sends HTTP request (line 12) — possible exfiltration
- **HIGH** `difyevnote2/Lib/site-packages/cffi/recompiler.py:78`: eval() with dynamic input
- **HIGH** `difyevnote2/Lib/site-packages/cffi/setuptools_ext.py:26`: Python exec() with dynamic input
- **HIGH** `difyevnote2/Lib/site-packages/flask/cli.py:1005`: eval() with dynamic input

#### beersoccer/mem0ai/mem0ai-0.2.9 (Score: 31)

- **HIGH** `performance/locustfile.py:191`: Reads sensitive data (line 56,57) and sends HTTP request (line 191) — possible exfiltration
- **MEDIUM** `performance/locustfile.py:191`: Reads environment variables (line 72,81,84,93,96,101,102,274,366) and sends HTTP request (line 191) — possible env leak
- **MEDIUM** `utils/mem0_client.py:688`: Periodic timer + HTTP request — possible beacon/phone-home pattern
- **MEDIUM** `utils/prompts.py:39`: Prompt injection: Attempts to extract credentials via prompt
- **MEDIUM** `CONFIG.md:757`: Tool shadowing: Redirects from another tool to this one

#### lfenghx/mini_claw/mini_claw-1.0.0 (Score: 35)

- **HIGH** `tools/TM.py:16`: Reads sensitive data (line 442) and sends HTTP request (line 16,17) — possible exfiltration
- **MEDIUM** `utils/mini_claw_runtime.py:715`: Reads environment variables (line 345,727,932,996) and sends HTTP request (line 715,721) — possible env leak
- **MEDIUM** `manifest.yaml:11`: Tool shadowing: Claims to be an enhanced version
- **MEDIUM** `tools/mini_claw.yaml:11`: Tool shadowing: Claims to be an enhanced version
- **MEDIUM** `tools/mini_claw.yaml:15`: Tool shadowing: Claims to be an enhanced version

#### qin2dim/table_cooking/table-cooking-0.0.3 (Score: 40)

- **HIGH** `tools/pipeline/service.py:3`: Reads sensitive data (line 94) and sends HTTP request (line 3) — possible exfiltration
- **HIGH** `tools/ai/table_self_query.py:958`: Python exec() with dynamic input
- **MEDIUM** `tools/ai/table_self_query.py:958`: [code-exec] exec() with dynamic input

#### stvlynn/sftp/sftp-0.0.1 (Score: 48)

- **HIGH** `tools/sftp.py:107`: Reads sensitive data (line 148) and sends HTTP request (line 107) — possible exfiltration
- **HIGH** `tools/upload.py:81`: Reads sensitive data (line 115) and sends HTTP request (line 81) — possible exfiltration

#### sawyer-shi/smart_excel_kit/smart_excel_kit-0.0.1 (Score: 57)

- **HIGH** `tools/excel_manipulator.py:134`: Python exec() with dynamic input
- **MEDIUM** `tools/excel_manipulator.py:134`: [code-exec] exec() with dynamic input
- **MEDIUM** `tools/utils.py:757`: [insecure-network] SSL verification disabled (verify=False)

#### Euraxluo/dingtalk-assistant-caller/dingtalk-assistant-caller-0.0.2 (Score: 63)

- **HIGH** `tools/dingtalk.py:370`: Reads sensitive data (line 24) and sends HTTP request (line 370) — possible exfiltration
- **MEDIUM** `tools/dingtalk.py:370`: Reads environment variables (line 66,67,110,514) and sends HTTP request (line 370) — possible env leak

## 🟡 Medium Risk Plugins

| Plugin | Score | 🟡 Med | 🟢 Low | Top Finding |
|--------|-------|--------|--------|-------------|
| clickzetta/clickzetta_lakehouse | 0 | 23 | 9 | [sql-injection] SQL query with f-string — SQL injection risk |
| petrus/mercury_tools/mercury_tools-0.2.9 | 0 | 13 | 1 | Financial execution: Direct money transfer capability |
| sawyer-shi/file_converter/file_converter-0.0.2 | 0 | 23 | 1 | dynamic import() |
| yaxuanm/qdrant/qdrant-0.0.1 | 0 | 20 | 1 | Prompt injection: Zero-width characters (potential hidden te |
| hjlarry/draw/draw-0.0.1 | 10 | 11 | 1 | Dynamic URL construction in HTTP request — potential SSRF |
| sawyer-shi/file_encrypt_decrypt/file_encrypt_decrypt-0.0.3 | 10 | 11 | 1 | Prompt injection: Zero-width characters (potential hidden te |
| ssf/mcp_agent-0.0.3 | 18 | 10 | 1 | dynamic import() |
| bowenliang123/base64_codec/base64_codec | 24 | 9 | 2 | Prompt injection: Instructs decoding of obfuscated payloads |
| thierrypdamiba/qdrant/qdrant-0.0.1 | 26 | 9 | 1 | Prompt injection: Zero-width characters (potential hidden te |
| ParkerWen/volcengine_ai/volcengine_ai-0.0.2 | 34 | 8 | 1 | Prompt injection: Claims elevated priority/privilege |
| shaoruidong/dify-plugin-volcengine-ai | 34 | 8 | 1 | Prompt injection: Claims elevated priority/privilege |
| sumuxi/su_printer/su_printer | 34 | 8 | 1 | Hex-encoded string sequence |
| yt-koike/dify-pillow/dify-pillow-0.0.1 | 34 | 8 | 1 | dynamic import() |
| oceanbase/powermem/powermem-0.0.3 | 42 | 7 | 1 | Request to localhost — verify if intentional |
| cashfree/cashfree_payments/cashfree_payments-0.0.8 | 46 | 3 | 15 | Prompt injection: Instructs decoding of obfuscated payloads |
| petrus/mercury_trigger/mercury_trigger-0.4.9 | 46 | 5 | 7 | Request to localhost — verify if intentional |
| junjiem/mcp_sse_agent/agent-mcp_sse | 50 | 6 | 1 | dynamic import() |
| kito/kito-dify | 50 | 6 | 1 | Request to localhost — verify if intentional |
| wwwzhouhui/qwen-image/qwen_text2image_0.0.4 | 50 | 2 | 17 | Reads environment variables (line 18) and sends HTTP request |
| lework/kafka/kafka_0.0.1 | 52 | 5 | 4 | Prompt injection: Instructs exfiltration of conversation dat |
| upstage-document-parser/upstage-document-parser | 56 | 5 | 2 | Reads environment variables (line 70) and sends HTTP request |
| JiekouAI/JiekouAI/jiekouai | 58 | 5 | 1 | dynamic import() |
| actionbook/actionbook/actionbook-v0.1.1 | 58 | 5 | 1 | Request to localhost — verify if intentional |
| burncloud/burncloud/burncloud | 58 | 5 | 1 | dynamic import() |
| cnjasonz/ppio/ppio-0.0.6 | 58 | 5 | 1 | dynamic import() |
| novita/novita/novita-0.0.7 | 58 | 5 | 1 | dynamic import() |
| ppio/ppio/ppio | 58 | 5 | 1 | dynamic import() |
| JOTO-Tech/schemarag/schemarag-0.1.6 | 66 | 3 | 5 | Prompt injection: Urgency-based behavioral directive in desc |
| axdlee/sophnet/sophnet-0.0.5 | 66 | 4 | 1 | Hex-encoded string sequence |
| datoujiejie/botos3/botos3 | 68 | 3 | 4 | [insecure-network] SSL verification disabled (verify=False) |
| stvlynn/x/x-0.0.1 | 68 | 2 | 8 | [insecure-network] SSL verification disabled (verify=False) |
| dwdecon/url_extract_images-0.3.0 | 72 | 3 | 2 | Hex-encoded string sequence |
| Organization/JOTO_DataFocus/Datafocus | 74 | 2 | 5 | [insecure-network] SSL verification disabled (verify=False) |
| caffbyte/imagetool | 74 | 3 | 1 | dynamic import() |
| petrus/quickbooks/quickbooks-0.2.10 | 74 | 3 | 1 | Financial execution: Direct money transfer capability |
| samanhappy/excel-process/dify-excel-process-plugin-v0.0.1 | 74 | 3 | 1 | Hex-encoded string sequence |
| wwwzhouhui/nano_banana/nano_banana_0.0.3 | 74 | 1 | 9 | [path-traversal] open() with user-controlled path — path tra |
| Fusic/upstage/upstage-0.0.1 | 76 | 2 | 4 | Periodic timer + HTTP request — possible beacon/phone-home p |
| smart_doc_generator/smart_doc_generator-1.1.0 | 76 | 1 | 8 | [path-traversal] open() with user-controlled path — path tra |
| bikeread/dify_wechat_plugin/dify_wechat_plugin | 78 | 2 | 3 | Periodic timer + HTTP request — possible beacon/phone-home p |
| edtechools/mattermost/mattermost-0.0.3 | 78 | 2 | 3 | Prompt injection: Instructs exfiltration of conversation dat |
| edtechools/mattermost_send_message/mattermost_send_message | 78 | 2 | 3 | Prompt injection: Instructs exfiltration of conversation dat |
| sawyer-shi/mind_map/mind_map | 78 | 2 | 3 | Prompt injection: Zero-width characters (potential hidden te |
| r3-yamauchi/kintone_file_datasource/kintone_file_datasource | 80 | 2 | 2 | [path-traversal] open() with user-controlled path — path tra |
| Cloudsway/reader/cloudsway_reader | 82 | 2 | 1 | [path-traversal] open() with user-controlled path — path tra |
| aopstudio/google_scholar/google_scholar | 82 | 2 | 1 | [path-traversal] open() with user-controlled path — path tra |
| arrenxxxxx/mcp_config_during_use/mcp_config_during_use | 82 | 2 | 1 | Prompt injection: Instructs exfiltration of conversation dat |
| asukhodko/markdown-chunker-2.1.7 | 82 | 2 | 1 | dynamic import() |
| atoy0m0/pdf-to-images | 82 | 2 | 1 | Request to localhost — verify if intentional |
| bowenliang123/cryptography/cryptography | 82 | 2 | 1 | Embedded private key |
| imran-siddique/agentmesh-trust-layer | 82 | 2 | 1 | Tool shadowing: Redirects from another tool to this one |
| jingfelix/kook-notify/kook-notify-0.0.1 | 82 | 2 | 1 | Prompt injection: Instructs exfiltration of conversation dat |
| junjiem/knowledge_extractor_tool/knowledge_extractor | 82 | 2 | 1 | dynamic import() |
| livien/ffmpeg_tools_dify | 82 | 2 | 1 | [cmd-injection] subprocess with variable input |
| michael_edison/funasr-connecter/funasr-connecter | 82 | 2 | 1 | Request to localhost — verify if intentional |
| r3-yamauchi/blastengine_mailer/blastengine_mailer | 82 | 2 | 1 | Unverifiable external dependency: Dynamic import from remote |
| r3-yamauchi/sendgrid_mailer/sendgrid_mailer | 82 | 2 | 1 | Unverifiable external dependency: Dynamic import from remote |
| r3-yamauchi/wordpress/wordpress | 82 | 2 | 1 | Unverifiable external dependency: Dynamic import from remote |
| witmeng/ragflow-api/ragflow-api | 82 | 2 | 1 | [insecure-network] SSL verification disabled (verify=False) |
| yeuoly/waifu/waifu.0.0.1 | 82 | 2 | 1 | Unverifiable external dependency: Dynamic import from remote |
| anspire/we-com-bot/anspire-wecom-bot | 84 | 1 | 4 | dynamic import() |
| gokuaiyunku/yunku_datasource_dify | 86 | 1 | 3 | dynamic import() |
| lfenghx/skill_agent/skill_agent | 86 | 1 | 3 | dynamic import() |
| nacos/a2a_server/a2a_server | 86 | 1 | 3 | High instruction density (17 directive words in 319 words) — |
| axdlee/safety-chat | 88 | 1 | 2 | [deserialization] pickle.load/loads — arbitrary code executi |
| feiwangoooh/giphy/giphy.0.0.1 | 88 | 1 | 2 | [weak-crypto] random module for security-sensitive value (us |
| investoday/stock/investoday-stock-3.0.5 | 88 | 1 | 2 | Prompt injection: Zero-width characters (potential hidden te |
| jingfelix/bilibili_search/bilibili_search-0.0.3 | 88 | 1 | 2 | Request to localhost — verify if intentional |
| oy_plat/gen_pptx/oy-gen-pptx | 88 | 1 | 2 | Reads environment variables (line 32,109) and sends HTTP req |
| r3-yamauchi/my_google_cloud_tools/my_google_cloud_tools | 88 | 1 | 2 | dynamic import() |
| raftds/salutespeech/salute-speech | 88 | 1 | 2 | Reads environment variables (line 17) and sends HTTP request |
| stock_research/stock_researcher | 88 | 1 | 2 | Dynamic URL construction in HTTP request — potential SSRF |
| Xcode-wu/trtc-conai/trtc-conai | 90 | 1 | 1 | High instruction density (10 directive words in 190 words) — |
| ahasasjeb/mc_ping/mc_ping | 90 | 1 | 1 | Hex-encoded string sequence |
| alterxyz/cloudflare_d1/data_connector_cloudflare_d1-0.0.3 | 90 | 1 | 1 | Prompt injection: Urgency-based behavioral directive in desc |
| alterxyz/conversation_memory/conversation_memory-0.0.4 | 90 | 1 | 1 | Reads environment variables (line 29,30,31) and sends HTTP r |
| apro/apro_ai_oracle/apro_ai_oracle.0.0.2 | 90 | 1 | 1 | Prompt injection: Instructs exfiltration of conversation dat |
| axdlee/safety_chat/safety_chat-0.0.4 | 90 | 1 | 1 | [deserialization] pickle.load/loads — arbitrary code executi |
| ayi1337/qweather/qweather-0.0.9 | 90 | 1 | 1 | [path-traversal] open() with user-controlled path — path tra |
| catnyan/link-reader/link-reader | 90 | 1 | 1 | Request to localhost — verify if intentional |
| comlan/auzre_search | 90 | 1 | 1 | dynamic import() |
| cybozu/kintone/kintone | 90 | 1 | 1 | Reads environment variables (line 186) and sends HTTP reques |
| dms/aliyundms_v0.0.8 | 90 | 1 | 1 | Prompt injection: Attempts to change agent identity |
| eft/redis/dify-plugin-redis | 90 | 1 | 1 | Request to localhost — verify if intentional |
| gu/gmail/gmail-0.0.1 | 90 | 1 | 1 | Prompt injection: Instructs decoding of obfuscated payloads |
| kurokobo/openai_audio_toolkit/openai_audio_toolkit | 90 | 1 | 1 | dynamic import() |
| leo-digital/doubao-seedream/doubao-seedream-1.0.1 | 90 | 1 | 1 | [path-traversal] open() with user-controlled path — path tra |
| linkup/search-web/search-web | 90 | 1 | 1 | Prompt injection: Unicode formatting/control characters (ste |
| logicober/cursor-background-agents/cursor-background-agents | 90 | 1 | 1 | Reads environment variables (line 16) and sends HTTP request |
| microsoft-teams/microsoft-teams | 90 | 1 | 1 | Prompt injection: Instructs exfiltration of conversation dat |
| modelhub_nanobanana/gemini | 90 | 1 | 1 | [path-traversal] open() with user-controlled path — path tra |
| nikolamilosevic86/neo4j_query | 90 | 1 | 1 | Prompt injection: Urgency-based behavioral directive in desc |
| sawyer-shi/flow_map/flow_map-0.0.2 | 90 | 1 | 1 | [path-traversal] open() with user-controlled path — path tra |
| shamspias/togetherai/image/togetherai-dify-image | 90 | 1 | 1 | Prompt injection: Instructs decoding of obfuscated payloads |
| stackit_model_serving/stackit-model-serving-dify-plugin | 90 | 1 | 1 | dynamic import() |
| stvlynn/ffmpeg/ffmpeg-0.0.1 | 90 | 1 | 1 | [cmd-injection] subprocess with variable input |
| weaviate/weaviate_plugin/weaviate_plugin-0.0.1 | 90 | 1 | 1 | Prompt injection: Attempts to extract credentials via prompt |
| whyteawhy/rhymefinder/rhymefinder | 90 | 1 | 1 | Prompt injection: Urgency-based behavioral directive in desc |
| xwang152-jack/wechat_official_plugin/wechat_official_plugin-0.0.1 | 90 | 1 | 1 | [path-traversal] open() with user-controlled path — path tra |
| yt-koike/dify-cron/dify-cron-0.1.0 | 90 | 1 | 1 | Periodic timer + HTTP request — possible beacon/phone-home p |
| zm1990s/ai_security_api/panw_ai_security_api_for_dify | 90 | 1 | 1 | [insecure-network] SSL verification disabled (verify=False) |

## Most Common Findings

| # | Finding | Occurrences |
|---|---------|-------------|
| 1 | [privilege] No SKILL.md found — permission analysis skipped | 461 |
| 2 | [prompt-injection] Prompt injection: Zero-width characters (potential hidden text) | 59 |
| 3 | [python-security] [info-leak] Printing sensitive data | 56 |
| 4 | [backdoor] dynamic import() | 54 |
| 5 | [prompt-injection] Prompt injection: Instructs exfiltration of conversation data | 25 |
| 6 | [python-security] [path-traversal] open() with user-controlled path — path traversal risk | 21 |
| 7 | [python-security] [weak-crypto] MD5 hash — cryptographically weak | 20 |
| 8 | [network-ssrf] Request to localhost — verify if intentional | 17 |
| 9 | [obfuscation] Hex-encoded string sequence | 13 |
| 10 | [sensitive-read] Accesses AWS credentials | 13 |
| 11 | [python-security] [weak-crypto] SHA1 hash — cryptographically weak | 13 |
| 12 | [python-security] [insecure-network] SSL verification disabled (verify=False) | 11 |
| 13 | [skill-risks] Financial execution: Direct money transfer capability | 10 |
| 14 | [backdoor] Python exec() with dynamic input | 8 |
| 15 | [sensitive-read] Accesses Kubernetes config | 8 |
| 16 | [prompt-injection] Prompt injection: Instructs decoding of obfuscated payloads | 8 |
| 17 | [tool-shadowing] Tool shadowing: Redirects from another tool to this one | 8 |
| 18 | [prompt-injection] Prompt injection: Claims elevated priority/privilege | 8 |
| 19 | [prompt-injection] Prompt injection: Unicode formatting/control characters (steganographic attack) | 8 |
| 20 | [skill-risks] Unverifiable external dependency: Dynamic import from remote URL | 8 |

## Recommendations

1. Plugins with 🔴 High Risk findings should be reviewed immediately before deployment
2. Consider integrating AgentShield into the dify-plugins CI pipeline
3. Add `.agentshield.yml` config to customize severity thresholds per plugin

---

*Generated by [AgentShield](https://github.com/elliotllliu/agentshield) v0.3.0*
