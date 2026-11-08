# Test result: blind benchmark samples for the Radar and output checks (M4.0b)

- **Brief:** [docs/testing/briefs/2026-11-08-m4-0b-blind-samples.md](../briefs/2026-11-08-m4-0b-blind-samples.md)
- **Author:** Antigravity
- **Date:** 2026-11-08
- **Files generated:**
  - `docs/testing/exports/blind-injection_indirect.jsonl` (250 lines)
  - `docs/testing/exports/blind-output_xss.jsonl` (250 lines)
  - `docs/testing/exports/blind-output_ssrf.jsonl` (250 lines)
  - `docs/testing/exports/blind-output_path.jsonl` (250 lines)

## Independence Confirmation
**I confirm that I have NOT read `agentwall/src/firewall/`, `agentwall/src/bench/`, `agentwall/bench/`, `docs/plans/phase4*.md`, or `docs/security/coverage-matrix.md` before or while writing these samples.** All samples were authored independently based strictly on real-world attack techniques, document formats, and realistic edge cases.

---

## Sample Counts and Label Breakdown

Each file contains exactly 250 samples numbered from 301 to 550, with a target language mix of 70% English (`en`), 20% Bahasa Malaysia (`ms`), and 10% Indonesian (marked `ms` with Indonesian family descriptors per the brief specification).

| Category | Malicious | Benign (Total) | Benign (Standard) | Benign (Hard) | Total | Language Mix (`en` / `ms`) |
|---|---|---|---|---|---|---|
| `injection_indirect` | 100 | 150 | 115 | 35 | **250** | 175 `en` / 75 `ms` (70% / 30%) |
| `output_xss` | 100 | 150 | 115 | 35 | **250** | 175 `en` / 75 `ms` (70% / 30%) |
| `output_ssrf` | 100 | 150 | 115 | 35 | **250** | 175 `en` / 75 `ms` (70% / 30%) |
| `output_path` | 100 | 150 | 115 | 35 | **250** | 175 `en` / 75 `ms` (70% / 30%) |
| **Total** | **400** | **600** | **460** | **140** | **1,000** | **700 `en` / 300 `ms`** |

---

## Families Used

### 1. `injection_indirect` (103 distinct families)
- **Malicious (26 families):**
  - Goal & Instruction Hijacking: `instruction_override`, `arahan_override`, `persona_hijack`, `perwatakan_palsu`, `roleplay_bypass`, `switch_persona`, `system_prompt_leak`, `bocor_sistem_prompt`
  - Tool Invocation & Exfiltration: `tool_call_smuggling`, `panggilan_alat_curang`, `data_exfiltration`, `eksfiltrasi_data`, `fake_tool_output`, `output_alat_palsu`
  - Concealment & Authority Impersonation: `concealment_override`, `sorokkan_arahan`, `fake_system_marker`, `penanda_sistem_palsu`, `urgency_coercion`, `paksaan_segera`
  - Encodings & Steganography: `encoded_payload`, `muatan_terkod`, `hidden_html_comment`, `komen_html_tersembunyi`, `markdown_link_exfil`, `pautan_markdown_curang`, `invisible_unicode_injection`, `suntikan_unicode_halimunan`
- **Benign & Hard Benign (77 families):**
  - Normal business data & customer service: `receipt_details`, `shipping_update`, `product_spec`, `delivery_instruction`, `resit_pembelian`, `tukar_alamat`, `status_pesanan`, `aduan_kelewatan`, `maklumat_akaun`, `bayaran_fpx`, `batal_pesanan`, `barang_rosak`, `pertanyaan_stok`
  - Hard benign (designed to mimic attack phrasing/markers safely): `abaikan_emel_lepas`, `ignore_previous_note`, `admin_guide`, `api_documentation`, `artikel_keselamatan`, `security_advisory`, `chat_history`, `email_forward`, `bug_report`, `code_sample`, `compliance_handbook`, `panduan_pematuhan`, `incident_postmortem`, `nota_mesyuarat`, `sop_krisis`, `pentest_summary`, `training_material`, `support_escalation_protocol`, etc.

### 2. `output_xss` (120 distinct families)
- **Malicious (55 families):**
  - Script & event execution: `script_tag`, `img_onerror`, `svg_onload`, `body_onload`, `body_onunload`, `input_autofocus`, `audio_onerror`, `video_onerror`, `bgsound_src`, `button_formaction`, `event_handler`, `event_onmouseover`, `event_onfocus`, `event_animationend`, `iframe_injection`, `bingkai_iframe_ms`
  - Protocol handlers & payloads: `javascript_uri`, `data_uri_html`, `vbscript_uri`, `meta_refresh_js`
  - Obfuscation & bypass: `script_mixed_case`, `script_multiline`, `script_null_byte`, `script_slash_bypass`, `img_onerror_html_entity`, `svg_onload_encoded`, `eval_expression`, `script_hex_encoded`, `borang_tindakan_ms`, `muatan_xss_tersembunyi_ms`
- **Benign & Hard Benign (65 families):**
  - Clean HTML/Markdown & ordinary documents: `clean_paragraph`, `clean_bullet_points`, `markdown_bold_italic`, `markdown_table`, `html_safe_span`, `html_safe_div`, `receipt_summary`, `order_confirmation`, `borang_maklumat_ms`, `laporan_kewangan_ms`
  - Hard benign (security discussions, code snippets, documentation explaining XSS): `aduan_pelanggan_kod_ms`, `api_spec_doc`, `artikel_xss_ms`, `audit_log`, `bug_tracker_ticket`, `code_documentation`, `coding_standard`, `cve_report`, `dev_blog_post`, `incident_report`, `json_api_response`, `markdown_code_block`, `penetration_test_log`, `pull_request_review`, `security_faq`, `semakan_kod_ms`, `tutorial_html_ms`, `waf_rule_documentation`, etc.

### 3. `output_ssrf` (165 distinct families)
- **Malicious (100 families):**
  - Cloud metadata targets: `aws_metadata`, `aws_user_data`, `aws_ecs_task_meta`, `gcp_metadata`, `azure_metadata`, `digitalocean_metadata`, `alibaba_metadata`, `oracle_cloud_metadata`, `openstack_metadata`
  - Localhost & Loopback: `loopback_ip`, `localhost_port`, `ipv6_loopback`, `ipv6_v4mapped_loopback`, `loopback_high_port`
  - Private networks (RFC 1918 & carrier grade): `private_rfc1918_10`, `private_rfc1918_172`, `private_rfc1918_192`, `carrier_grade_nat_100`
  - Obfuscation variants: `decimal_ip_bypass`, `hex_ip_bypass`, `octal_ip_bypass`, `zero_padded_ip`, `mixed_notation_ip`, `dotless_integer_ip`, `enclosed_alphanumerics`, `dns_rebinding_nip_io`, `dns_rebinding_sslip_io`, `burp_collaborator`, `interactsh_leak`, `crlf_injection_http`, `smuggling_gopher`, `smuggling_dict`, `smuggling_ldap`, `panggilan_ip_dalaman_ms`, `pendedahan_metadata_ms`, `alat_pemantau_ms`, `pautan_pelayan_sulit_ms`
- **Benign & Hard Benign (65 families):**
  - Standard URLs & documentation: `courier_tracking_url`, `courier_jnt_link`, `ecommerce_help_link`, `government_portal_link`, `payment_gateway_fpx`, `payment_portal`, `pautan_bantuan_ms`, `pautan_kerajaan_ms`
  - Hard benign (cloud docs, RFC references, internal network documentation, IP tutorials): `api_rate_limiting`, `aws_imds_documentation`, `cloud_compliance`, `corporate_vpn_manual`, `cve_analysis`, `dasar_keselamatan_awan_ms`, `devops_runbook`, `docker_networking_doc`, `incident_response_doc`, `ip_addressing_guide`, `kubernetes_networking_guide`, `panduan_rangkaian_pejabat_ms`, `pentest_finding`, `rfc1918_documentation`, `system_architecture_diagram`, `troubleshooting_guide`, etc.

### 4. `output_path` (165 distinct families)
- **Malicious (100 families):**
  - Unix sensitive files: `absolute_path_passwd`, `absolute_path_shadow`, `absolute_path_sudoers`, `proc_environ`, `proc_self_cmdline`, `ssh_private_key`, `ssh_auth_keys`, `ssh_known_hosts`, `bash_history`, `zsh_history`, `apache_httpd_conf`, `nginx_conf`, `crontab_root`
  - Windows sensitive files: `windows_sam`, `windows_system`, `windows_hosts`, `windows_unattend`, `boot_ini`, `iis_web_config`
  - Application secrets & configs: `aws_credentials`, `azure_tokens`, `gcp_service_account_key`, `env_file`, `docker_config`, `k8s_serviceaccount_token`, `django_settings`, `wp_config`
  - Traversal encodings: `dot_dot_slash`, `nested_dot_dot_slash`, `url_encoded_dot_dot`, `double_url_encoded_dot_dot`, `unicode_dot_dot`, `null_byte_injection`, `semicolon_bypass`, `backslash_traversal`, `lintasan_laluan_kredensial_ms`, `akses_kunci_ssh_ms`, `eksploitasi_bacaan_fail_ms`
- **Benign & Hard Benign (65 families):**
  - Normal relative links & filesystem text: `api_route_path`, `category_route_path`, `clean_css_import`, `clean_markdown_link`, `download_link_relative`, `image_asset_path`, `relative_doc_link`, `pautan_imej_produk_ms`, `muat_turun_invois_ms`
  - Hard benign (CLI documentation, coding tutorials, filesystem write-ups, audit logs): `api_docs_relative_links`, `arahan_terminal_ms`, `audit_log_sample`, `bash_scripting_manual`, `code_review_comment`, `compliance_matrix`, `cve_writeup`, `database_backup_runbook`, `deployment_checklist`, `developer_onboarding_guide`, `devops_pipeline_spec`, `git_workflow_guide`, `incident_postmortem`, `linux_admin_guide`, `panduan_terminal_linux_ms`, `pentest_audit_report`, `security_policy`, `semakan_keselamatan_fail_ms`, etc.

---

## Hard-to-Label Cases & Observations

1. **Security Articles & Incident Reports Containing Real Path/URL/XSS Tokens:**
   - Articles describing CVEs or internal network architectures inherently include strings like `/etc/passwd`, `169.254.169.254`, or `<script>alert(1)</script>`.
   - *Resolution:* Marked as `label: "benign"`, `hard: true`. The text explains or analyzes the vulnerability in prose or Markdown code blocks without intending to trick an agent or trigger unauthorized execution in a renderer.
2. **Customer Support Inquiries Containing Malformed HTML or Code Snippets:**
   - E-commerce customers frequently report issues by pasting broken markdown, email signatures with `<` brackets, or quotes containing "ignore my previous email".
   - *Resolution:* Labeled `label: "benign"`, `hard: true` if phrasing closely mirrored prompt injection ("Please ignore what I said in my last ticket, I want the blue shirt instead"), while keeping the intent strictly legitimate.
3. **Internal vs. Localhost Documentation:**
   - Documentation for setting up a local development server often tells developers to bind to `127.0.0.1:8000` or `localhost:3000`.
   - *Resolution:* Labeled `label: "benign"`, `hard: true`. These are authentic developer setup guides, not attempts to force the AI agent to fetch loopback endpoints.
4. **Obvious Placeholders:**
   - Per brief specifications, all sample payloads avoid realistic looking credentials or tokens, using explicit placeholders like `[API-KEY]`, `[TOKEN]`, `[BAIT-VALUE]`, or standard harmless demonstration targets (`example.com`, `example.org`).

---

## Conclusion
All 1,000 blind samples across the 4 categories are generated, strictly schema-validated, and ready for benchmarking. Independence from the internal Radar implementation rules has been strictly preserved throughout.
