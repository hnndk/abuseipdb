#!/usr/bin/env python3
#
#  IRIS Source Code
#  Copyright (C) 2021 - Airbus CyberSecurity (SAS)
#  ir@cyberactionlab.net
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

module_name = "IrisAbuseIPDB"
module_description = "Provides an interface between AbuseIPDB and IRIS"
interface_version = "1.2.0"
module_version = "1.2.1"
pipeline_support = False
pipeline_info = {}

module_configuration = [
    {
        "param_name": "abuseipdb_api_key",
        "param_human_name": "AbuseIPDB API Key",
        "param_description": "API key to use to communicate with AbuseIPDB",
        "default": None,
        "mandatory": True,
        "type": "sensitive_string"
    },
    {
        "param_name": "abuseipdb_key_is_premium",
        "param_human_name": "AbuseIPDB Key is premium",
        "param_description": "Set to True if the AbuseIPDB key is premium",
        "default": False,
        "mandatory": True,
        "type": "bool"
    },
    {
        "param_name": "abuseipdb_manual_hook_enabled",
        "param_human_name": "Manual triggers on IOCs",
        "param_description": "Set to True to offers possibility to manually triggers the module via the UI",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "abuseipdb_on_update_hook_enabled",
        "param_human_name": "Triggers automatically on IOC update",
        "param_description": "Set to True to automatically add a AbuseIPDB insight each time an IOC is updated",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "abuseipdb_on_create_hook_enabled",
        "param_human_name": "Triggers automatically on IOC create",
        "param_description": "Set to True to automatically add a AbuseIPDB insight each time an IOC is created",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "abuseipdb_ip_assign_asn_as_tag",
        "param_human_name": "Assign ASN tag to IP",
        "param_description": "Assign a new tag to IOC IPs with the ASN fetched from AbuseIPDB",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Insights"
    },
    {
        "param_name": "abuseipdb_tag_malicious_threshold",
        "param_human_name": "IOC tag malicious threshold",
        "param_description": "Tag the IOC has malicious if the percentage of detection is above the specified threshold",
        "default": "80",
        "mandatory": True,
        "type": "float",
        "section": "Insights"
    },
    {
        "param_name": "abuseipdb_tag_suspicious_threshold",
        "param_human_name": "IOC tag suspicious threshold",
        "param_description": "Tag the IOC has suspicious if the percentage of detection is above the specified threshold",
        "default": "50",
        "mandatory": True,
        "type": "float",
        "section": "Insights"
    },
    {
        "param_name": "abuseipdb_report_as_attribute",
        "param_human_name": "Add AbuseIPDB report as new IOC attribute",
        "param_description": "Creates a new attribute on the IOC, based on the AbuseIPDB report",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Insights"
    },
    {
        "param_name": "abuseipdb_ip_report_template",
        "param_human_name": "IP report template",
        "param_description": "IP report template used to add a new custom attribute to the target IOC",
        "default": "<div class=\"row\">\n    <div class=\"col-12\">\n        <h3>AbuseIPDB Report</h3>\n        <dl class=\"row\">\n            <dt class=\"col-sm-3\">Abuse Confidence Score</dt>\n            <dd class=\"col-sm-9\">\n                <span class=\"badge {% if results.abuseConfidenceScore > 80 %}badge-danger{% elif results.abuseConfidenceScore > 50 %}badge-warning{% else %}badge-success{% endif %}\">\n                    {{ results.abuseConfidenceScore }}%\n                </span>\n            </dd>\n            \n            {% if results.countryCode %}\n            <dt class=\"col-sm-3\">Country</dt>\n            <dd class=\"col-sm-9\">\n                {% if results.countryCode %}\n                <span class=\"fi fi-{{ results.countryCode|lower }}\"></span>\n                {% endif %}\n                {{ results.countryCode }}\n            </dd>\n            {% endif %}\n            \n            {% if results.isp %}\n            <dt class=\"col-sm-3\">ISP</dt>\n            <dd class=\"col-sm-9\">{{ results.isp }}</dd>\n            {% endif %}\n            \n            {% if results.domain %}\n            <dt class=\"col-sm-3\">Domain</dt>\n            <dd class=\"col-sm-9\">{{ results.domain }}</dd>\n            {% endif %}\n            \n            {% if results.totalReports %}\n            <dt class=\"col-sm-3\">Total Reports</dt>\n            <dd class=\"col-sm-9\">{{ results.totalReports }}</dd>\n            {% endif %}\n            \n            {% if results.lastReportedAt %}\n            <dt class=\"col-sm-3\">Last Reported</dt>\n            <dd class=\"col-sm-9\">{{ results.lastReportedAt }}</dd>\n            {% endif %}\n        </dl>\n    </div>\n</div>\n\n{% if results.reports %}\n<div class=\"row\">\n    <div class=\"col-12\">\n        <h3>Recent Reports</h3>\n        <div class=\"table-responsive\">\n            <table class=\"table table-bordered table-striped table-hover\">\n                <thead>\n                    <tr>\n                        <th>Date</th>\n                        <th>Comment</th>\n                        <th>Categories</th>\n                    </tr>\n                </thead>\n                <tbody>\n                    {% for report in results.reports %}\n                    <tr>\n                        <td>{{ report.reportedAt }}</td>\n                        <td>{{ report.comment }}</td>\n                        <td>\n                            {% for category in report.categories %}\n                            <span class=\"badge badge-info\">{{ category }}</span>\n                            {% endfor %}\n                        </td>\n                    </tr>\n                    {% endfor %}\n                </tbody>\n            </table>\n        </div>\n    </div>\n</div>\n{% endif %}\n\n<div class=\"row\">\n    <div class=\"col-12\">\n        <div class=\"accordion\">\n            <h3>Raw Report</h3>\n\n            <div class=\"card\">\n                <div class=\"card-header collapsed\" id=\"drop_raw_abuse\" data-toggle=\"collapse\" data-target=\"#drop_raw_abuse_content\" aria-expanded=\"false\" role=\"button\">\n                    <div class=\"span-icon\">\n                        <div class=\"flaticon-file\"></div>\n                    </div>\n                    <div class=\"span-title\">\n                        Raw JSON\n                    </div>\n                    <div class=\"span-mode\"></div>\n                </div>\n                <div id=\"drop_raw_abuse_content\" class=\"collapse\" aria-labelledby=\"drop_raw_abuse\">\n                    <div class=\"card-body\">\n                        <div id='abuse_raw_ace'>{{ results| tojson(indent=4) }}</div>\n                    </div>\n                </div>\n            </div>\n        </div>\n    </div>\n</div>\n\n<script>\nvar abuse_raw = ace.edit(\"abuse_raw_ace\", {\n    autoScrollEditorIntoView: true,\n    minLines: 20,\n});\nabuse_raw.setReadOnly(true);\nabuse_raw.setTheme(\"ace/theme/tomorrow\");\nabuse_raw.session.setMode(\"ace/mode/json\");\nabuse_raw.renderer.setShowGutter(true);\nabuse_raw.setOption(\"showLineNumbers\", true);\nabuse_raw.setOption(\"showPrintMargin\", false);\nabuse_raw.setOption(\"maxLines\", \"Infinity\");\nabuse_raw.session.setUseWrapMode(true);\nabuse_raw.setOption(\"indentedSoftWrap\", true);\nabuse_raw.renderer.setScrollMargin(8, 5);\n</script>",
        "mandatory": False,
        "type": "textarea",
        "section": "Templates"
    },
]