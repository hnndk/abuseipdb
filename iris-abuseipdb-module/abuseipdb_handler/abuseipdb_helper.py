import json
import traceback

from jinja2 import Template
import logging
from iris_interface import IrisInterfaceStatus

log = logging.getLogger('iris_abuseipdb_module.abuseipdb_helper')


def gen_ip_report_from_template(html_template, abuseipdb_report) -> IrisInterfaceStatus:
    """
    Generates an HTML report for IP, displayed as an attribute in the IOC

    :param html_template: A string representing the HTML template
    :param abuseipdb_report: The JSON report fetched with AbuseIPDB API
    :return: IrisInterfaceStatus
    """
    template = Template(html_template)
    context = abuseipdb_report
    
    # Extract data from the report
    data = context.get('data', {})
    
    # Add useful calculated fields to context
    context['results'] = data
    
    # Calculate severity level based on confidence score
    confidence_score = data.get('abuseConfidenceScore', 0)
    if confidence_score >= 80:
        context['severity'] = 'malicious'
    elif confidence_score >= 50:
        context['severity'] = 'suspicious'
    else:
        context['severity'] = 'clean'
    
    # Format the country code for flag display
    country_code = data.get('countryCode', '')
    if country_code:
        context['country_code_lower'] = country_code.lower()
    
    # Format last reported date for better display
    last_reported = data.get('lastReportedAt', '')
    if last_reported:
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(last_reported.replace('Z', '+00:00'))
            context['last_reported_formatted'] = dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            context['last_reported_formatted'] = last_reported
    
    # Add report count summary
    total_reports = data.get('totalReports', 0)
    context['total_reports'] = total_reports
    
    # Check if there are reports for premium users
    reports = data.get('reports', [])
    context['has_reports'] = len(reports) > 0
    context['reports_count'] = len(reports)
    
    # Add ISP and ASN info
    isp = data.get('isp', '')
    asn = data.get('asn', '')
    if isp and asn:
        context['isp_asn'] = f"{isp} (AS{asn})"
    elif isp:
        context['isp_asn'] = isp
    elif asn:
        context['isp_asn'] = f"AS{asn}"
    
    try:
        rendered = template.render(context)
    except Exception:
        log.error(traceback.format_exc())
        return IrisInterfaceStatus.I2Error(traceback.format_exc())

    return IrisInterfaceStatus.I2Success(data=rendered)