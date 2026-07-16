import json
import traceback
from datetime import datetime

from jinja2 import Template, Environment, select_autoescape

import iris_interface.IrisInterfaceStatus as InterfaceStatus


def gen_ip_report_from_template(html_template, abuseipdb_report) -> InterfaceStatus.IIStatus:
    """
    Generates an HTML report for IP, displayed as an attribute in the IOC

    :param html_template: A string representing the HTML template
    :param abuseipdb_report: The JSON report fetched with AbuseIPDB API
    :return: IrisInterfaceStatus
    """
    if not html_template:
        return InterfaceStatus.I2Error("HTML template is empty")
    
    if not abuseipdb_report:
        return InterfaceStatus.I2Error("AbuseIPDB report is empty")
    
    try:
        # Create Jinja2 environment with autoescape
        env = Environment(autoescape=select_autoescape(['html', 'xml']))
        template = Template(html_template)
        
        # Prepare context
        context = abuseipdb_report.copy()
        
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
        else:
            context['isp_asn'] = 'Unknown'
        
        # Render template
        rendered = template.render(context)
        
        return InterfaceStatus.I2Success(data=rendered)
        
    except Exception as e:
        error_msg = f"Error rendering template: {str(e)}\n{traceback.format_exc()}"
        return InterfaceStatus.I2Error(error_msg)