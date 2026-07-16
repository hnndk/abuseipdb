#!/usr/bin/env python3
#
#  IRIS AbuseIPDB Module Source Code
#  contact@dfir-iris.org
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
import logging
import traceback
import requests
import json

from iris_interface.IrisModuleInterface import IrisPipelineTypes, IrisModuleInterface, IrisModuleTypes
import iris_interface.IrisInterfaceStatus as InterfaceStatus

from iris_abuseipdb_module.abuseipdb_handler.abuseipdb_helper import gen_ip_report_from_template


class AbuseIPDBHandler(object):
    def __init__(self, mod_config, server_config, logger):
        self.mod_config = mod_config
        self.server_config = server_config
        self.log = logger
        self.api_key = self.mod_config.get('abuseipdb_api_key')
        self.is_premium = self.mod_config.get('abuseipdb_key_is_premium', False)
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.session = requests.Session()
        self.session.headers.update({
            "Key": self.api_key,
            "Accept": "application/json"
        })

    def _query_abuseipdb(self, ip_address: str) -> dict:
        """
        Query the AbuseIPDB API for an IP address
        
        :param ip_address: IP address to query
        :return: API response
        """
        url = f"{self.base_url}/check"
        
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90
        }
        
        # Add premium parameters if key is premium
        if self.is_premium:
            params["verbose"] = True
        
        # Configure proxies if set
        proxies = {}
        if self.server_config.get('http_proxy'):
            proxies['http'] = self.server_config.get('HTTP_PROXY')
        if self.server_config.get('https_proxy'):
            proxies['https'] = self.server_config.get('HTTPS_PROXY')
        
        try:
            response = self.session.get(url, params=params, proxies=proxies if proxies else None)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.log.error(f"Error querying AbuseIPDB: {e}")
            raise

    def _validate_report(self, report):
        """
        Validate the AbuseIPDB report
        
        :param report: Report from AbuseIPDB API
        :return: IIStatus
        """
        self.log.info('AbuseIPDB report fetched.')
        
        if not report:
            self.log.error('Unable to get report. Is the API key valid?')
            return InterfaceStatus.I2Error("Empty report received")
        
        data = report.get('data')
        if not data:
            error_msg = report.get('errors', [{}])[0].get('detail', 'Unknown error')
            self.log.error(f'Got invalid feedback from AbuseIPDB: {error_msg}')
            return InterfaceStatus.I2Error(f"API Error: {error_msg}")
        
        return InterfaceStatus.I2Success(data=report)

    def tag_if_malicious_or_suspicious(self, confidence_score: int, ioc):
        """
        Tag an IOC based on Abuse Confidence Score
        
        :param confidence_score: Abuse Confidence Score (0-100)
        :param ioc: IOC to tag
        :return: None
        """
        try:
            malicious_threshold = float(self.mod_config.get('abuseipdb_tag_malicious_threshold', 80))
            suspicious_threshold = float(self.mod_config.get('abuseipdb_tag_suspicious_threshold', 50))
            
            if ioc.ioc_tags is None:
                ioc.ioc_tags = ""
            
            # Remove existing AbuseIPDB tags
            tags_list = [tag.strip() for tag in ioc.ioc_tags.split(',') if tag.strip()]
            tags_list = [tag for tag in tags_list if not tag.startswith('abuse:')]
            
            # Add new tag based on confidence score
            if confidence_score >= malicious_threshold:
                tags_list.append('abuse:malicious')
                self.log.info(f'Tagged IOC {ioc.ioc_value} as malicious (score: {confidence_score})')
            elif confidence_score >= suspicious_threshold:
                tags_list.append('abuse:suspicious')
                self.log.info(f'Tagged IOC {ioc.ioc_value} as suspicious (score: {confidence_score})')
            else:
                tags_list.append('abuse:clean')
                self.log.info(f'Tagged IOC {ioc.ioc_value} as clean (score: {confidence_score})')
            
            # Update tags
            ioc.ioc_tags = ','.join(tags_list)
            
        except Exception as e:
            self.log.error(f"Error in tag_if_malicious_or_suspicious: {str(e)}")

    def assign_asn_tag(self, asn: str, ioc):
        """
        Assign ASN tag to IOC
        
        :param asn: ASN to assign
        :param ioc: IOC to tag
        :return: None
        """
        try:
            if not asn:
                self.log.info('ASN was null - skipping')
                return
            
            if ioc.ioc_tags is None:
                ioc.ioc_tags = ""
            
            tags_list = [tag.strip() for tag in ioc.ioc_tags.split(',') if tag.strip()]
            asn_tag = f'ASN:{asn}'
            
            if asn_tag not in tags_list:
                tags_list.append(asn_tag)
                ioc.ioc_tags = ','.join(tags_list)
                self.log.info(f'Added ASN tag {asn_tag} to IOC')
            else:
                self.log.info('ASN already tagged for this IOC. Skipping')
                
        except Exception as e:
            self.log.error(f"Error in assign_asn_tag: {str(e)}")

    def _add_attribute_to_ioc(self, ioc, rendered_report):
        """
        Safely add an attribute to an IOC
        
        :param ioc: IOC object
        :param rendered_report: Rendered HTML report
        :return: IIStatus
        """
        try:
            # Method 1: Try to use the IRIS API if available
            try:
                from app.datamgmt.manage.manage_attribute_db import add_tab_attribute_field
                
                # Try different parameter combinations
                try:
                    # Try with all parameters
                    result = add_tab_attribute_field(
                        ioc, 
                        tab_name='AbuseIPDB Report', 
                        field_name="HTML report", 
                        field_type="html",
                        field_value=rendered_report
                    )
                    if result:
                        self.log.info('Successfully added AbuseIPDB report as attribute (method 1)')
                        return InterfaceStatus.I2Success()
                except TypeError:
                    # Try with different parameter order
                    try:
                        result = add_tab_attribute_field(
                            ioc.id,
                            "AbuseIPDB Report",
                            rendered_report,
                            "html"
                        )
                        if result:
                            self.log.info('Successfully added AbuseIPDB report as attribute (method 2)')
                            return InterfaceStatus.I2Success()
                    except:
                        pass
                        
            except ImportError:
                self.log.warning("add_tab_attribute_field not available, using fallback method")
            
            # Method 2: Fallback - Use direct database access
            try:
                from app import db
                from app.models import IocAttribute
                
                # Check if attribute already exists
                existing = IocAttribute.query.filter_by(
                    ioc_id=ioc.id,
                    attribute_name="AbuseIPDB Report"
                ).first()
                
                if existing:
                    # Update existing attribute
                    existing.attribute_value = rendered_report
                    existing.attribute_type = "html"
                else:
                    # Create new attribute
                    attr = IocAttribute(
                        ioc_id=ioc.id,
                        attribute_name="AbuseIPDB Report",
                        attribute_type="html",
                        attribute_value=rendered_report,
                        source="AbuseIPDB Module"
                    )
                    db.session.add(attr)
                
                db.session.commit()
                self.log.info('Successfully added/updated AbuseIPDB report as attribute (fallback)')
                return InterfaceStatus.I2Success()
                
            except Exception as e:
                self.log.error(f"Fallback attribute addition failed: {str(e)}")
                return InterfaceStatus.I2Error(f"Failed to add attribute: {str(e)}")
                
        except Exception as e:
            self.log.error(f"Error in _add_attribute_to_ioc: {str(e)}")
            return InterfaceStatus.I2Error(f"Error adding attribute: {str(e)}")

    def handle_abuseipdb_ip(self, ioc):
        """
        Handles an IOC of type IP and adds AbuseIPDB insights
        
        :param ioc: IOC instance
        :return: IIStatus
        """
        self.log.info(f'Getting AbuseIPDB report for {ioc.ioc_value}')
        
        try:
            report = self._query_abuseipdb(ioc.ioc_value)
        except Exception as e:
            error_msg = f'Error querying AbuseIPDB: {str(e)}'
            self.log.error(error_msg)
            # Don't fail completely - continue processing
            return InterfaceStatus.I2Success("Query failed but continuing")
        
        # Validate report
        status = self._validate_report(report)
        if status.is_failure():
            self.log.error(f'Report validation failed: {status.get_message()}')
            return status
        
        report = status.get_data()
        results = report.get('data', {})
        
        # Extract confidence score
        confidence_score = results.get('abuseConfidenceScore', 0)
        
        # Tag based on confidence score
        try:
            self.tag_if_malicious_or_suspicious(confidence_score, ioc)
        except Exception as e:
            self.log.error(f'Error in tag_if_malicious_or_suspicious: {str(e)}')
        
        # Assign ASN tag if enabled
        if self.mod_config.get('abuseipdb_ip_assign_asn_as_tag', True):
            try:
                asn = results.get('asn')
                self.assign_asn_tag(asn, ioc)
            except Exception as e:
                self.log.error(f'Error in assign_asn_tag: {str(e)}')
        
        # Add report as attribute if enabled
        if self.mod_config.get('abuseipdb_report_as_attribute', True):
            self.log.info('Adding AbuseIPDB IP Report to IOC')
            
            try:
                # Generate HTML report
                status = gen_ip_report_from_template(
                    html_template=self.mod_config.get('abuseipdb_ip_report_template'),
                    abuseipdb_report=report
                )
                
                if status.is_failure():
                    self.log.warning(f'Failed to generate report: {status.get_message()}')
                else:
                    rendered_report = status.get_data()
                    
                    # Add attribute to IOC
                    attr_status = self._add_attribute_to_ioc(ioc, rendered_report)
                    if attr_status.is_failure():
                        self.log.warning(f'Failed to add attribute: {attr_status.get_message()}')
                    else:
                        self.log.info('Successfully added AbuseIPDB report as attribute')
                        
            except Exception as e:
                self.log.error(f'Error adding report as attribute: {str(e)}')
                # Don't fail the entire processing
        else:
            self.log.info('Skipped adding attribute report. Option disabled')
        
        return InterfaceStatus.I2Success("Successfully processed IP")