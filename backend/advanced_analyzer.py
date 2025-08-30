import dns.resolver
import dns.reversename
import socket
import ssl
import whois
import requests
from datetime import datetime
import json
from typing import Dict, List, Any

class AdvancedDomainAnalyzer:
    def __init__(self):
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'dns1', 'dns2', 'ns', 'smtp', 'secure', 'vpn', 'm', 'shop', 'ftp', 'mail2',
            'test', 'ns1', 'ns2', 'ns3', 'ns4', 'admin', 'blog', 'dev', 'staging',
            'api', 'cdn', 'static', 'media', 'img', 'images', 'js', 'css', 'assets'
        ]
        
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443]
    
    def get_dns_records(self, domain: str) -> Dict[str, Any]:
        """Get comprehensive DNS records for a domain"""
        try:
            records = {}
            
            # A Records (IPv4)
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                records['A'] = [str(r) for r in a_records]
            except:
                records['A'] = []
            
            # AAAA Records (IPv6)
            try:
                aaaa_records = dns.resolver.resolve(domain, 'AAAA')
                records['AAAA'] = [str(r) for r in aaaa_records]
            except:
                records['AAAA'] = []
            
            # MX Records (Mail Exchange)
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                records['MX'] = [str(r.exchange) for r in mx_records]
            except:
                records['MX'] = []
            
            # NS Records (Name Servers)
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                records['NS'] = [str(r) for r in ns_records]
            except:
                records['NS'] = []
            
            # TXT Records
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                records['TXT'] = [str(r) for r in txt_records]
            except:
                records['TXT'] = []
            
            # CNAME Records
            try:
                cname_records = dns.resolver.resolve(domain, 'CNAME')
                records['CNAME'] = [str(r) for r in cname_records]
            except:
                records['CNAME'] = []
            
            # SOA Records
            try:
                soa_records = dns.resolver.resolve(domain, 'SOA')
                soa = soa_records[0]
                records['SOA'] = {
                    'mname': str(soa.mname),
                    'rname': str(soa.rname),
                    'serial': soa.serial,
                    'refresh': soa.refresh,
                    'retry': soa.retry,
                    'expire': soa.expire,
                    'minimum': soa.minimum
                }
            except:
                records['SOA'] = {}
            
            return records
            
        except Exception as e:
            return {'error': f'DNS lookup failed: {str(e)}'}
    
    def check_ssl_certificate(self, domain: str) -> Dict[str, Any]:
        """Check SSL certificate details"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Parse certificate dates
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    
                    # Calculate days until expiration
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': not_before.isoformat(),
                        'not_after': not_after.isoformat(),
                        'days_until_expiry': days_until_expiry,
                        'is_expired': days_until_expiry < 0,
                        'is_expiring_soon': 0 <= days_until_expiry <= 30,
                        'san': cert.get('subjectAltName', []),
                        'signature_algorithm': cert.get('signatureAlgorithm', ''),
                        'key_size': cert.get('keySize', 'Unknown')
                    }
                    
        except Exception as e:
            return {'error': f'SSL check failed: {str(e)}'}
    
    def enumerate_subdomains(self, domain: str) -> Dict[str, Any]:
        """Enumerate subdomains using common wordlist"""
        try:
            found_subdomains = []
            
            for subdomain in self.common_subdomains:
                full_domain = f"{subdomain}.{domain}"
                try:
                    # Try to resolve the subdomain
                    dns.resolver.resolve(full_domain, 'A')
                    found_subdomains.append({
                        'subdomain': full_domain,
                        'status': 'active',
                        'type': 'A'
                    })
                except:
                    # Subdomain doesn't exist
                    pass
            
            return {
                'total_found': len(found_subdomains),
                'subdomains': found_subdomains,
                'searched_count': len(self.common_subdomains)
            }
            
        except Exception as e:
            return {'error': f'Subdomain enumeration failed: {str(e)}'}
    
    def port_scan(self, domain: str, ports: List[int] = None) -> Dict[str, Any]:
        """Scan common ports on a domain"""
        if ports is None:
            ports = self.common_ports
            
        try:
            open_ports = []
            closed_ports = []
            
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((domain, port))
                    sock.close()
                    
                    if result == 0:
                        # Port is open
                        service = self.get_service_name(port)
                        open_ports.append({
                            'port': port,
                            'service': service,
                            'status': 'open'
                        })
                    else:
                        closed_ports.append(port)
                        
                except Exception as e:
                    closed_ports.append(port)
            
            return {
                'total_ports_scanned': len(ports),
                'open_ports': open_ports,
                'closed_ports': closed_ports,
                'open_count': len(open_ports),
                'closed_count': len(closed_ports)
            }
            
        except Exception as e:
            return {'error': f'Port scan failed: {str(e)}'}
    
    def get_service_name(self, port: int) -> str:
        """Get common service name for a port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        return services.get(port, 'Unknown')
    
    def get_whois_info(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS information for a domain"""
        try:
            w = whois.whois(domain)
            
            # Handle different data types for dates
            def format_date(date_value):
                if not date_value:
                    return None
                if isinstance(date_value, list):
                    date_value = date_value[0] if date_value else None
                if date_value:
                    try:
                        return date_value.isoformat() if hasattr(date_value, 'isoformat') else str(date_value)
                    except:
                        return str(date_value)
                return None
            
            # Handle different data types for other fields
            def format_field(field_value):
                if not field_value:
                    return None
                if isinstance(field_value, list):
                    return field_value[0] if field_value else None
                return field_value
            
            return {
                'registrar': format_field(w.registrar),
                'creation_date': format_date(w.creation_date),
                'expiration_date': format_date(w.expiration_date),
                'updated_date': format_date(w.updated_date),
                'status': format_field(w.status),
                'name_servers': w.name_servers if w.name_servers else [],
                'emails': w.emails if w.emails else [],
                'org': format_field(w.org),
                'country': format_field(w.country)
            }
        except Exception as e:
            return {'error': f'WHOIS lookup failed: {str(e)}'}
    
    def comprehensive_analysis(self, domain: str) -> Dict[str, Any]:
        """Perform comprehensive domain analysis"""
        try:
            results = {
                'domain': domain,
                'analysis_timestamp': datetime.now().isoformat(),
                'dns_records': self.get_dns_records(domain),
                'ssl_certificate': self.check_ssl_certificate(domain),
                'subdomains': self.enumerate_subdomains(domain),
                'port_scan': self.port_scan(domain),
                'whois_info': self.get_whois_info(domain)
            }
            
            # Calculate security score
            security_score = self.calculate_security_score(results)
            results['security_score'] = security_score
            
            return results
            
        except Exception as e:
            return {'error': f'Comprehensive analysis failed: {str(e)}'}
    
    def calculate_security_score(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate a security score based on analysis results"""
        score = 100
        issues = []
        warnings = []
        
        # Check SSL certificate
        if 'ssl_certificate' in results and 'error' not in results['ssl_certificate']:
            ssl_info = results['ssl_certificate']
            if ssl_info.get('is_expired'):
                score -= 30
                issues.append('SSL certificate expired')
            elif ssl_info.get('is_expiring_soon'):
                score -= 15
                warnings.append('SSL certificate expiring soon')
        
        # Check open ports
        if 'port_scan' in results and 'error' not in results['port_scan']:
            open_ports = results['port_scan'].get('open_ports', [])
            dangerous_ports = [21, 23, 3389]  # FTP, Telnet, RDP
            
            for port_info in open_ports:
                if port_info['port'] in dangerous_ports:
                    score -= 20
                    issues.append(f'Dangerous port {port_info["port"]} ({port_info["service"]}) is open')
        
        # Check DNS security
        if 'dns_records' in results and 'error' not in results['dns_records']:
            txt_records = results['dns_records'].get('TXT', [])
            has_spf = any('spf' in record.lower() for record in txt_records)
            has_dkim = any('dkim' in record.lower() for record in txt_records)
            
            if not has_spf:
                score -= 10
                warnings.append('No SPF record found')
            if not has_dkim:
                score -= 10
                warnings.append('No DKIM record found')
        
        # Ensure score doesn't go below 0
        score = max(0, score)
        
        # Determine security level
        if score >= 80:
            level = 'Excellent'
        elif score >= 60:
            level = 'Good'
        elif score >= 40:
            level = 'Fair'
        elif score >= 20:
            level = 'Poor'
        else:
            level = 'Critical'
        
        return {
            'score': score,
            'level': level,
            'issues': issues,
            'warnings': warnings,
            'max_score': 100
        }
