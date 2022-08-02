from datetime import datetime
from cme.helpers.logger import write_log

class CMEModule:
    '''
        Uses WMI to dump DNS from an AD DNS Server.
        Module by @fang0654

    '''

    name = 'enum_dns'
    description = 'Uses WMI to dump DNS from an AD DNS Server'
    supported_protocols = ['smb']
    opsec_safe= True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        DOMAIN             Domain to enumerate DNS for. Defaults to all zones.
        '''
        self.domains = None
        if module_options and 'DOMAIN' in module_options:
            self.domains = module_options['DOMAIN']

    def on_admin_login(self, context, connection):

        if not self.domains:
            domains = []
            if output := connection.wmi(
                'Select Name FROM MicrosoftDNS_Zone', 'root\\microsoftdns'
            ):
                domains.extend(result['Name']['value'] for result in output)
                context.log.success(f'Domains retrieved: {domains}')
        else:
            domains = [self.domains]
        data = ""
        for domain in domains:
            if output := connection.wmi(
                f'Select TextRepresentation FROM MicrosoftDNS_ResourceRecord WHERE DomainName = "{domain}"',
                'root\\microsoftdns',
            ):
                domain_data = {}
                context.log.highlight(f"Results for {domain}")
                data += f"Results for {domain}\n"
                for entry in output:
                    text = entry['TextRepresentation']['value']
                    rname = text.split(' ')[0]
                    rtype = text.split(' ')[2]
                    rvalue = ' '.join(text.split(' ')[3:])
                    if domain_data.get(rtype, False):
                        domain_data[rtype].append(f"{rname}: {rvalue}")
                    else:
                        domain_data[rtype] = [f"{rname}: {rvalue}"]

                for k, v in sorted(domain_data.items()):
                    context.log.highlight(f"Record Type: {k}")
                    data += f"Record Type: {k}\n"
                    for d in sorted(v):
                        context.log.highlight("\t"+d)
                        data += "\t" + d + "\n"

        log_name = f'DNS-Enum-{connection.args.target[0]}-{datetime.now().strftime("%Y-%m-%d_%H%M%S")}.log'

        write_log(data, log_name)
        context.log.info(f"Saved raw output to {log_name}")

