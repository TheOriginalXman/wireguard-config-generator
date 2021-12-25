import qrcode
import json
import subprocess
import sys
import os
import getopt
from dotenv import load_dotenv
load_dotenv()

# This program will generate configs for wireguard.
# you will need to install qrcode and pillow in python
# and you need to install wireguard, so that you can call wg from your terminal

env = {
    "serverName" : str(os.getenv("SERVER_NAME")),
    "interfaceConfigPath" : str(os.getenv("INTERFACE_CONFIG_LOCATION")),
    "listeningPort" : str(os.getenv("PORT")),
    "serverSubnet" : {
        "value" : os.getenv('TUNNEL_NET'),
        "octet1" : int(os.getenv('TUNNEL_NET').split('.')[0]),
        "octet2" : int(os.getenv('TUNNEL_NET').split('.')[1]),
        "octet3" : int(os.getenv('TUNNEL_NET').split('.')[2]),
        "octet4" : int(os.getenv('TUNNEL_NET').split('.')[3].split('/')[0]),
        "cidr" : int(os.getenv('TUNNEL_NET').split('.')[3].split('/')[1])
    },
    "iptables" : os.getenv('IPTABLES'),
    "allowedIps" : os.getenv('ALLOWEDIPS'),
    "routeAllTraffic" : False,
    "endpoint" : os.getenv('ENDPOINT_URL') + ':' + os.getenv('PORT'),
    "clients" : int(os.getenv('NUMBER_OF_CLIENTS')), # TODO add client Names
    "preshared_key" : eval(os.getenv('PSK')),
    "dns" : os.getenv('DNS'),
    "peerConfigPath" : os.getenv('PEER_CONFIG_LOCATION')
    # TODO add ipv6 protocol
    }

def processFile(filePath):
    bp = open(filePath)
    bp = json.loads(bp)

    setServerSubnet(bp)

            # self.serverName = bp['name']    
            # self.interfaceConfigFilePath = bp['filePath']
            # self.listeningPort = bp['port']
            # self.serverSubnet = self.setServerSubnet(bp['serverSubnet'])
            # self.interfaceName = bp['natInterface']
            # self.endpoint = bp['endpoint']
            # self.peer_cidr = bp['peer_cidr']
            # self.clients = getClients
            

def setServerSubnet(bp):
     subnetValue = bp['serverSubnet']
     bp['serverSubnet'] = {
                            "value" : subnetValue,
                            "octet1" : int(subnetValue.split('.')[0]),
                            "octet2" : int(subnetValue.split('.')[1]),
                            "octet3" : int(subnetValue.split('.')[2]),
                            "octet4" : int(subnetValue.split('.')[3].split('/')[0]),
                            "cidr" : int(subnetValue.split('.')[3].split('/')[1])
                        }
    
################### Do not edit below this line ##################


def main(args):
    optionString = 'dhn:t:i:ac:f:'
    longOptions = ['default',
                    'help',
                    'port=',
                    'endpoint=',
                    'dns=',
                    'tunnel=',
                    'ipinterface=',
                    'allowedips=',
                    'clients=',
                    'psk=',
                    'ipv6=',
                    'file=',
                    'interfacepath=',
                    'clientpath=']
    try:
        options, remainder = getopt.getopt(args, optionString, longOptions)
    except getopt.GetoptError as e:
        print(e)
        print("For help refer to help manual, by running with option -h or --help, for more information")
        return
    # print 'OPTIONS   :', options

    optSet = set()
    for opt, arg in options:
        optSet.add(opt)
    
    if '-h' in optSet or '--help' in optSet:
        # TODO Create help message function
        display_help(optionString, longOptions)
        return
    elif '-d' in optSet or '--default' in optSet:
        print("Running with default configuration from .env")
        generate()
        return        

    if len(remainder) > 0:
        print(f"Error the following arguments, {remainder.join(',')} ,are not allowed. Please refer to help manual, by running with option -h or --help, for more information")

    for opt, arg in options:
        if opt in ('-f', '--file'):
            print(f"Processing {arg}")
            blueprint = processFile(arg)
            generate(blueprint)
            break
        elif opt in ('-n', '--dns'):
            env['dns'] = arg
        elif opt in ('-t', '--tunnel'):
            env['serverSubnet']['value'] = arg
        elif opt in ('-i', '--ipinterface'):
            env['iptables'] = arg
        elif opt in ('-a'):
            env['routeAllTraffic'] = True
        elif opt in ('--allowedips'):
            env['allowedIps'] = args
        elif opt in ('-c', '--clients'):
            env['clients'] = arg
            # TODO pass in client names and derive number of clients
        elif opt in ('--psk'):
            env['preshared_key'] = arg
        elif opt in ('--ipv6'):
            pass
            # ipv6 = arg
            #TODO add ipv6 support
        elif opt in ('--interfacepath'):
            env['interfaceConfigPath'] = arg
        elif opt in ('--clientpath'):
            env['peerConfigPath'] = arg

    # print 'OUTPUT    :', output_filename
    # print 'REMAINING :', remainder

def generate(blueprint):
    #Validate inputs
    # TODO create validation for inputs/globals

    wg_priv_keys = []
    wg_pub_keys = []
    wg_psk = []

    # Gen-Keys
    for x in range(len(blueprint['clients'])+1):
        keys = generate_wireguard_keys()

        if x == 0:
            blueprint['privateKey'] = keys[0]
            blueprint['publicKey'] = keys[1]
            blueprint['presharedKey'] = keys[2]
        else:
            blueprint['clients'][x-1]['privateKey'] = keys[0]
            blueprint['clients'][x-1]['privateKey'] = keys[1]
            blueprint['clients'][x-1]['privateKey'] = keys[2]

        # wg_priv_keys.append(keys[0])
        # wg_pub_keys.append(keys[1])
        # wg_psk.append(keys[2])
    server = serverConfig(blueprint)
    serverFileLocation = f"{blueprint['filePath']}{blueprint['name']}.conf"

    writeFiles(server, serverFileLocation)

    for x in range(len(blueprint['clients'])):
        peer = peerConfig(blueprint,blueprint['clients'][x])
        peerFileLocation = f"{blueprint['clients'][x]['filePath']}{blueprint['clients'][x]['name']}.conf"

        writeFiles(peer, peerFileLocation)
        


def writeFiles(config, location):
    make_qr_code_png(config, f"{location}.png")
    with open(f"{location}.conf", "wt+") as f:
        f.write(config)

def serverConfig(bp):

    ################# Server-Config ##################
    server_config = f"[Interface]\n" \
        f"# Name = {bp['name']}\n" \
        f"Address = {bp['serverSubnet']['octet1']}.{bp['serverSubnet']['octet2']}.{bp['serverSubnet']['octet3']}.{bp['serverSubnet']['octet4']+1}/{bp['serverSubnet']['cidr']}\n" \
        f"ListenPort = {bp['port']}\n" \
        f"PrivateKey = {bp['privateKey']}\n"

    if bp['natInterface'] and bp['natInterface']['ipv4']: #TODO add ipv6
        server_config += f"PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {bp['natInterface']['ipv4']} -j MASQUERADE\n" \
            f"PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {bp['natInterface']['ipv4']} -j MASQUERADE\n"

    for x in range(len(bp['clients'])):
        server_config += f"[Peer]\n" \
            f"# Name = {bp['clients'][x]['name']}\n" \
            f"PublicKey = {['clients'][x]['publicKey']}\n" \
            f"PresharedKey = {['clients'][x]['presharedKey']}\n" \
            f"AllowedIPs = {bp['serverSubnet']['octet1']}.{bp['serverSubnet']['octet2']}.{bp['serverSubnet']['octet3']}.{bp['serverSubnet']['octet4']+1+x}/32\n"

    print("*"*10 + " Server-Conf " + "*"*10)
    print(server_config)

    return server_config

def peerConfig(bp, client):
    ################# Client-Configs ##################

    client_config = f"[Interface]\n" \
        f"# Name = {client['name']}\n" \
        f"Address = {bp['serverSubnet']['octet1']}.{bp['serverSubnet']['octet2']}.{bp['serverSubnet']['octet3']}.{bp['serverSubnet']['octet4']+1+}/24\n" \
        f"PrivateKey = {client['privateKey']}\n"

    if client['dns']:
        client_config += f"DNS = {client['dns']}\n"

    client_config += f"[Peer]\n" \
        f"# Name = {bp['name']}\n" \
        f"PublicKey = {bp['publicKey']}\n" \
        f"PresharedKey = {client['presharedKey']}\n" \
        f"Endpoint = {bp['endpoint']:bp['port']}\n" 
    
    if client['keepAlive']:
        client_config += f"PersistentKeepalive = {client['keepAlive']}"

    if client['routeAllTraffic'] == False:
        client_config += f"AllowedIPs = {','.join(client['allowedIps'])}\n"
    else:
        client_config += f"AllowedIPs = 0.0.0.0/0\n"

    print("*"*10 + f" Client-Conf " + "*"*10)
    print(client_config)

    #print("*"*10 + " Debugging " + "*"*10 )
    #print("*"*10 + " Priv-Keys " + "*"*10 )
    # print(wg_priv_keys)
    #print("*"*10 + " Pub-Keys " + "*"*10 )
    # print(wg_pub_keys)


def generate_wireguard_keys():
    privkey = subprocess.check_output(
        "wg genkey", shell=True).decode("utf-8").strip()
    pubkey = subprocess.check_output(
        f"echo '{privkey}' | wg pubkey", shell=True).decode("utf-8").strip()
    psk = subprocess.check_output(
        "wg genkey", shell=True).decode("utf-8").strip()

    return (privkey, pubkey, psk)


def make_qr_code_png(text, filename):
    img = qrcode.make(text)
    img.save(f"{filename}")
    
def display_help(optionString,longOptions):
    print("Wireguard Config Generator\n\n")
    print("\tAllowed Options/Flags")
    print("\n\tAll options should be added with a single dash for short for or double dash with long form.")
    print("\tex: -d or --default")
    print("\tOptions should be followed by a colon, ':', for single dash flags or an equals sign, '=' for double dash flags.")
    print("\tex. -n:'8.8.8.8' or --dns='8.8.8.8'")
    print("\n\tHere is an example of multiple arguments being passed.")
    print("\tex. wireguard-config-generator.py -a -n:'8.8.8.8' --clients=3")

    for opt in optionString:
        if opt == ':':
            continue
        printOptionDefinition(f"-{opt}", getOptionDefinition(opt))
        
    for opt in longOptions:
        if '=' in opt:
            opt = opt[:-1]
        printOptionDefinition(f"--{opt}", getOptionDefinition(opt))

def printOptionDefinition(opt, definition):
    print("\n\n")
    print(f"\t\t {opt} \t\t\t {definition}")

def getOptionDefinition(opt):
    if opt in ('h', 'help'):
        return "Overrides all other flags and arguments and prints the help manual."
    elif opt in ('d', 'default'):
        return "Overrides an other options that are set and all variables are set to values in the .env file."
    elif opt in ('f', 'file'):
        return "Feature still in development."
        # return "Parameter: String. Takes a string path to the JSON file that can list the settings of multiple Interfaces and peers. All other setting and variables will be ignored. Example: python3 -f:'/user/directory/configs.json'"
    elif opt in ('n', 'dns'):
        return "Parameter: String. Sets the dns ip value for all peers. Leave blank if DNS is not needed on the peers."
    elif opt in ('t', 'tunnel'):
        return "Parameter: String. This sets the ip subnet for the tunnel on the interface."
    elif opt in ('i', 'ipinterface'):
        return "Parameter: String. This sets the name of the  Internet-facing interface. This may be ens2p0 or similar on more recent Ubuntu versions (check, e.g., 'ip a' for details about your local interfaces)."
    elif opt in ('a'):
        return "This option will forward all traffic from the peers to your interface."
    elif opt in ('allowedips'):
        return "Parameter: String. This will set the subnets that the peers will be allowed to connect to on the interface. The value should be comma seperated IPs."
    elif opt in ('c', 'clients'):
        return "Parameter: Integer. This will set the number of peers to be generated for the interface."
    elif opt in ('psk'):
        return "Parameter: Boolean. This will determine if there should be a preshared key generated for each peer."
    elif opt in ('ipv6'):
        return "Feature still in development."
    elif opt in ('interfacepath'):
        return "Paramter: String. This would be the path where the interface config of the server will be saved to."
    elif opt in ('clientpath'):
        return "Paramter: String. This would be the path where the all of the peer information including the QR codes will be saved to."
    elif opt in ('port'):
        return "Parameter: String. This should be the listening port set for the wireguard service. If the server is behind a device, e.g., a router that is doing NAT, be sure to forward the specified port on which WireGuard will be running from the router to the WireGuard server."
    elif opt in ('endpoint'):
        return "Parameter: String. This value should be set to your public ip or domain of the server you'd like to connect to."

if __name__ == "__main__":
    main(sys.argv[1:])
