import xml.etree.ElementTree as ET
import subprocess

import click
import nmap


def pinger(target):
    cmd = ['ping', '-c', '1', '-W', '2', target]
    if subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        return True
    else:
        return False


def report_parser(target):
    host_ports = {}
    port_list = []
    try:
        tree = ET.parse(f"{target}-scan.xml")
        root = tree.getroot()

        for host in root.findall('host'):
            for ip in host.findall('address'):
                address = ip.attrib['addr']

                for ports in host.findall('ports'):
                    for port in ports.findall('port'):
                        port_number = int(port.attrib['portid'])
                        port_list.append(port_number)

                    host_ports[address] = port_list

        return host_ports
    except Exception as err:
        print(err)
        return host_ports


def masscan_scanner(target, interface, ports):
    if pinger(target) is False:
        print("Target doesn't seem to be reachable. Scan may fail.")

    rate = "1000"

    print(f"[+] Starting masscan for host: {target}")
    scan = subprocess.Popen(['masscan', target, '--ports', ports, '--max-rate', rate, '-oX', f"{target}-scan.xml"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    scan.communicate()

    return(report_parser(target))


def nmap_scanner(masscan_result):
    nmap_args = "-Pn -sS -sC -sV -T4 -p"

    nm = nmap.PortScanner()
    for result in masscan_result:
        for host, ports in result.iteritems():
            args = nmap_args + ','.join(map(str, ports))
            print(args)
            print(f"[+] nmap scan for {host}")
            nm.scan(host, arguments=args)

    print(nm.scaninfo())


@click.command()
@click.option("--target", default="", help="Target's IP address")
@click.option("--interface", default="", help="Source interface for the scan")
@click.option("--ports", default="0-65535", help="Port range to scan. Defaults to 0-65535 (all ports)")
def main(target, interface, ports):
    masscan_result = masscan_scanner(target, interface, ports)
    nmap_scanner(masscan_result)


if __name__ == "__main__":
    main()
