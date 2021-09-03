import csv
import xml.etree.ElementTree as ET
import shlex
import subprocess

import click
import nmap
from rich.console import Console
from rich.table import Table

CSVFILE = 'ports.csv'


def splitter(cmd):
    return shlex.split(cmd)


def pinger(target):
    return not bool(
        subprocess.call(
            splitter(f'ping -c 1 -W 2 {target}'),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    )


def report_parser(target):
    host_ports = {}
    port_list = []
    try:
        tree = ET.parse(f'{target}-scan.xml')
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
    console = Console()
    if pinger(target) is False:
        console.print("[bold red]Target doesn't seem to be reachable. Scan may fail.")

    rate = '1000'

    with console.status(f'[bold blue]Masscan for target {target} in progress...', spinner_style='bold blue'):
        scan = subprocess.Popen(
            splitter(f'masscan {target} --ports {ports} --max-rate {rate} -oX {target}-scan.xml'),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        scan.communicate()


def nmap_scanner(nmap_target):
    console = Console()
    ports = []

    nm = nmap.PortScanner()
    for result in nmap_target:
        for port in nmap_target[result]:
            ports.append(port)

    with console.status(
        f'[bold yellow]Nmap scan for {result}. Scanning TCP ports {ports}', spinner_style='bold yellow'
    ):
        nm.scan(
            result,
            arguments=f"-sS -sC -sV -T4 -p{','.join(map(str, ports))} -oN {result}-scan.txt",
        )


def nmap_reporter(target):
    table = Table(title=f'Port scan for {target}')

    table.add_column('Port')
    table.add_column('Status')
    table.add_column('Service')
    table.add_column('Additional info')

    with open(CSVFILE, newline='') as file:
        reader = csv.reader(
            file,
            delimiter=';',
        )
        for row in reader:
            table.add_row(row[5], row[6], row[7], f'{row[8]} {row[10]}')

    console = Console()
    console.print(table)


@click.command()
@click.option('--target', default='', help="Target's IP address")
@click.option('--interface', default='', help='Source interface for the scan')
@click.option(
    '--ports',
    default='0-65535',
    help='Port range to scan. Defaults to 0-65535 (all ports)',
)
def main(target, interface, ports):
    masscan_scanner(target, interface, ports)
    nmap_target = report_parser(target)
    nmap_scanner(nmap_target)
    nmap_reporter(target)


if __name__ == '__main__':
    main()
