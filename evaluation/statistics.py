import json
import os
import argparse
import csv


def get_json_report_statistics():
    # Parse a json report while deduplicating vulnerabilities.
    def parse_report(path):
        data = open(path, 'rb').read()
        data = json.loads(data)
        vulns = set()
        for vuln in data['vuln']:
            vulns.add((vuln['eval']['IoControlCode'], vuln['title']))
        report = {}
        for vuln in vulns:
            if vuln[1] not in report:
                report[vuln[1]] = 1
            else:
                report[vuln[1]] += 1
        return data['basic'], report

    if os.path.isdir(args.path):
        if args.path.endswith('/'):
            args.path = args.path[:-1]

        walks = [{'root': root, 'dirs': dirs, 'files': files} for root, dirs, files in os.walk(args.path)]
        with open(f'{args.path}/vulns.csv', 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            vuln_titles = ['map physical memory', 'controllable process handle', 'dest or src controllable', 'buffer overflow', 'null pointer dereference - input buffer', 'null pointer dereference - allocated memory', 'read/write controllable address', 'arbitrary shellcode execution', 'arbitrary wrmsr', 'arbitrary out', 'ObjectName in ObjectAttributes controllable']
            writer.writerow(['driver'] + vuln_titles + ['time (ioctl handler)', 'time (hunting vulns)', 'memory (ioctl handler)', 'memory (hunting vulns)', 'unique addr (ioctl handler)', 'unique addr (hunting vulns)'])
            statistics = {}
            for vuln_title in vuln_titles:
                statistics[vuln_title] = 0

            # Recursively parse json reports in a directory.
            for walk in walks:
                root = walk['root']
                if root[-1] == '/':
                    root = root[:-1]

                for f in walk['files']:
                    if f.lower().endswith('.json'):
                        path = f'{root}/{f}'
                        basic, report = parse_report(path)
                        vuln_count = []

                        # Count the types of vulnerabilities.
                        for vuln_title in vuln_titles:
                            if vuln_title in report:
                                vuln_count.append(report[vuln_title])
                                statistics[vuln_title] += report[vuln_title]
                            else:
                                vuln_count.append(0)

                        # Get the information of performance of analyzing a driver.
                        basic_info = []
                        if 'time' in basic:
                            if 'ioctl handler' in basic['time']:
                                basic_info.append(basic['time']['ioctl handler'])
                            else:
                                basic_info.append(0)
                            if 'hunting vulns' in basic['time']:
                                basic_info.append(basic['time']['hunting vulns'])
                            else:
                                basic_info.append(0)
                        if 'memory' in basic:
                            if 'ioctl handler' in basic['memory']:
                                basic_info.append(basic['memory']['ioctl handler'])
                            else:
                                basic_info.append(0)
                            if 'hunting vulns' in basic['memory']:
                                basic_info.append(basic['memory']['hunting vulns'])
                            else:
                                basic_info.append(0)
                        if 'unique addr' in basic:
                            if 'ioctl handler' in basic['unique addr']:
                                basic_info.append(basic['unique addr']['ioctl handler'])
                            else:
                                basic_info.append(0)
                            if 'hunting vulns' in basic['unique addr']:
                                basic_info.append(basic['unique addr']['hunting vulns'])
                            else:
                                basic_info.append(0)

                        writer.writerow([basic['path']] + vuln_count + basic_info)
        print(statistics)
    elif os.path.isfile(args.path):
        if not args.path.lower().endswith('.json'):
            print('target file is not a json file')
            return
        
        report = parse_report(args.path)
        print(report)
    else:
        print(f'{args.path} is not a dir or a file.')

def copy_wdm_driver():
    # Recursively copy WDM drivers in a directory to <path>/wdm.
    if args.path[-1] == '/':
        args.path = args.path[:-1]
    walks = [{'root': root, 'dirs': dirs, 'files': files} for root, dirs, files in os.walk(args.path)]
    if not os.path.exists(f'{args.path}/wdm'):
        os.makedirs(f'{args.path}/wdm')
    
    for walk in walks:
        root = walk['root']
        if root[-1] == '/':
            root = root[:-1]

        for f in walk['files']:
            path = f'{root}/{f}'
            if os.path.isfile(f'{path}.json'):
                os.system(f'cp "{path}" {args.path}/wdm')
                os.system(f'cp "{path}.json" {args.path}/wdm')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-w', '--wdm', default=False, action='store_true', help='copy the wdm drivers into <path>/wdm')
    parser.add_argument('path', type=str, help='target dir or file path')
    
    args = parser.parse_args()
    
    if args.path == '':
        print('no path given')
        exit()
    get_json_report_statistics()

    if args.wdm:
        copy_wdm_driver()
