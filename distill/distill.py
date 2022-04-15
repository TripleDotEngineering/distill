#initialize dependencies
import argparse
import csv
import json
import trivium
import networkx as nx
import xml.etree.ElementTree as ET
import subprocess
import os
import datetime


# Library to translate Nessus scans into readable JSON formatting
def csv_to_json(csvFilePath, jsonFilePath):
    '''Converts the newly created CSV file into a JSON file.'''

    jsonArray = []
    labels = ['IP Address', 'Risk Factor', 'Severity', 'CVE', 'Base Score', 'Temporal Score', 'Port', 'Protocol', 'Plugin ID', 'Plugin Name']

    # read csv file
    with open(csvFilePath, encoding='utf-8') as csvf:
        # load csv file data using csv library's dictionary reader
        csvReader = csv.DictReader(csvf, labels)

        # convert each csv row into python dict
        for row in csvReader:
            jsonArray.append(row)


    # convert python jsonArray to JSON String and write to file
    with open(jsonFilePath, 'w', encoding='utf-8') as jsonf:
        jsonString = json.dumps(jsonArray, indent=4)
        jsonf.write(jsonString)

def get_nodes(model_name, diagram_name):
    '''Grabs network model information regarding the graph nodes
    by using the Trivium API.'''

    ALLOWED_NODE_TYPES = ['td.cyber.node']

    # set params
    params = {
            "custom.isNetworkDiagram" : "true"
    }

    diagrams = trivium.api.element.get(model_name, element=diagram_name)
    ids = list(diagrams["custom"]["diagramContents"].keys())
    params = {'ids' : ','.join(ids)}
    elements = trivium.api.element.get(model_name, params=params)
    nodes = [e for e in elements if e['type'] in ALLOWED_NODE_TYPES]
    return nodes

# Grabs the edges from a user's Trivium diagram
def get_edges(model_name, diagram_name):
    '''Grabs network model information regarding the graph edges
    by using the Trivium API.'''
    
    ALLOWED_NODE_TYPES = ['td.cyber.node']
    ALLOWED_EDGE_TYPES = ['td.edge']

    # set params
    params = {
            "custom.isNetworkDiagram" : "true"
    }

    diagrams = trivium.api.element.get(model_name, element=diagram_name)
    ids = list(diagrams["custom"]["diagramContents"].keys())
    params = {'ids' : ','.join(ids)}
    elements = trivium.api.element.get(model_name, params=params)
    nodes = [e for e in elements if e['type'] in ALLOWED_NODE_TYPES]
    node_ids = [e['id'] for e in nodes]
    edges = [e for e in elements if e['type'] in ALLOWED_EDGE_TYPES and e['source'] in node_ids and e['target'] in node_ids]
    return edges

def create_graph(nodelist, edgelist):
    '''Creates the NetworkX model using two dictionary
    lists, one for the nodes and one for the edges.'''

    G = nx.Graph()

    for i in range(len(nodelist)):
        G.add_node(nodelist[i]['id'], ip=nodelist[i]['ip'], distill_score=nodelist[i]['score'], cve_info=nodelist[i]['cve'])

    for i in range(len(edgelist)):
        G.add_edge(edgelist[i]['source'], edgelist[i]['target'], id=edgelist[i]['id'])

    return G

def add_scores(jsonFilePath):
    '''Creates the Distill Score from Temporal and Base score
    information found in Nessus Scan.'''

    distill_info = {}
    score = 0
    base_score = 0
    base_count = 0
    max_score = float("-inf")

    # Opens the json file "report.json"
    with open(jsonFilePath, "r") as f:
        data = json.load(f)

    # Grabs the IP Address of the machines and creates the dictionary.
    for ip in range(len(data)):
        distill_info.update({data[ip].get('IP Address'): '0'})

    # Updates the appropiate value of each dictionary key with Distill Scores.
    for key in distill_info.keys():
        for sev in range(len(data)):
            if data[sev].get('IP Address') == key:

                # Cutoff threshold at Severity scores of Medium or more.
                if int(data[sev].get('Severity')) >= 2:
                    base_score = (float(data[sev].get('Base Score')) * float(data[sev].get('Temporal Score'))) + base_score
                
                    if float(data[sev].get('Base Score')) != 0 and float(data[sev].get('Base Score')) != None:
                        base_count = base_count + 1
                
        score = base_score
        
        if score > max_score:
            max_score = score

        distill_info.update({key:str(score)})
        score = 0


    # Bring all scores to < 1.0
    power = len(str(int(max_score)))
    for ip in distill_info:
        distill_info[ip] = str(float(distill_info[ip])/(10**power))
    return distill_info

def distill_score(filename):
    '''Pulls necessary information from the Nessus Scan and
    converts it into the appropiate data formats.
    
    This function first generates a CSV file using the .nessus file
    given from the Nessus Scan. Information such as CVE scores and IP addresses
    are put into the CSV file. A helper function is than called to convert that
    CVE file into a JSON file. Once the JSON file is returned a second helper
    function is used to create the Distill Scores.'''

    score_dict = {}
    tree = ET.parse(filename)

    with open('report.csv', 'w') as report_file:
        for host in tree.findall('Report/ReportHost'):
            ipaddr = host.find("HostProperties/tag/[@name='host-ip']").text

            for item in host.findall('ReportItem'):
                risk_factor = item.find('risk_factor').text
                pluginID = item.get('pluginID')
                pluginName = item.get('pluginName')
                port = item.get('port')
                protocol = item.get('protocol')
                severity = item.get('severity')

                if(type(item.find('cvss_base_score')) == type(None)):
                    base_score = '0' # this is informational
                else:
                    base_score = item.find('cvss_base_score').text

                if(type(item.find('cvss_temporal_score')) == type(None)):
                    temp_score = '0' # this is informational
                else:
                    temp_score = item.find('cvss_temporal_score').text

                if(type(item.find('cve')) == type(None)):
                    cve = ' ' # this is informational
                else:
                    cve = item.find('cve').text

                report_file.write(
                ipaddr + ',' + \
                risk_factor + ',' + \
                severity + ',' + \
                cve + ',' + \
                base_score + ',' + \
                temp_score + ',' + \
                port + ',' + \
                protocol + ',' + \
                pluginID + ',' + \
                '"' + pluginName + '"' + '\n'
                )
                
    # Set filepaths
    csvFilePath = r'report.csv'
    jsonFilePath = r'report.json'
    csv_to_json(csvFilePath, jsonFilePath)


    print("Creating Distill Scores...\n")

    # Add values to the score dictionary
    score_dict = add_scores(jsonFilePath)

    # deletes CSV file
    os.remove(csvFilePath)

    return score_dict

# Helper function to acquire CVE information
def capture_cve(filename):
    '''Helper function that creates a Dictionary with
    each IP address and a list of their vulnerabilities.'''

    cve_dict = {}
    cve_list = []

    # Opens the json file "report.json"
    with open(filename, "r") as f:
        data = json.load(f)

    # Grabs the IP Address of the machines and creates the dictionary.
    for ip in range(len(data)):
        cve_dict.update({data[ip].get('IP Address'): []})

    for key in cve_dict.keys():
        for sev in range(len(data)):
            if data[sev].get('IP Address') == key:
                if int(data[sev].get('Severity')) >= 2 and data[sev].get('CVE') != ' ':
                    cve_list.append(data[sev].get('CVE'))

        cve_dict.update({key:cve_list})
        cve_list = []

    # deletes JSON file
    os.remove(filename)
    return cve_dict

def cve():
    '''Function that stores necessary CVE information
    and utilizes helper function capture_cve.'''

    cve_dict = {}
    jsonFilePath = r'report.json'
    cve_dict = capture_cve(jsonFilePath)
    return cve_dict

def match_ip(ip_val, distill_info):
    '''Simple function used to match IP addresses from the Nessus Scan
    and Trivium model.'''

    for key in distill_info.keys():
        if ip_val == key:
            return distill_info[key]

def update_model(model, diagram, ip_val, score_dict):
    '''Passes new Distill Score information into the user's
    Trivium network model.'''

    ALLOWED_NODE_TYPES = ['td.cyber.node']

    # This tells us whats in the diagram.
    diagrams = trivium.api.element.get(model, element=diagram)
    ids = list(diagrams["custom"]["diagramContents"].keys())
    params = {'ids' : ','.join(ids), 'fields': 'id,name,type,source,target,custom'}
    # This grabs the nodes from the diagram.
    elements = trivium.api.element.get(model, params=params)
    nodes = [e for e in elements if e['type'] in ALLOWED_NODE_TYPES]

    for node in nodes:
        ip = node['custom']['properties']['ip']['value']
        for i in range(len(ip_val)):
            if ip == ip_val[i]:
                score = match_ip(ip_val[i], score_dict)
                node['custom']['properties']['score'] = {'type':'string', 'value': str(score), 'units':''}

    trivium.api.element.patch(model, nodes)

def file_generator(name, node_ids, dictlist_nodes):
    '''Generates a PDF file that links to CVE information
    regarding each vulnerability in each node.'''

    cve_amount = 0

    # Writes markdown file.
    if name:
        f = open(name + ".md", "w")
        f.write("#\t " + name.split("/")[-1].upper() + "'S NODE DATA REPORT\n\n")
    else:
        f = open("report.md", "w")
        f.write("#\t NODE DATA REPORT\n\n")

    for i in range(len(node_ids)):
        f.write("")
        f.write("NodeIP: " + dictlist_nodes[i]["ip"] + "  \n")
        f.write("NodeID: " + dictlist_nodes[i]["id"] + "  \n")
        f.write("**Distill Score:** " + dictlist_nodes[i]["score"] + "  \n")
        f.write("[Go to this Node's Vulnerability Report](#cve-report-for-"+str(dictlist_nodes[i]["ip"])+")" + "  \n")
        f.write('\n')

    for i in range(len(node_ids)):
        f.write("")
        f.write("# CVE REPORT FOR " + str(dictlist_nodes[i]["ip"]))
        f.write("\n\n")
        f.write("[RETURN TO TOP](#node-data-report)")
        f.write('\n\n')
        cve_amount = len(dictlist_nodes[i]["cve"])
        f.write("**Number of Vulnerabilities in Node:** " + str(cve_amount) + "  \n\n")

        # Adds CVE data to markdown report.
        for cve in range(cve_amount):
            cve_name = str(dictlist_nodes[i]["cve"][cve])
            f.write("["+cve_name+"](https://cve.mitre.org/cgi-bin/cvename.cgi?name="+cve_name+") \n\n")

    f.close()

    # Converts markdown report to PDF using pandoc.
    markdown_name = name + ".md"
    if name:
        markdown = markdown_name
    else:
        markdown = r'report.md'

    fileout = os.path.splitext(markdown)[0] + ".pdf"
    args = ['pandoc', markdown, '-o', fileout]
    process = subprocess.Popen(args)
    process.wait()

    # deletes markdown file.
    os.remove(markdown)

def main():
    '''Distill is a command line tool that is used in line with
    the Trivium graphing applicaiton.
    
    This command line tool will require the user to have access to their
    Trivium account and be connected to it on use. The tool will also
    require information regarding the model's ID, diagram's ID, and the
    Nessus file from the scan. With all of this information, the tool will
    generate an original Distill Score and a NetworkX model for the user. The
    user will also be supplied a PDF report regarding their network model's
    vulnerability information.'''

    # initialize parser
    parser = argparse.ArgumentParser()

    # display landing screen for command-line tool
    parser.add_argument("-m", "--model", type=str, help="Model Name", required=True)
    parser.add_argument("-d", "--diagram", type=str, help="Diagram Name", required=True)
    parser.add_argument("-n", "--nessus", type=argparse.FileType('r'), help="Nessus Files", required=True)
    parser.add_argument("-o", "--output", type=str, help="Output File Name", required=False)
    args = parser.parse_args()

    print("Starting Distill at " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    print()

    # initialization from user's command-line input
    model = args.model
    diagram = args.diagram
    filename = args.nessus

    if args.output:
        new_name = args.output
    else:
        new_name = 'distill'

    print("Retrieving Trivium Model...\n")

    # retrieve nodes and edges from user's Trivium diagram
    nodes = get_nodes(model, diagram)
    edges = get_edges(model, diagram)

    # contains ids for only the nodes
    node_ids = [ e['id'] for e in nodes]
    # contains ids for only the edges
    edge_ids = [ e['id'] for e in edges]

    # parses through trivium and pulls the node/IP Address from properties.
    custom = [ e['custom'] for e in nodes]
    # print(json.dumps(custom, indent=4))
    prop = [ e['properties'] for e in custom]
    ip = [ e['ip'] for e in prop]
    ip_val = [ e['value'] for e in ip]

    # parses through trivium and pulls the edge/source/target from properties.
    source = [ e['source'] for e in edges]
    target = [ e['target'] for e in edges]

    # creates an arraylist of dictionaries with node_id as the key and IP Address/Distill score as values
    dictlist_nodes = [dict() for x in range(len(node_ids))]
    dictlist_edges = [dict() for x in range(len(edge_ids))]

    print("Scanning Nessus File...\n")

    # dictionaries that store distill scores and cve data.
    score_dict = distill_score(filename)
    cve_dict = cve()

    # prints the contents of the previously created arraylist of dictionaries
    # ip_val stored as a string
    for i in range(len(node_ids)):
        dictlist_nodes[i] = {'id':node_ids[i], 'ip':ip_val[i], 'score':match_ip(ip_val[i], score_dict), 'cve':match_ip(ip_val[i], cve_dict)}

    for i in range(len(edge_ids)):
        dictlist_edges[i] = {'id':edge_ids[i], 'source':source[i], 'target':target[i]}

    print("Updating Trivium Model with New Distill Scores...\n")

    update_model(model, diagram, ip_val, score_dict)

    print("Creating NetworkX Model for Sublimate Usage...\n")

    graph = create_graph(dictlist_nodes, dictlist_edges)
    
    # Output NetworkX graph as JSON
    with open(new_name + ".json", "w") as f:
        f.write(json.dumps(nx.readwrite.node_link_data(graph)))

    print("Generating PDF Report...\n")

    file_generator(new_name, node_ids, dictlist_nodes)

    print("DONE")
    
if __name__ == "__main__":
    main()
