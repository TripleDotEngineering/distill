import distill.distill as d

# Must uncomment the .csv and .json os.remove() calls in distill.py
# To get input files for the first 

# Test pytest functionality:
# test_passes() should PASS, test_fails() should FAIL
#####################
# def test_passes():
#     assert True

# def test_fails():
#     assert False
#####################

# Tests the create_graph() endpoint for NetworkX accuracy
def test_create_graph(input_graph_nodes, input_graph_edges):
    output = str(d.create_graph(input_graph_nodes, input_graph_edges))
    assert output == "Graph with " + str(len(input_graph_nodes)) + " nodes and " + str(len(input_graph_edges)) + " edges"

# Tests the thresholding mechanism in add_scores() via nessus scan
def test_add_scores(input_distill_scores):
    output = dict(d.distill_score('fullreport.nessus'))
    assert output == input_distill_scores

# Tests the capture_cve() method with report.json
def test_capture_cve(input_cve_info):
    output = dict(d.capture_cve('report.json'))
    assert output == input_cve_info

# Tests to ensure functionality of the csv to json conversion in csv_to_json().
def test_file_types(input_file_types):
    output = str(d.csv_to_json(r'report.csv', r'report.json'))
    assert output == input_file_types

# Tests the get_nodes() endpoint, with time-reliant fields removed.
def test_get_nodes(input_get_nodes):
    output = d.get_nodes('ucf.cs.sd.fa21.ctm:sample-network-diagram', 
                         'd0db04de-af78-86f3-c952-0590fe949b6578af')
    for element in output:
        if 'createdOn' in element:
            del element['createdOn']
        if 'updatedOn' in element:
            del element['updatedOn']
    assert output == input_get_nodes

# Tests the get_edges() endpoint, with time-reliant fields removed.
def test_get_edges(input_get_edges):
    output = d.get_edges('ucf.cs.sd.fa21.ctm:sample-network-diagram', 
                         'd0db04de-af78-86f3-c952-0590fe949b6578af')
    for element in output:
        if 'createdOn' in element:
            del element['createdOn']
        if 'updatedOn' in element:
            del element['updatedOn']
    assert output == input_get_edges

# Tests the update_model() endpoint, using a cached version of the updated model.
def test_update_model(input_update_model, input_ip_val, input_score_dict):
    output = d.update_model('ucf.cs.sd.fa21.ctm:sample-network-diagram', 
                            'd0db04de-af78-86f3-c952-0590fe949b6578af', 
                            input_ip_val,
                            input_score_dict)
    assert output == input_update_model