import pytest
import json

@pytest.fixture
def input_graph_nodes():
    with open('tests/assets/test1_nodelist.json') as node_json:
        nodelist = json.load(node_json)
    return nodelist

@pytest.fixture
def input_graph_edges():
    with open('tests/assets/test1_edgelist.json') as edge_json:
        edgelist = json.load(edge_json)
    return edgelist
    
@pytest.fixture
def input_distill_scores():
    with open('tests/assets/test1_added_scores.json') as score_json:
        scorelist = json.load(score_json)
    return scorelist

@pytest.fixture
def input_cve_info():
    with open('tests/assets/test1_cve_info.json') as cve_json:
        cvelist = json.load(cve_json)
    return cvelist

@pytest.fixture
def input_file_types():
    with open('report.json') as report_json:
        report = str(json.load(report_json))
    return report

@pytest.fixture
def input_get_nodes():
    with open('tests/assets/test1_get_nodes.json') as node_details_json:
        model_info = json.load(node_details_json)
        for element in model_info:
            if 'createdOn' in element:
                del element['createdOn']
            if 'updatedOn' in element:
                del element['updatedOn']
    return model_info

@pytest.fixture
def input_get_edges():
    with open('tests/assets/test1_get_edges.json') as edge_details_json:
        model_info = json.load(edge_details_json)
        for element in model_info:
            if 'createdOn' in element:
                del element['createdOn']
            if 'updatedOn' in element:
                del element['updatedOn']
    return model_info

@pytest.fixture
def input_update_model():
    with open('tests/assets/test1_trivium_get.json') as trivium_json:
        trivium_info = json.load(trivium_json)
    return trivium_info

@pytest.fixture
def input_ip_val():
    with open('tests/assets/test1_ip_val.json') as ip_val_json:
        ip_info = json.load(ip_val_json)
    return ip_info

@pytest.fixture
def input_score_dict():
    with open('tests/assets/test1_score_dict.json') as score_dict_json:
        score_info = json.load(score_dict_json)
    return score_info