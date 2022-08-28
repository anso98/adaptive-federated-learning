
def basic_analysis_cases(previous_case):

    case_no_for_analysis = previous_case + 1

    # Basecase
    if case_no_for_analysis == 0:
        case_no_for_analysis = 0
        percentage_of_malicious_nodes = 0
        percentage_malicious_data = 0
    
    # 1 Node Malicious
    elif case_no_for_analysis == 1:
        percentage_of_malicious_nodes = 0.2
        percentage_malicious_data = 0.2
    elif case_no_for_analysis == 2:
        percentage_of_malicious_nodes = 0.2
        percentage_malicious_data = 0.4
    elif case_no_for_analysis == 3:
        percentage_of_malicious_nodes = 0.2
        percentage_malicious_data = 0.6
    elif case_no_for_analysis == 4:
        percentage_of_malicious_nodes = 0.2
        percentage_malicious_data = 0.8
    elif case_no_for_analysis == 5:
        percentage_of_malicious_nodes = 0.2
        percentage_malicious_data = 1

    # 2 Nodes Malicious
    elif case_no_for_analysis == 6:
        percentage_of_malicious_nodes = 0.4
        percentage_malicious_data = 0.2
    elif case_no_for_analysis == 7:
        percentage_of_malicious_nodes = 0.4
        percentage_malicious_data = 0.4
    elif case_no_for_analysis == 8:
        percentage_of_malicious_nodes = 0.4
        percentage_malicious_data = 0.6
    elif case_no_for_analysis == 9:
        percentage_of_malicious_nodes = 0.4
        percentage_malicious_data = 0.8
    elif case_no_for_analysis == 10:
        percentage_of_malicious_nodes = 0.4
        percentage_malicious_data = 1

    # 3 Nodes Malicious
    elif case_no_for_analysis == 11:
        percentage_of_malicious_nodes = 0.6
        percentage_malicious_data = 0.2
    elif case_no_for_analysis == 12:
        percentage_of_malicious_nodes = 0.6
        percentage_malicious_data = 0.4
    elif case_no_for_analysis == 13:
        percentage_of_malicious_nodes = 0.6
        percentage_malicious_data = 0.6
    elif case_no_for_analysis == 14:
        percentage_of_malicious_nodes = 0.6
        percentage_malicious_data = 0.8
    elif case_no_for_analysis == 15:
        percentage_of_malicious_nodes = 0.6
        percentage_malicious_data = 1

    # 4 Nodes Malicious
    elif case_no_for_analysis == 16:
        percentage_of_malicious_nodes = 0.8
        percentage_malicious_data = 0.2
    elif case_no_for_analysis == 17:
        percentage_of_malicious_nodes = 0.8
        percentage_malicious_data = 0.4
    elif case_no_for_analysis == 18:
        percentage_of_malicious_nodes = 0.8
        percentage_malicious_data = 0.6
    elif case_no_for_analysis == 19:
        percentage_of_malicious_nodes = 0.8
        percentage_malicious_data = 0.8
    elif case_no_for_analysis == 20:
        percentage_of_malicious_nodes = 0.8
        percentage_malicious_data = 1

    # 5 Nodes Malicious
    elif case_no_for_analysis == 21:
        percentage_of_malicious_nodes = 1
        percentage_malicious_data = 0.2
    elif case_no_for_analysis == 22:
        percentage_of_malicious_nodes = 1
        percentage_malicious_data = 0.4
    elif case_no_for_analysis == 23:
        percentage_of_malicious_nodes = 1
        percentage_malicious_data = 0.6
    elif case_no_for_analysis == 24:
        percentage_of_malicious_nodes = 1
        percentage_malicious_data = 0.8
    elif case_no_for_analysis == 25:
        percentage_of_malicious_nodes = 1
        percentage_malicious_data = 1

    return case_no_for_analysis, percentage_of_malicious_nodes, percentage_malicious_data


def get_labeling_of_case(casenumber):
    result = ''
    if casenumber == 0:
        return "no malicious node"
    if casenumber == 1:
        return "20% mal. nodes (20% mal. data)"
    if casenumber == 2:
        return "20% mal. nodes (40% mal. data)"
    if casenumber == 3:
        return "20% mal. node (60% mal. data)"
    if casenumber == 4:
        return "20% mal. node (80% mal. data)"
    if casenumber == 5:
        return "20% mal. node (100% mal. data)"
    if casenumber == 6:
        return "40% mal. node (20% mal. data)"
    if casenumber == 7:
        return "40% mal. node (40% mal. data)"
    if casenumber == 8:
        return "40% mal. node (60% mal. data)"
    if casenumber == 9:
        return "40% mal. node (80% mal. data)"
    if casenumber == 10:
        return "40% mal. node (100% mal. data)"   
    if casenumber == 11:
        return "60% mal. node (20% mal. data)"
    if casenumber == 12:
        return "60% mal. node (40% mal. data)"
    if casenumber == 13:
        return "60% mal. node (60% mal. data)"
    if casenumber == 14:
        return "60% mal. node (80% mal. data)"
    if casenumber == 15:
        return "60% mal. node (100% mal. data)" 
    if casenumber == 16:
        return "80% mal. node (20% mal. data)"
    if casenumber == 17:
        return "80% mal. node (40% mal. data)"
    if casenumber == 18:
        return "80% mal. node (60% mal. data)"
    if casenumber == 19:
        return "80% mal. node (80% mal. data)"
    if casenumber == 20:
        return "80% mal. node (100% mal. data)"    
    if casenumber == 21:
        return "100% mal. node (20% mal. data)"
    if casenumber == 22:
        return "100% mal. node (40% mal. data)"
    if casenumber == 23:
        return "100 mal. node (60% mal. data)"
    if casenumber == 24:
        return "100% mal. node (80% mal. data)"
    if casenumber == 25:
        return "100% mal. node (100% mal. data)"
    else:
        return "Not in range"