import numpy as np
import pandas as pd
import json
import glob
from datetime import datetime
import seaborn as sns
import matplotlib.pyplot as plt
def progress_bar(current, total):
    print()
    print('[', end='')
    for i in range(total):
        if i < current:
            print('=', end='')
        else:
            print(' ', end='')
    print(']', end='')
    print()
     
def init_gt():
    df_gt = pd.read_csv('./python/security_related/datasets/UNSW-NB15/gt/UNSW-NB15_1.csv')
    # This csv file contains names of all the features
    df_col = pd.read_csv('./python/security_related/datasets/UNSW-NB15/gt/NUSW-NB15_features.csv', encoding='ISO-8859-1')
    # Making column names lower case, removing spaces
    df_col['Name'] = df_col['Name'].apply(lambda x: x.strip().replace(' ', '').lower())
    # Renaming our dataframe with proper column names
    df_gt.columns = df_col['Name']


    # Define a manual mapping for column names needs constant updating for new datasets
    column_mapping = {
        "srcip": "src_ip",
        "sport": "src_port",
        "dstip": "dest_ip",
        "dsport": "dest_port",
        "stime" : "timestamp",
        "state": "flow.state",
        "service": "app_proto",
        "sbytes": "flow.bytes_toserver",
        "dbytes": "flow.bytes_toclient",
        "timestamp" : "flow.time",
        "service" : "app_proto",
        # Add more mappings if needed
    }

    # Rename columns in df_gt based on the mapping
    df_gt.rename(columns=column_mapping, inplace=True)
    df_gt = df_gt[['src_ip', 'dest_ip','src_port','dest_port', 'proto',
                    #'flow.bytes_toserver', 'flow.bytes_toclient','dur',
                    'label',
                    ]] 
    df_gt.dropna(inplace=True)
    # Make "proto" column lowercase in both dataframes
    df_gt['proto'] = df_gt['proto'].str.lower()
    # If df_gt contains non integer values in "dest_port" or "src_port" drop the row
    df_gt["src_port"] = pd.to_numeric(df_gt["src_port"], errors="coerce")
    df_gt["dest_port"] = pd.to_numeric(df_gt["dest_port"], errors="coerce")

    # Drop rows where src_port or dest_port is NaN (i.e., non-numeric values)
    df_gt = df_gt.dropna(subset=["src_port", "dest_port"])
    
    df_gt['label'] = df_gt['label'].replace(0, False)
    df_gt['label'] = df_gt['label'].replace(1, True)
    # If ip_src or ip_dst doest not start with a number, drop the row
   
    df_gt = df_gt[df_gt['src_ip'].str.contains(r'^\d', na=False)]
    df_gt = df_gt[df_gt['dest_ip'].str.contains(r'^\d', na=False)]
    # Save the shortened dataframes to CSV
    #df_gt.to_csv("gt_short.csv", index=False)

    # Convert the port columns to integers
    df_gt['src_port'] = df_gt['src_port'].astype(int)
    df_gt['dest_port'] = df_gt['dest_port'].astype(int)
    return df_gt

# Read the Suricata JSON logs with lines=True
def json_to_csv(file_path):
        chunk_size = 10000  # Number of rows per chunk

        dfs = []
        # Event type = alert
        for chunk in pd.read_json(file_path, lines=True, chunksize=chunk_size):
            dfs.append(chunk[["src_ip", "dest_ip","src_port","dest_port","proto", "event_type"]])

        df_sur = pd.concat(dfs, ignore_index=True)  # Combine chunks
        


        # Save to CSV
        #df_sur.to_csv("eve.csv", index=False)

        print("Nested JSON converted successfully!")
        # Save csv file in the same directory
        return df_sur


def main(path):
    # Load all files in /eve_files/ directory
    file_path = path + "/*/eve.json"
    files = glob.glob(file_path)
    print(files)
    idx = range(0,len(files)-1)
    tot_true_pos = 0
    tot_false_pos = 0
    tot_false_neg = 0
    tot_true_neg = 0
    list_acc = []
    list_recall = []
    list_precision = []
    list_f1 = []
    df_gt = init_gt()
    for file_path in files:
        

        df_sur = json_to_csv(file_path)

        


        if 'flow.start' in df_sur.columns and 'flow.end' in df_sur.columns:
                # Convert the flow start and end times to datetime objects
                df_sur['flow.start'] = pd.to_datetime(df_sur['flow.start'])
                df_sur['flow.end'] = pd.to_datetime(df_sur['flow.end'])
                
                # Calculate the duration as the difference between flow.end and flow.start
                df_sur['dur'] = df_sur['flow.end'] - df_sur['flow.start']



        df_sur = df_sur[['src_ip', 'dest_ip','src_port','dest_port', 'proto',
                        #'flow.bytes_toserver', 'flow.bytes_toclient','dur',
                        'event_type',
                        ]] 
        


        df_sur.dropna(inplace=True)
        
        # Make "proto" column lowercase in both dataframes
        df_sur['proto'] = df_sur['proto'].str.lower()


        # Drop
        # If ip_src or ip_dst doest not start with a number, drop the row
        df_sur = df_sur[df_sur['src_ip'].str.contains(r'^\d', na=False)]
        df_sur = df_sur[df_sur['dest_ip'].str.contains(r'^\d', na=False)]
        
        # Save the shortened dataframes to CSV
        #df_sur.to_csv("eve_short.csv", index=False)
        

        # Convert the port columns to integers
        df_sur['src_port'] = df_sur['src_port'].astype(int)
        df_sur['dest_port'] = df_sur['dest_port'].astype(int)
        
        # Merge the two dataframes on the common columns
        df_merged = pd.merge(df_sur, df_gt, on=['src_ip', 'dest_ip','src_port','dest_port', 'proto'], how='inner', suffixes=('_suricata', '_gt'))

        # Drop NaN rows
        df_merged.dropna(inplace=True)
        # save to csv
        #df_merged.to_csv("merged.csv", index=False)
        # Extract all column with "event_type" = alert also extract rows when "event_type" != alert but "label" = true
        df_true_negative = df_merged[(df_merged["event_type"] != "alert") & (df_merged["label"] == False)] # Number of true negatives
        df_false_negatives = df_merged[(df_merged["event_type"] != "alert") & (df_merged["label"] == True)] # Number of false negatives
        df_alerts = df_merged[df_merged['event_type'] == "alert"]
        df_merged = pd.concat([df_false_negatives, df_alerts], ignore_index=True)



        # print("df_merged:")
        # print(df_merged.head(5))

        true_pos = df_merged[(df_merged["event_type"] == "alert") & (df_merged["label"] == True)]
        false_pos = df_merged[(df_merged["event_type"] == "alert") & (df_merged["label"] == False)]
        
        print("File name:", file_path)
        print("Alerts:", len(df_alerts))
        print("True positives:", len(true_pos))
        print("False positives:", len(false_pos))
        print("True negatives:", len(df_true_negative))
        print("False negatives:", len(df_false_negatives))
        # Add to the total count
        tot_true_pos = tot_true_pos + len(true_pos)
        tot_false_pos = tot_false_pos + len(false_pos)
        tot_false_neg = tot_false_neg + len(df_false_negatives)
        tot_true_neg = tot_true_neg + len(df_true_negative)
        # Save the accuracy, recall, precision, and F1 score
        if (len(df_true_negative) + len(true_pos) + len(false_pos) + len(df_false_negatives)) != 0: list_acc.append((len(true_pos) + len(df_true_negative)) / (len(df_true_negative) + len(true_pos) + len(false_pos) + len(df_false_negatives))) 
        else: list_acc.append(0)
        if (len(true_pos) + len(df_false_negatives)) != 0: list_recall.append(len(true_pos) / (len(true_pos) + len(df_false_negatives))) 
        else: list_recall.append(0)
        if (len(true_pos) + len(false_pos)) != 0: list_precision.append(len(true_pos) / (len(true_pos) + len(false_pos)))
        else: list_precision.append(0)
        if (list_precision[-1] + list_recall[-1]) != 0: list_f1.append(2 * (list_precision[-1] * list_recall[-1]) / (list_precision[-1] + list_recall[-1]))
        else: list_f1.append(0)
        # Progress bar
        progress_bar(files.index(file_path)+1, (len(files)))

    print("=====================================")
    # After for loop print values
    print("Total True positives:", tot_true_pos)
    print("Total False positives:", tot_false_pos)
    print("Total False negatives:", tot_false_neg)
    print("Total True negatives:", tot_true_neg)
    # Calculate accuracy, precision, recall, F1 score
    if (tot_true_pos + tot_true_neg + tot_false_pos + tot_false_neg) == 0:
        accuracy = 0
    else: accuracy = (tot_true_pos + tot_true_neg) / (tot_true_pos + tot_true_neg + tot_false_pos + tot_false_neg)
    if tot_true_pos + tot_false_neg == 0:
        recall = 0
    else: recall = tot_true_pos / (tot_true_pos + tot_false_neg)
    if (tot_true_pos + tot_false_pos) == 0:
        precision = 0
    else: precision = tot_true_pos / (tot_true_pos + tot_false_pos)
    if precision + recall == 0:
        f1 = 0
    else: f1 = 2 * (precision * recall) / (precision + recall)
    print("Accuracy:", accuracy)
    print("Recall:", recall)
    print("Precision:", precision)
    print("F1 score:", f1)

    # Visualize with seaborn
    cm = np.array([[tot_true_pos, tot_false_neg],[tot_false_pos, tot_true_neg]])
    labels = ['True Pos','False Neg','False Pos','True Neg']
    labels = np.asarray(labels).reshape(2,2)
    sns.heatmap(cm, annot=True, fmt='', cmap='Blues')
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.show()
    plt.plot(list_acc, label='Accuracy')
    plt.plot(list_recall, label='Recall')
    plt.plot(list_precision, label='Precision')
    plt.plot(list_f1, label='F1 score')
    plt.legend()
    plt.xlabel("File num")
    plt.ylabel("Value")
    plt.show()


#main("python/security_related/datasets/UNSW-NB15/eve_files")