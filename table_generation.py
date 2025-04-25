# Unite all dfs
import pandas as pd
import argparse
import os
def main():
    print("Current Working Directory:", os.getcwd())
    parser = argparse.ArgumentParser(description="Table generation")
    
    args = parser.parse_args()
    latency_df = pd.read_csv("./tables/latency/syseval.csv")
    regular_df = pd.read_csv("./tables/regular/syseval.csv")
    controller_df = pd.read_csv("./tables/controller/syseval.csv")
    datasets_df = pd.read_csv("./tables/dataset_classification/classeval.csv")
    # print(latency_df)
    # print("-----------------------")
    # print(regular_df)
    
    # Remove "unnamed" column
    latency_df = latency_df.loc[:, ~latency_df.columns.str.contains('^Unnamed')]
    regular_df = regular_df.loc[:, ~regular_df.columns.str.contains('^Unnamed')]
    controller_df = controller_df.loc[:, ~controller_df.columns.str.contains('^Unnamed')]
    # datasets_df = datasets_df.loc[:, ~datasets_df.columns.str.contains('^Unnamed')]
    # print("------removed unnamed------------")
    # print(latency_df)
    # print("-----------------------")
    # print(regular_df)

    regular_df['Throughput'] = regular_df['Throughput'].apply(lambda x: f"throughput_{int(x)}")
    latency_df['Latency'] = latency_df['Latency'].apply(lambda x: f"latency_{int(x)}")
    controller_df['Speeds'] = controller_df['Speeds'].apply(lambda x: f"throughput_{int(x)}")
    # print("------changed columns ------------")
    # print(latency_df)
    # print("-----------------------")
    # print(regular_df)

    regular_df = regular_df.rename(columns={'Throughput': 'row_value'})
    latency_df = latency_df.rename(columns={'Latency': 'row_value'})
    controller_df = controller_df.rename(columns={'Speeds': 'row_value'})
    datasets_df = datasets_df.rename(columns={'Dataset': 'row_value'})

    # print("------changed columns ------------")
    # print(latency_df)
    # print("-----------------------")
    # print(regular_df)
    """ To merge Controller and Regular they need to have the same recorded throughputs in row_value."""
    # df_merged = regular_df.merge(controller_df, on='row_value')
    # print(df_merged)
    # exit(0)
    # Concatenate vertically (stack)
    combined_df = pd.concat([regular_df, latency_df,controller_df,datasets_df])
    print("-----------fin------------")
    print(combined_df)
    

    combined_df.to_csv("./tables/all_metrics.csv")
    
if __name__ == "__main__":
    main()
