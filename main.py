import os
import time

import joblib
import pandas as pd
from process_flows import analyze_pcap
import tensorflow as tf
from tensorflow.keras.models import model_from_json
# from tensorflow.keras.models import model_from_json
from tensorflow.keras.optimizers import Adam
import numpy as np

def check_new_files(folder_path, last_check_time):
    files = os.listdir(folder_path)
    new_files = []

    for file in files:
        file_path = os.path.join(folder_path, file)
        file_creation_time = os.path.getctime(file_path)

        if file_creation_time > last_check_time:
            new_files.append(file_path)

    return new_files


def read_files(file_paths):
    for file_path in file_paths:
        with open(file_path, 'r') as file:
            content = file.read()
            print(f"Reading {file_path}:\n{content}\n")

def format_3d(df):
    X = np.array(df)
    return np.reshape(X, (X.shape[0], X.shape[1], 1))

def model_multiplex(X):
    with open('Models/GRU20-64-b256.json', 'r') as json_file:
        loaded_model_json = json_file.read()
    model = model_from_json(loaded_model_json)
    model.load_weights('Models/GRU20-64-b256.h5')
    model.compile(optimizer=Adam(), loss='categorical_crossentropy', metrics=['accuracy'])

    scaler = joblib.load('scaler.pkl')
    print(X)
    ids = X['Flow ID']
    del X['Flow ID']
    del X['Unnamed: 0']
    X = scaler.transform(X)

    y_pred = model.predict(format_3d(X))
    y_pred = y_pred.round()

    y_pred = np.argmax(y_pred, axis=1)
    y_pred = pd.Series(y_pred)

    return y_pred, ids


if __name__ == '__main__':
    start_time = time.time()
    #############################################################
    #   这里需要进行如下修改：文件阅读、文件夹的定义
    #   在循环中，加入计时器，计算流平均处理时间
    #############################################################

    # FOLDER_PATH=''
    # last_check_time = time.time()
    # check_new_files(FOLDER_PATH,last_check_time)

    # last_check_time = time.time()

    # while True:
        # new_files = check_new_files(folder_path, last_check_time)

        # if new_files:
            # read_files(new_files)
            # last_check_time = time.time()

        # time.sleep(10)
    pcap_file = "C:/Users/86130/PycharmProjects/pythonProject27/UNSW_1000_packets (1).pcap"
    # pcap_file = "C:/Users/86130/PycharmProjects/pythonProject27/abc.pcap.pcapng"
    server_ip = "149.171.126.3"
    features = analyze_pcap(pcap_file, server_ip)
    df = pd.DataFrame(features)
    df.to_csv("flows.csv",index=True,header=True)

    df = pd.read_csv("flows.csv")
    df = df.iloc[1:].reset_index(drop=True)

    result, ids = model_multiplex(df)

    print(result)
    print(ids)

    samples = result

    samples = samples.replace(0,'BENIGN')
    samples = samples.replace(1,'DrDoS_DNS')
    samples = samples.replace(2,'DrDoS_LDAP')
    samples = samples.replace(3,'DrDoS_MSSQL')
    samples = samples.replace(4,'DrDoS_NTP')
    samples = samples.replace(5,'DrDoS_NetBIOS')
    samples = samples.replace(6,'DrDoS_SNMP')
    samples = samples.replace(7,'DrDoS_SSDP')
    samples = samples.replace(8,'DrDoS_UDP')
    samples = samples.replace(9,'Syn')
    samples = samples.replace(10,'UDP-lag')
    samples = samples.replace(11,'Unnamed')

    print(samples)

    existing = pd.concat([ids,samples], axis=1)

    existing.columns = ['Flow ID', 'Type']
    print(existing)
    existing.to_csv("existing.csv",index=True,header=True)

    detected = existing[existing['Type'] != 'BENIGN']

    print(detected)

    detected.to_csv("detected.csv",index=False,header=True)

    # 与前面注释掉的while循环一起用，对序列号进行增加
    # new_filename = f"{base_filename}{new_sequence}.csv"
    # detected.to_csv(new_filename,index=False,header=True)
    end_time = time.time()

    elapsed_time = end_time - start_time

    # 打印运行时间
    print(f"程序运行时间：{elapsed_time} 秒")
