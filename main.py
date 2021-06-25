from fastai.tabular.all import *
from fastai.tabular import *
from fastai import *
from fastai.test_utils import *
import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedKFold
from sklearn.model_selection import train_test_split, StratifiedShuffleSplit
import os
import sys
import glob
from sklearn.utils import shuffle
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import itertools
from sklearn.metrics import confusion_matrix
from datetime import datetime
from cleandata import *
from createbinaryfile import *
import subprocess

dep_var = 'Label'
cat_names = ['Dst Port', 'Protocol']
cont_names = ['Timestamp', 'Flow Duration', 'Tot Fwd Pkts',
              'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max',
              'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
              'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean',
              'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean',
              'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot',
              'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
              'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
              'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags',
              'Bwd URG Flags', 'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s',
              'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean',
              'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt',
              'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt',
              'CWE Flag Count', 'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg',
              'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg',
              'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg',
              'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts',
              'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
              'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts',
              'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max',
              'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']

dataPath = 'data'
resultPath = 'results'
imagePath = 'images/'
modelPath = 'model'
modelName = 'name'
procs = [FillMissing, Categorify, Normalize]

def load(fileName):
    dataFile = os.path.join(dataPath, fileName)
    df = pd.read_csv(dataFile)
    df = df.dropna()
    df = shuffle(df)

    return df

def get_dls(df, path, bs, valid_idx=None):
    return TabularDataLoaders.from_df(
        df = df,
        path=path,
        procs=procs,
        cat_names=cat_names,
        cont_names=cont_names,
        y_names=dep_var,
        valid_idx=valid_idx,
        bs=bs,
        val_bs=bs
    )

def main():
    #cicflowmeter -f example.pcap -c flows.csv
    pcapFile = sys.argv[1]
    subprocess.run(["cicflowmeter", "-f", "data/" + pcapFile, "-c", "flow.csv"])

    # learn = synth_learner(path=modelPath)
    # learn = learn.load(modelName)
    # data = load(dataFile)


if __name__ == "__main__":
    main()