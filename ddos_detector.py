from __future__ import absolute_import
from __future__ import division

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
# import seaborn as sns

from keras.models import Sequential
from keras.layers import Dense, LSTM, Bidirectional

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from tensorflow.keras.models import load_model
# from joblib import load
import pickle


class Detector():

    def training(self):
        # sns.set()
        number_of_samples = 50000

        data_attack = pd.read_csv('dataset_attack_training_data.csv', nrows=number_of_samples)
        data_normal = pd.read_csv('dataset_normal_training_data.csv', nrows=number_of_samples)

        data_normal.columns = ['frame.len', 'frame.protocols', 'ip.hdr_len',
                               'ip.len', 'ip.flags.rb', 'ip.flags.df', 'p.flags.mf', 'ip.frag_offset',
                               'ip.ttl', 'ip.proto', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport',
                               'tcp.len', 'tcp.ack', 'tcp.flags.res', 'tcp.flags.ns', 'tcp.flags.cwr',
                               'tcp.flags.ecn', 'tcp.flags.urg', 'tcp.flags.ack', 'tcp.flags.push',
                               'tcp.flags.reset', 'tcp.flags.syn', 'tcp.flags.fin', 'tcp.window_size',
                               'tcp.time_delta', 'class']
        data_attack.columns = ['frame.len', 'frame.protocols', 'ip.hdr_len',
                               'ip.len', 'ip.flags.rb', 'ip.flags.df', 'p.flags.mf', 'ip.frag_offset',
                               'ip.ttl', 'ip.proto', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport',
                               'tcp.len', 'tcp.ack', 'tcp.flags.res', 'tcp.flags.ns', 'tcp.flags.cwr',
                               'tcp.flags.ecn', 'tcp.flags.urg', 'tcp.flags.ack', 'tcp.flags.push',
                               'tcp.flags.reset', 'tcp.flags.syn', 'tcp.flags.fin', 'tcp.window_size',
                               'tcp.time_delta', 'class']

        data_normal = data_normal.drop(['ip.src', 'ip.dst', 'frame.protocols'], axis=1)
        data_attack = data_attack.drop(['ip.src', 'ip.dst', 'frame.protocols'], axis=1)

        features = ['frame.len', 'ip.hdr_len',
                    'ip.len', 'ip.flags.rb', 'ip.flags.df', 'p.flags.mf', 'ip.frag_offset',
                    'ip.ttl', 'ip.proto', 'tcp.srcport', 'tcp.dstport',
                    'tcp.len', 'tcp.ack', 'tcp.flags.res', 'tcp.flags.ns', 'tcp.flags.cwr',
                    'tcp.flags.ecn', 'tcp.flags.urg', 'tcp.flags.ack', 'tcp.flags.push',
                    'tcp.flags.reset', 'tcp.flags.syn', 'tcp.flags.fin', 'tcp.window_size',
                    'tcp.time_delta']

        X_normal = data_normal[features].values
        X_attack = data_attack[features].values
        Y_normal = data_normal['class']
        Y_attack = data_attack['class']
        X = np.concatenate((X_normal, X_attack))
        Y = np.concatenate((Y_normal, Y_attack))

        scalar = StandardScaler(copy=True, with_mean=True, with_std=True)
        scalar.fit(X)
        X = scalar.transform(X)
        pickle.dump(scalar, open('fiscaler.pkl', 'wb'))
        print("fiscaler.pkl created!")


        for i in range(0, len(Y)):
            if Y[i] == "attack":
                Y[i] = 0
            else:
                Y[i] = 1

        features = len(X[0])
        samples = X.shape[0]
        train_len = 25
        input_len = samples - train_len
        I = np.zeros((samples - train_len, train_len, features))

        for i in range(input_len):
            temp = np.zeros((train_len, features))
            for j in range(i, i + train_len - 1):
                temp[j - i] = X[j]
            I[i] = temp

        X_train, X_test, Y_train, Y_test = train_test_split(I, Y[25:100000], test_size=0.2, random_state=4)

        model = Sequential()
        model.add(Bidirectional(LSTM(64, activation='tanh', kernel_regularizer='l2')))
        model.add(Dense(128, activation='relu', kernel_regularizer='l2'))
        model.add(Dense(1, activation='sigmoid', kernel_regularizer='l2'))

        model.compile(loss='mean_absolute_error', optimizer='adam', metrics=['accuracy'])

        history = model.fit(X_train, Y_train, epochs=1, validation_split=0.2, verbose=1)

        model.save('brnn_model.h5')

    def predictResult(self, x_test):
        model = load_model("/home/ubuntu/pox/pox/forwarding/brnn_model.h5")
        scalar = pickle.load(open('/home/ubuntu/pox/pox/forwarding/fiscaler.pkl', 'rb'))
        x_test = np.array(x_test, dtype='f')
        x_test = scalar.transform(x_test)
        predict = model.predict(np.array([x_test]), verbose=1)
        return predict


if __name__ == "__main__":
    defender = Detector()
    defender.training()
