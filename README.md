# DDoS-Detection-and-Mitigation-in-SDN-environment-using-POX-and-LSTM-DNN-model

First clone the repository or download the files directly to your computer.

put the l3_mySwitch.py into your pox/pox/forwarding folder and run the following command
I recommend you to run the l3_mySwitch in PyCharm environment
$cd  
$cd pox  
$python ./pox.py forwarding.l3_mySwitch  

in another terminal, (not pycharm)

$sudo mn -–switch ovsk –-topo tree,depth=2,fanout=4 –-controller=remote,ip=127.0.0.1,port=6633  
$xterm h2, h3  


For DDoS Attack (Syn Flooding) (in h2 xterm)
$hping3 10.0.0.4 -c 10000 –-flood --rand-source -w 64 -p 0 -S -d 120  

For Normal traffic  (in h3 xterm)
$hping3 10.0.0.1   
