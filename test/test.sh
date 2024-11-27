echo "Hello"
sleep 5
echo "World" &
echo "haha" &
sleep 10
echo "Calculate the ten digits after the one thousandth digit of pi" && \
echo "scale=1010; 4*a(1)" | bc -l|grep -o '[0-9]'|tail -n 10|tr -d '\n' && \
sleep 10 
#请确保shell脚本程序在未运行完所有的任务之前不会退出
#Please make sure that the shell script does not exit before running all tasks.
#Veuillez vous assurer que le script shell ne se ferme pas avant d'exécuter toutes les tâches
echo "finish"
