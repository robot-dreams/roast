if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <host> <start_port> <t> <n>"
    exit 1
fi

host=$1
start_port=$2
t=$3
n=$4
let f_max=$n-$t

echo "t,n,f,attacker_level,elapsed,send_cnt,recv_cnt,sessions_started"
for attack in `seq 0 2`
do
    for f in `seq 0 $f_max`
    do
        for i in `seq 1 10`
        do
            python3 coordinator.py $host $start_port $t $n $f $attack
        done
    done
done
