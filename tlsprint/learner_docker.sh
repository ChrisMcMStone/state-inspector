#!/bin/bash

# trap ctrl-c and call ctrl_c()
trap ctrl_c INT

#############
# Change me
statelearner="/home/chris/Documents/phd/hw_symb/grey_box/greyboxstatelearning/statelearner"
docker_dir="/home/chris/Documents/phd/hw_symb/grey_box/greyboxstatelearning/tlsprint"
#############

tag=""
cnt_id=""
workdir=""
mbedtls="mbedtls"
openssl="openssl"
botan="botan"

function ctrl_c() {
  docker kill cnt_id
  cp $statelearner/logs/learnerLog0.log.0 $workdir
}

docker_image=$1
conf_template=$2

echo "Testing: $docker_image"
tag=`cut -d ":" -f2 <<< "$docker_image"`
echo "$tag"


docker pull $docker_image
docker run --privileged --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -p 4433:4433 $docker_image &

sleep 3

cnt_id=$(sudo docker ps | grep $tag -m 1 | awk '{ print $1 }')

case $docker_image in
  *"$openssl"*)
      mkdir $docker_dir/openssl
      mkdir $docker_dir/openssl/$tag

      workdir=$docker_dir/openssl/$tag
      config=$workdir/config.properties
      cp $conf_template $config


      bin="/usr/local/bin/openssl"
      sudo docker cp -L $cnt_id:$bin $workdir

      echo "output_dir=/tmp/openssl/$tag" >> $config
      echo "bin_path=$workdir/openssl" >> $config
      sudo mkdir /tmp/openssl/$tag

      cd $statelearner
      ./run_learner.sh $config
      cp logs/learnerLog0.log.0 $workdir
      cd -

      ;;
  *"$mbedtls"*)
      mkdir $docker_dir/mbedtls
      mkdir $docker_dir/mbedtls/$tag
      workdir=$docker_dir/mbedtls/$tag
      config=$workdir/config.properties
      cp $conf_template $config

      bin="/usr/local/bin/ssl_server"
      sudo docker cp -L $cnt_id:$bin $workdir

      echo "output_dir=/tmp/mbedtls/$tag" >> $config
      echo "bin_path=`pwd`/$tag/mbedtls" >> $config
      sudo mkdir /tmp/mbedtls/$tag

      cd $statelearner
      ./run_learner.sh $config
      cp logs/learnerLog0.log.0 $workdir
      cd -
      ;;
  *"$botan"*)
      ;;
  *)
      echo "ERROR"
      ;;
esac


docker kill $(docker ps -q)
