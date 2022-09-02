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
sutpid=""

function ctrl_c() {
  sudo kill -9 $sutpid
  cp $statelearner/logs/learnerLog0.log.0 $workdir
}

docker_image=$1
conf_template=$2

echo "Testing: $docker_image"
tag=`cut -d ":" -f2 <<< "$docker_image"`
echo "$tag"


docker pull $docker_image
#docker run --privileged --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -p 4433:4433 $docker_image &

#cnt_id=$(sudo docker ps | grep $tag -m 1 | awk '{ print $1 }')

case $docker_image in
  *"$openssl"*)
      bin="/usr/local/bin/openssl"
      workdir=$docker_dir/openssl/$tag
      fs=$workdir/chroot
      config=$workdir/config.properties

      mkdir /tmp/openssl
      mkdir /tmp/openssl/$tag
      dump_dir=/tmp/openssl/$tag

      if [[ ! -d $fs ]]; then

          mkdir $docker_dir/openssl
          mkdir $docker_dir/openssl/$tag
          mkdir $workdir/chroot

          cp $conf_template $config

          cd $workdir
          sudo docker cp -L $cnt_id:$bin $workdir
          docker run -ti --rm --volume=`pwd`:/opt/backup $docker_image tar -cvpzf /opt/backup/chroot.tar.gz --exclude=/opt/backup --one-file-system /

          tar -zxf chroot.tar.gz --directory $fs

          sudo cp -L $fs$bin $workdir

          echo "output_dir=$dump_dir" >> $config
          echo "bin_path=$workdir/openssl" >> $config

          cd $fs
          if [[ ! -f ./dev/random ]]; then
            touch ./dev/random
            touch ./dev/urandom
            sudo mount --bind /dev/random ./dev/random
            sudo mount --bind /dev/urandom ./dev/urandom
          fi
      fi

      cd $fs

      sudo chroot . /bin/bash -c "openssl s_server -accept 4433 -www -key server.key -cert server.crt" &
      sleep 3
      sutpid=`pgrep openssl`

      cd $statelearner
      ./run_learner.sh $config
      sudo kill -9 $sutpid
      sudo cp logs/learnerLog0.log.0 $workdir
      sudo cp $dump_dir/full-model.dot.pdf  $dump_dir/minimised-model.dot.pdf $dump_dir/stateaddrset.log $workdir
      cd -

      ;;
  *"$mbedtls"*)
      bin="/usr/local/bin/ssl_server"
      workdir=$docker_dir/mbedtls/$tag
      fs=$workdir/chroot
      config=$workdir/config.properties

      mkdir /tmp/mbedtls
      mkdir /tmp/mbedtls/$tag
      dump_dir=/tmp/mbedtls/$tag

      if [[ ! -d $fs ]]; then

          mkdir $docker_dir/mbedtls
          mkdir $docker_dir/mbedtls/$tag
          mkdir $workdir/chroot

          cp $conf_template $config

          cd $workdir
          sudo docker cp -L $cnt_id:$bin $workdir
          docker run -ti --rm --volume=`pwd`:/opt/backup $docker_image tar -cvpzf /opt/backup/chroot.tar.gz --exclude=/opt/backup --one-file-system /

          tar -zxf chroot.tar.gz --directory $fs

          sudo cp -L $fs$bin $workdir

          echo "output_dir=$dump_dir" >> $config
          echo "bin_path=$workdir/ssl_server" >> $config

          cd $fs
          if [[ ! -f ./dev/random ]]; then
            touch ./dev/random
            touch ./dev/urandom
            sudo mount --bind /dev/random ./dev/random
            sudo mount --bind /dev/urandom ./dev/urandom
          fi
      fi

      cd $fs

      sudo chroot . /bin/bash -c "ssl_server" &
      sleep 3
      sutpid=`pgrep ssl_server`

      cd $statelearner
      ./run_learner.sh $config
      sudo kill -9 $sutpid
      sudo cp logs/learnerLog0.log.0 $workdir
      sudo cp $dump_dir/full-model.dot.pdf  $dump_dir/minimised-model.dot.pdf $dump_dir/stateaddrset.log $workdir
      cd -

      ;;
  *"$botan"*)
      ;;
  *)
      echo "ERROR"
      ;;
esac
